#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
透明代理模块（Mode B 核心）
处理 iptables REDIRECT 转发的连接，通过 SO_ORIGINAL_DST 获取原始目标地址。

工作流程:
  目标App → iptables REDIRECT → 127.0.0.1:3161
  → SO_ORIGINAL_DST 恢复原始地址 → 连接真实服务器 → 双向转发 + 数据包捕获
"""

import socket
import struct
import threading
import select
import errno
import logging

logger = logging.getLogger(__name__)

# ── Linux 内核常量 ──────────────────────────────────────────────

SOL_IP = 0
SO_ORIGINAL_DST = 80     # 获取 iptables REDIRECT 前的原始目标地址
SO_MARK = 36              # 设置 socket 防火墙标记（防回环）

# 透明代理自己的连接标记，iptables 应跳过 mark=1 的包
PROXY_MARK = 1

# 不做透明代理的端口（明文协议跳过，避免噪声）
SKIP_PORTS = {80, 443, 53, 853}
# 80=HTTP, 443=HTTPS, 53=DNS-over-TCP, 853=DNS-over-TLS


class TransparentProxy:
    """
    透明代理服务器。

    iptables 规则示例 (按 UID):
      iptables -t nat -A OUTPUT -p tcp \
        -m owner --uid-owner <app_uid> \
        ! -d 127.0.0.1 \
        -j REDIRECT --to-port 3161

    全局模式（谨慎使用）:
      iptables -t nat -A OUTPUT -p tcp \
        -m owner ! --uid-owner 0 \          # 排除 root
        ! -d 127.0.0.1 \
        -m mark ! --mark 1 \                 # 排除代理自身连接
        -j REDIRECT --to-port 3161
    """

    def __init__(self, host='0.0.0.0', port=3161):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.packet_callback = None
        self.target_uids = set()
        self.connection_count = 0

    def set_packet_callback(self, callback):
        self.packet_callback = callback

    def set_target_uids(self, uids):
        self.target_uids = set(uids)

    @staticmethod
    def get_original_dst(sock):
        """
        通过 SO_ORIGINAL_DST 获取 iptables REDIRECT 之前的原始目标。

        返回的 sockaddr_in 结构:
          sin_family (2B, big-endian)  = AF_INET (0x0002)
          sin_port   (2B, big-endian)
          sin_addr   (4B, big-endian)
          sin_zero   (8B, padding)

        返回 (ip_str, port) 或 (None, None)。
        """
        try:
            raw = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
            family, port, a, b, c, d = struct.unpack('!HHBBBB', raw[:8])
            if family != 2:  # AF_INET
                logger.debug(f'非 IPv4 连接: family={family}')
                return None, None
            return f'{a}.{b}.{c}.{d}', port
        except OSError as e:
            if e.errno == errno.ENOPROTOOPT:
                logger.debug('SO_ORIGINAL_DST 不可用 — 连接非 REDIRECT 来源')
            else:
                logger.debug(f'SO_ORIGINAL_DST 失败: {e}')
            return None, None
        except Exception as e:
            logger.debug(f'SO_ORIGINAL_DST 失败: {e}')
            return None, None

    @staticmethod
    def format_hex(data):
        hex_str = data.hex().upper()
        return ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))

    def _create_marked_socket(self):
        """创建带 SO_MARK 标记的 socket，防止回环被 iptables 再次重定向"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_MARK, PROXY_MARK)
        except OSError as e:
            logger.debug(f'SO_MARK 设置失败 (非 root?): {e}')
        return sock

    def start(self):
        """启动透明代理服务器"""
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(128)
            self.server_socket.settimeout(1.0)  # 每秒检查 running 标志
            self.running = True
            logger.info(
                f'透明代理启动: {self.host}:{self.port} (iptables REDIRECT 目标)'
            )

            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    self.connection_count += 1
                    logger.debug(
                        f'[#{self.connection_count}] REDIRECT 连接: {client_addr}'
                    )
                    t = threading.Thread(
                        target=self._handle_redirected,
                        args=(client_sock, client_addr, self.connection_count),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        logger.error(f'Accept 错误: {e}')
                    break
        except Exception as e:
            logger.error(f'透明代理启动失败: {e}')
            self.running = False
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.server_socket = None
        logger.info('透明代理已停止')

    def _handle_redirected(self, client_sock, client_addr, conn_id):
        target_sock = None
        orig_addr = orig_port = None

        try:
            client_sock.settimeout(30)

            # 获取 iptables REDIRECT 前的原始目标
            orig_addr, orig_port = self.get_original_dst(client_sock)
            if orig_addr is None:
                logger.warning(f'[#{conn_id}] 无法获取原始目标，非 REDIRECT 连接')
                return

            # 跳过明文协议端口，减少噪声
            if orig_port in SKIP_PORTS:
                logger.debug(f'[#{conn_id}] 跳过端口 {orig_port}')
                return

            # 通知 UI
            if self.packet_callback:
                self.packet_callback(
                    direction='新连接',
                    hex_data=f'{orig_addr}:{orig_port}',
                    size=0,
                    port=orig_port,
                    client=f'{client_addr[0]}:{client_addr[1]}',
                )

            # 用带 SO_MARK 的 socket 连接真实目标，避免被全局 iptables 回环
            target_sock = self._create_marked_socket()
            target_sock.settimeout(10)
            target_sock.connect((orig_addr, orig_port))
            target_sock.settimeout(30)

            logger.info(
                f'[#{conn_id}] 透明代理: {client_addr} → {orig_addr}:{orig_port}'
            )

            # 双向数据转发
            self._relay(
                client_sock, target_sock, client_addr,
                orig_addr, orig_port, conn_id,
            )

        except OSError as e:
            logger.debug(f'[#{conn_id}] 连接失败: {e}')
        except Exception as e:
            logger.error(f'[#{conn_id}] 透明代理处理异常: {e}')
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if target_sock:
                try:
                    target_sock.close()
                except Exception:
                    pass
            logger.debug(f'[#{conn_id}] 连接关闭')

    def _relay(self, client_sock, target_sock, client_addr, orig_addr, orig_port, conn_id):
        client_ip = client_addr[0]
        client_port = client_addr[1]
        rx_total = 0
        tx_total = 0

        try:
            while self.running:
                r, _, e = select.select(
                    [client_sock, target_sock], [], [client_sock, target_sock], 1.0,
                )
                if not self.running:
                    break

                if e:
                    logger.debug(f'[#{conn_id}] socket 异常，断开')
                    break

                # 客户端 → 真实服务器（上行）
                if client_sock in r:
                    try:
                        data = client_sock.recv(65536)
                    except OSError:
                        break
                    if not data:
                        break

                    tx_total += len(data)
                    target_sock.sendall(data)

                    if self.packet_callback:
                        self.packet_callback(
                            direction='C→S',
                            hex_data=self.format_hex(data),
                            size=len(data),
                            port=orig_port,
                            client=f'{client_ip}:{client_port}',
                        )

                # 真实服务器 → 客户端（下行）
                if target_sock in r:
                    try:
                        data = target_sock.recv(65536)
                    except OSError:
                        break
                    if not data:
                        break

                    rx_total += len(data)
                    client_sock.sendall(data)

                    if self.packet_callback:
                        self.packet_callback(
                            direction='S→C',
                            hex_data=self.format_hex(data),
                            size=len(data),
                            port=orig_port,
                            client=f'{orig_addr}:{orig_port}',
                        )

        except Exception as e:
            logger.debug(f'[#{conn_id}] relay 结束: {e}')
        finally:
            logger.debug(
                f'[#{conn_id}] 统计: 上行 {tx_total}B / 下行 {rx_total}B'
            )


# ── 全局实例 ─────────────────────────────────────────────────────

_transparent_instance = None


def set_transparent_instance(proxy):
    global _transparent_instance
    _transparent_instance = proxy


def get_transparent_instance():
    global _transparent_instance
    return _transparent_instance
