#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOCKS5代理服务器核心模块（Android版）
"""

import socket
import threading
import struct
import select
import logging

logger = logging.getLogger(__name__)


class SOCKS5Server:
    def __init__(self, host='0.0.0.0', port=3160):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.packet_callback = None
        self.active_connections = {}
        self.client_connections = {}

    def set_packet_callback(self, callback):
        self.packet_callback = callback

    @staticmethod
    def format_hex_data(data):
        hex_str = data.hex().upper()
        return ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))

    def start_server(self):
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"SOCKS5 server started on {self.host}:{self.port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.debug(f"New connection from {client_address}")
                    t = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True,
                    )
                    t.start()
                except socket.error as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
                        break
        except Exception as e:
            logger.error(f"Server start failed: {e}")
            self.running = False
        finally:
            self.stop_server()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info("SOCKS5 server stopped")

    def handle_client(self, client_socket, client_address):
        try:
            if not self._handshake(client_socket):
                return
            target_socket = self._connect_request(client_socket)
            if not target_socket:
                return
            self._relay(client_socket, target_socket, client_address)
        except Exception as e:
            logger.error(f"Handle client {client_address} error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _handshake(self, client_socket):
        try:
            data = client_socket.recv(256)
            if len(data) < 3:
                return False
            version, nmethods = struct.unpack('!BB', data[:2])
            if version != 5:
                return False
            client_socket.send(struct.pack('!BB', 5, 0))
            return True
        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            return False

    def _connect_request(self, client_socket):
        try:
            data = client_socket.recv(256)
            if len(data) < 4:
                return None
            version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])
            if version != 5 or cmd != 1:
                self._send_error(client_socket, 7)
                return None

            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(data[4:8])
                port = struct.unpack('!H', data[8:10])[0]
            elif atyp == 3:  # Domain
                addr_len = data[4]
                addr = data[5:5 + addr_len].decode('utf-8')
                port = struct.unpack('!H', data[5 + addr_len:7 + addr_len])[0]
            else:
                self._send_error(client_socket, 8)
                return None

            if self.packet_callback:
                self.packet_callback(
                    direction='连接',
                    hex_data=f'{addr}:{port}',
                    size=len(data),
                    port=port,
                    client=f'{client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}',
                )

            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((addr, port))
            target_socket.settimeout(None)

            response = struct.pack('!BBBB', 5, 0, 0, 1)
            response += socket.inet_aton('0.0.0.0')
            response += struct.pack('!H', 0)
            client_socket.send(response)
            logger.debug(f"Connected to target {addr}:{port}")
            return target_socket
        except Exception as e:
            logger.error(f"Connect request failed: {e}")
            self._send_error(client_socket, 1)
            return None

    def _send_error(self, client_socket, error_code):
        try:
            response = struct.pack('!BBBB', 5, error_code, 0, 1)
            response += socket.inet_aton('0.0.0.0')
            response += struct.pack('!H', 0)
            client_socket.send(response)
        except Exception:
            pass

    def _relay(self, client_socket, target_socket, client_address):
        client_ip = client_address[0]
        client_port = client_address[1]
        target_port = 0
        target_addr = ""

        try:
            target_port = target_socket.getpeername()[1]
            target_addr = f'{target_socket.getpeername()[0]}:{target_port}'
            self.active_connections[target_port] = (client_socket, target_socket)
            self.client_connections[client_port] = (client_socket, target_socket)
        except Exception:
            target_port = 0

        try:
            while self.running:
                r, w, e = select.select([client_socket, target_socket], [], [], 1)
                if not self.running:
                    break

                if client_socket in r:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    if self.packet_callback and target_port not in [80, 443]:
                        self.packet_callback(
                            direction='C→S',
                            hex_data=self.format_hex_data(data),
                            size=len(data),
                            port=target_port,
                            client=f'{client_ip}:{client_port}',
                        )
                    target_socket.send(data)

                if target_socket in r:
                    data = target_socket.recv(4096)
                    if not data:
                        break
                    if self.packet_callback and target_port not in [80, 443]:
                        self.packet_callback(
                            direction='S→C',
                            hex_data=self.format_hex_data(data),
                            size=len(data),
                            port=client_port,
                            client=f'{target_addr}',
                        )
                    client_socket.send(data)
        except Exception as e:
            logger.error(f"Relay error: {e}")
        finally:
            if target_port in self.active_connections:
                del self.active_connections[target_port]
            if client_port in self.client_connections:
                del self.client_connections[client_port]
            try:
                client_socket.close()
            except Exception:
                pass
            try:
                target_socket.close()
            except Exception:
                pass

    def send_custom_packet(self, target_port: int, data: bytes) -> bool:
        try:
            if target_port in self.client_connections:
                sock, _ = self.client_connections[target_port]
                sock.send(data)
                logger.info(f"Sent {len(data)} bytes to client port {target_port}")
                return True
            elif target_port in self.active_connections:
                _, sock = self.active_connections[target_port]
                sock.send(data)
                logger.info(f"Sent {len(data)} bytes to target port {target_port}")
                return True
            else:
                logger.warning(f"No active connection on port {target_port}")
                return False
        except Exception as e:
            logger.error(f"Send custom packet failed: {e}")
            return False


_server_instance = None


def set_server_instance(server):
    global _server_instance
    _server_instance = server


def get_server_instance():
    global _server_instance
    return _server_instance
