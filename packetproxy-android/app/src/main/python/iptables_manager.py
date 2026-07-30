#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
iptables 规则管理器（Root Android — Mode B 核心）

管理透明代理所需的 NAT REDIRECT 规则。

两种模式:

  【推荐】按 UID 模式 — 只拦截指定 app 的流量:
    iptables -t nat -A OUTPUT -p tcp \
      -m owner --uid-owner <app_uid> \
      ! -d 127.0.0.1 \
      -j REDIRECT --to-port <proxy_port>

    安全：代理自身以 root 运行，不会匹配 app_uid，无回环风险。

  全局模式 — 拦截所有 TCP 流量:
    iptables -t nat -A OUTPUT -p tcp \
      -m owner ! --uid-owner 0 \         # 排除 root（代理自身）
      ! -d 127.0.0.1 \                    # 排除本地回环
      -m mark ! --mark 1 \                # 排除 SO_MARK=1 的连接
      ! --dport 53 \                       # 保留 DNS
      -j REDIRECT --to-port <proxy_port>
"""

import subprocess
import logging
import re

logger = logging.getLogger(__name__)

RULE_TAG = 'PACKETPROXY'
PROXY_MARK = 1  # 与 transparent_proxy.py 中 SO_MARK 值一致


class IptablesManager:
    def __init__(self, redirect_port=3161):
        self.redirect_port = redirect_port
        self.rules_applied = False
        self._applied_uids = []
        self._mode = None  # 'uid' or 'global'

    # ── 设备检查 ─────────────────────────────────────────────────

    def check_root(self) -> bool:
        """检查是否有 root 权限"""
        try:
            result = subprocess.run(
                ['su', '-c', 'id'],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0 and 'uid=0' in result.stdout
        except FileNotFoundError:
            logger.warning('su 不可用 - 设备未 root')
            return False
        except Exception as e:
            logger.error(f'Root 检查失败: {e}')
            return False

    def check_iptables(self) -> bool:
        """检查 iptables 是否可用"""
        try:
            result = subprocess.run(
                ['su', '-c', 'which iptables'],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0 and 'iptables' in result.stdout
        except Exception:
            return False

    def get_kernel_version(self) -> str:
        """获取内核版本"""
        try:
            result = subprocess.run(
                ['su', '-c', 'uname -r'],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip()
        except Exception:
            return '未知'

    # ── 应用信息 ─────────────────────────────────────────────────

    def get_app_uid(self, package_name: str) -> str:
        try:
            result = subprocess.run(
                ['su', '-c', f'dumpsys package {package_name} | grep userId='],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r'userId=(\d+)', result.stdout)
            if match:
                return match.group(1)
        except Exception as e:
            logger.error(f'获取 UID 失败 ({package_name}): {e}')
        return None

    def list_installed_apps(self) -> list:
        """列出已安装的第三方应用包名"""
        try:
            result = subprocess.run(
                ['su', '-c', 'pm list packages -3'],
                capture_output=True, text=True, timeout=15,
            )
            packages = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith('package:'):
                    packages.append(line[8:].strip())
            return sorted(packages)
        except Exception as e:
            logger.error(f'列出应用失败: {e}')
            return []

    def get_app_label(self, package_name: str) -> str:
        """获取应用显示名称（通过 dumpsys）"""
        try:
            result = subprocess.run(
                ['su', '-c',
                 f'dumpsys package {package_name} | '
                 f'grep -A1 "ApplicationInfo" | grep "labelRes"'],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() or package_name
        except Exception:
            return package_name

    def get_app_uid_info(self, package_name: str) -> dict:
        """获取应用的 UID + 网络使用信息"""
        uid = self.get_app_uid(package_name)
        return {
            'package': package_name,
            'uid': uid,
        }

    # ── iptables 操作 ─────────────────────────────────────────────

    def _run_iptables(self, args: str) -> bool:
        """以 root 执行 iptables 命令"""
        cmd = f'iptables {args}'
        try:
            result = subprocess.run(
                ['su', '-c', cmd],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0 and result.stderr:
                logger.warning(f'iptables: {result.stderr.strip()[:120]}')
            return result.returncode == 0
        except Exception as e:
            logger.error(f'iptables 执行失败: {e}')
            return False

    # ── 模式 1: 按 UID 拦截（推荐） ──────────────────────────────

    def add_uid_rules(self, uids: list) -> bool:
        """
        【推荐】为指定 UID 的应用添加 REDIRECT 规则。

        只拦截指定 app 的流量，代理自身 (root) 不受影响。
        """
        if not self.check_root():
            logger.error('需要 root 权限')
            return False

        if not uids:
            logger.error('UID 列表为空')
            return False

        self.remove_redirect_rules()

        success = True
        for uid in uids:
            # 排除本地回环地址，只重定向出站流量
            rule = (
                f'-t nat -A OUTPUT -p tcp '
                f'-m owner --uid-owner {uid} '
                f'! -d 127.0.0.1 '
                f'-j REDIRECT --to-port {self.redirect_port} '
                f'-m comment --comment {RULE_TAG}_uid_{uid}'
            )
            if not self._run_iptables(rule):
                success = False
                logger.error(f'添加 UID={uid} 规则失败')

        if success:
            self.rules_applied = True
            self._applied_uids = list(uids)
            self._mode = 'uid'
            logger.info(
                f'已为 {len(uids)} 个 UID 添加 REDIRECT 规则 → '
                f'端口 {self.redirect_port}'
            )
        return success

    # ── 模式 2: 全局拦截（谨慎使用） ──────────────────────────────

    def add_global_rules(self) -> bool:
        """
        全局 REDIRECT — 拦截所有 app 的 TCP 流量。

        安全检查:
          - 排除 root (UID 0) 的流量，防止回环
          - 排除 SO_MARK=1 的连接（透明代理自身的出站连接）
          - 排除本地回环 (127.0.0.1)
          - 保留 DNS 端口 (53, 853)，避免影响域名解析
        """
        if not self.check_root():
            logger.error('需要 root 权限')
            return False

        self.remove_redirect_rules()

        chain = 'OUTPUT'
        rules = [
            # 1) 放行 DNS — 不影响域名解析
            (f'-t nat -A {chain} -p tcp --dport 53 -j RETURN '
             f'-m comment --comment {RULE_TAG}_dns'),

            # 2) 放行本地回环
            (f'-t nat -A {chain} -p tcp -d 127.0.0.1 -j RETURN '
             f'-m comment --comment {RULE_TAG}_local'),

            # 3) 放行透明代理自身的出站（SO_MARK 标记）
            (f'-t nat -A {chain} -p tcp -m mark --mark {PROXY_MARK} -j RETURN '
             f'-m comment --comment {RULE_TAG}_proxy'),

            # 4) 放行 root (UID 0) 的流量 — 代理自身和系统服务
            (f'-t nat -A {chain} -p tcp -m owner --uid-owner 0 -j RETURN '
             f'-m comment --comment {RULE_TAG}_root'),

            # 5) 剩余 TCP 全部 REDIRECT
            (f'-t nat -A {chain} -p tcp -j REDIRECT --to-port {self.redirect_port} '
             f'-m comment --comment {RULE_TAG}'),
        ]

        success = True
        for rule in rules:
            if not self._run_iptables(rule):
                success = False

        if success:
            self.rules_applied = True
            self._mode = 'global'
            logger.info(f'全局 REDIRECT 已启用 → 端口 {self.redirect_port}')
        else:
            # 部分失败则全部回滚
            self.remove_redirect_rules()
            logger.error('全局规则添加失败，已回滚')

        return success

    # ── 清理 ──────────────────────────────────────────────────────

    def remove_redirect_rules(self) -> bool:
        """移除所有本工具添加的 NAT REDIRECT 规则"""
        try:
            result = subprocess.run(
                ['su', '-c',
                 'iptables -t nat -L OUTPUT -n --line-numbers'],
                capture_output=True, text=True, timeout=10,
            )

            # 从后往前删除（行号不变原则）
            rules_to_delete = []
            for line in result.stdout.strip().split('\n'):
                if RULE_TAG in line:
                    try:
                        rules_to_delete.append(int(line.split()[0]))
                    except (ValueError, IndexError):
                        pass

            for num in reversed(rules_to_delete):
                self._run_iptables(f'-t nat -D OUTPUT {num}')

            self.rules_applied = False
            self._applied_uids = []
            self._mode = None

            if rules_to_delete:
                logger.info(f'已移除 {len(rules_to_delete)} 条规则')
            return True
        except Exception as e:
            logger.error(f'移除规则失败: {e}')
            return False

    def list_rules(self) -> str:
        try:
            result = subprocess.run(
                ['su', '-c', 'iptables -t nat -L OUTPUT -n -v'],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout if result.returncode == 0 else '(无)'
        except Exception:
            return '(无)'

    def get_rules_summary(self) -> str:
        """获取简洁规则摘要（用于 UI 显示）"""
        try:
            result = subprocess.run(
                ['su', '-c',
                 'iptables -t nat -L OUTPUT -n --line-numbers 2>/dev/null'],
                capture_output=True, text=True, timeout=10,
            )
            lines = []
            for line in result.stdout.strip().split('\n'):
                if RULE_TAG in line or 'REDIRECT' in line:
                    lines.append(line.strip())
            return '\n'.join(lines) if lines else '(无相关规则)'
        except Exception:
            return '(无)'

    # ── 状态查询 ──────────────────────────────────────────────────

    def get_full_status(self) -> dict:
        return {
            'has_root': self.check_root(),
            'has_iptables': self.check_iptables(),
            'kernel': self.get_kernel_version(),
            'rules_active': self.rules_applied,
            'mode': self._mode,
            'redirect_port': self.redirect_port,
            'applied_uids': self._applied_uids.copy(),
            'rules': self.get_rules_summary(),
        }


iptables_manager = IptablesManager()
