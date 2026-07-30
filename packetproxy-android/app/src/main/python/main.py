#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketProxy - Android 透明代理数据包拦截工具
支持 LAN SOCKS5 代理 + iptables 透明劫持
"""

import os
import sys
import json
import logging
import threading
import socket
import struct
import platform
from datetime import datetime

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

os.environ['KIVY_LOG_MODE'] = 'PYTHON'

from kivy.config import Config
Config.set('kivy', 'window_title', 'PacketProxy')
Config.set('graphics', 'width', '400')
Config.set('graphics', 'height', '700')
Config.set('input', 'mouse', 'mouse,multitouch_on_demand')

from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.core.window import Window
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.utils import get_color_from_hex as hex_color

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.button import MDRaisedButton, MDFlatButton, MDIconButton
from kivymd.uix.card import MDCard
from kivymd.uix.chip import MDChip
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.list import MDListItem, MDListItemHeadlineText, MDListItemSupportingText
from kivymd.uix.dialog import MDDialog, MDDialogButtonContainer, MDDialogHeadlineText
from kivymd.uix.snackbar import MDSnackbar, MDSnackbarText

try:
    from socks5_server import SOCKS5Server, set_server_instance, get_server_instance
    from transparent_proxy import TransparentProxy, set_transparent_instance, get_transparent_instance
    from iptables_manager import iptables_manager
    from packet_manager import packet_manager
    from config_manager import config_manager
    from hex_pattern_utils import HexPatternUtils
    from app_randomizer import get_random_app_features
except ImportError as e:
    print(f'Import error: {e}')
    sys.exit(1)


class ServerScreen(MDScreen):
    pass


class PacketScreen(MDScreen):
    pass


class SendScreen(MDScreen):
    pass


class IptablesScreen(MDScreen):
    pass


class LogScreen(MDScreen):
    pass


class LogHandler(logging.Handler):
    def __init__(self, app_ref):
        super().__init__()
        self.app_ref = app_ref
        self.log_lines = []
        self.max_lines = 300

    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_lines.append(msg)
            if len(self.log_lines) > self.max_lines:
                self.log_lines = self.log_lines[-self.max_lines:]
            if self.app_ref:
                self.app_ref.update_log_display()
        except Exception:
            pass

    def get_logs(self):
        return '\n'.join(self.log_lines)

    def clear(self):
        self.log_lines.clear()
        if self.app_ref:
            self.app_ref.update_log_display()


class PacketProxyApp(MDApp):
    server_running = BooleanProperty(False)
    transparent_running = BooleanProperty(False)
    iptables_active = BooleanProperty(False)
    intercepting = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.server = None
        self.server_thread = None
        self.transparent = None
        self.transparent_thread = None
        self.log_handler = None
        self._update_scheduled = None

    # ── Build & Init ────────────────────────────────────────────────

    def build(self):
        self.theme_cls.material_style = 'M3'
        self.theme_cls.theme_style = 'Dark'
        self.theme_cls.primary_palette = 'Blue'
        self.title = 'PacketProxy'
        Window.bind(on_keyboard=self._on_keyboard)
        self._setup_logging()
        self._setup_packet_callback()

        # 延迟获取 LAN IP（需要等 UI 就绪）
        Clock.schedule_once(lambda dt: self._detect_lan_info(), 1)

        # KV 文件已定义 MDScreenManager 为 root，不覆盖
        return None

    def _setup_logging(self):
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        self.log_handler = LogHandler(self)
        self.log_handler.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        self.log_handler.setFormatter(fmt)
        root_logger.addHandler(self.log_handler)
        logging.info('PacketProxy 已启动')

    def _setup_packet_callback(self):
        def on_packet(packet):
            pass  # stats handled in add_packet_row
        packet_manager.set_ui_callback(on_packet)

    def _on_keyboard(self, window, key, *args):
        if key == 27:
            if self.root.current != 'server':
                self.root.current = 'server'
                return True
        return False

    # ── LAN Info ────────────────────────────────────────────────────

    @staticmethod
    def _get_lan_ip():
        """获取本机局域网 IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass

        # Fallback: 遍历网卡 (需要 fcntl)
        if HAS_FCNTL:
            try:
                for iface in socket.if_nameindex():
                    name = iface[1]
                    if name.startswith(('wlan', 'eth', 'rmnet')):
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            ip = socket.inet_ntoa(
                                fcntl.ioctl(
                                    s.fileno(), 0x8915,
                                    struct.pack('256s', name[:15].encode())
                                )[20:24]
                            )
                            s.close()
                            if ip and not ip.startswith('127.'):
                                return ip
                        except Exception:
                            pass
            except Exception:
                pass
        return '未知'

    @mainthread
    def _detect_lan_info(self):
        try:
            screen = self.root.get_screen('server')
            lan_ip = self._get_lan_ip()
            screen.ids.lan_info_label.text = (
                f'[b]手机 IP:[/b] {lan_ip}\n'
                f'[b]SOCKS5 代理地址:[/b] {lan_ip}:3160\n'
                f'[b]PC 端设置:[/b] Proxifier → SOCKS5 {lan_ip}:3160'
            )
        except Exception:
            pass

    # ── SOCKS5 Server ───────────────────────────────────────────────

    def start_server(self):
        if self.server_running:
            self._snack('SOCKS5 服务器已在运行中')
            return

        screen = self.root.get_screen('server')
        host = screen.ids.host_input.text.strip() or '0.0.0.0'
        try:
            port = int(screen.ids.port_input.text.strip() or '3160')
        except ValueError:
            self._snack('端口号无效')
            return

        self.server = SOCKS5Server(host, port)
        self.server.set_packet_callback(self._on_packet_intercepted)
        set_server_instance(self.server)

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        self.server_running = True
        self._update_server_buttons()
        logging.info(f'SOCKS5 服务器启动: {host}:{port}')

    def _run_server(self):
        try:
            self.server.start_server()
        except Exception as e:
            logging.error(f'SOCKS5 异常: {e}')
        finally:
            self.server_running = False

    def stop_server(self):
        if self.server:
            self.server.stop_server()
        self.server_running = False
        self._update_server_buttons()
        logging.info('SOCKS5 服务器已停止')

    # ── Transparent Proxy ───────────────────────────────────────────

    def start_transparent(self):
        if self.transparent_running:
            self._snack('透明代理已在运行中')
            return

        screen = self.root.get_screen('server')
        try:
            tport = int(screen.ids.transparent_port_input.text.strip() or '3161')
        except ValueError:
            self._snack('透明代理端口无效')
            return

        self.transparent = TransparentProxy('0.0.0.0', tport)
        self.transparent.set_packet_callback(self._on_packet_intercepted)
        set_transparent_instance(self.transparent)

        # 同步 iptables manager 端口
        iptables_manager.redirect_port = tport

        self.transparent_thread = threading.Thread(
            target=self._run_transparent, daemon=True
        )
        self.transparent_thread.start()

        self.transparent_running = True
        self._update_server_buttons()
        logging.info(f'透明代理启动: 127.0.0.1:{tport}')

        # 提示用户下一步
        if iptables_manager.check_root():
            self._snack('透明代理已启动 - 请在 iptables 页面配置拦截规则')

    def _run_transparent(self):
        try:
            self.transparent.start()
        except Exception as e:
            logging.error(f'透明代理异常: {e}')
        finally:
            self.transparent_running = False

    def stop_transparent(self):
        if self.transparent:
            self.transparent.stop()
        self.transparent_running = False
        self._update_server_buttons()
        logging.info('透明代理已停止')

    # ── iptables Control ────────────────────────────────────────────

    def _get_iptables_screen(self):
        return self.root.get_screen('iptables')

    def refresh_iptables_status(self):
        """刷新 iptables 页面状态"""
        screen = self._get_iptables_screen()
        status = iptables_manager.get_full_status()
        has_root = status['has_root']

        if has_root:
            screen.ids.root_status_label.text = (
                f'[b][color=#4CAF50]Root: OK[/color][/b]  '
                f'内核: {status["kernel"][:20]}'
            )
        else:
            screen.ids.root_status_label.text = (
                '[b][color=#F44336]Root: 未获取 - Mode B 需要 Root[/color][/b]'
            )

        mode_text = (
            f'模式: {status["mode"]}' if status['mode']
            else '规则状态: 未应用'
        )
        screen.ids.iptables_status_label.text = mode_text
        screen.ids.iptables_rules_label.text = (
            status['rules'] or '无规则\n\n提示: 先选择目标应用 → 点"应用规则"'
        )

        if has_root:
            self._load_app_list()

        # 确保 iptables_manager 端口与透明代理 UI 端口同步
        try:
            tp = screen.ids.transparent_port_input.text.strip()
            if tp:
                iptables_manager.redirect_port = int(tp)
        except ValueError:
            pass

    def _load_app_list(self):
        """加载已安装应用列表"""
        screen = self._get_iptables_screen()
        list_box = screen.ids.app_list_box
        list_box.clear_widgets()

        packages = iptables_manager.list_installed_apps()
        for pkg in packages[:100]:  # 限制数量
            item = MDListItem(
                MDListItemHeadlineText(text=pkg),
                MDListItemSupportingText(text=f'UID: {iptables_manager.get_app_uid(pkg) or "?"}'),
                on_release=lambda x, p=pkg: self._toggle_app_selection(p, x),
                theme_bg_color='Custom',
                md_bg_color=(1, 1, 1, 0.05),
            )
            list_box.add_widget(item)

        screen.ids.app_count_label.text = f'共 {len(packages)} 个第三方应用'
        logging.info(f'已加载 {len(packages)} 个应用')

    def _selected_packages(self):
        return getattr(self, '_selected_pkgs', set())

    def _toggle_app_selection(self, pkg, item):
        selected = self._selected_packages()
        if pkg in selected:
            selected.discard(pkg)
            item.md_bg_color = (1, 1, 1, 0.05)
        else:
            selected.add(pkg)
            item.md_bg_color = hex_color('#1565C0')
        setattr(self, '_selected_pkgs', selected)

        screen = self._get_iptables_screen()
        screen.ids.selected_count_label.text = f'已选 {len(selected)} 个'

    def apply_iptables_rules(self):
        """Mode B 一键设置：启动透明代理 + 为选中应用添加 REDIRECT"""
        if not iptables_manager.check_root():
            self._snack('需要 Root 权限')
            return

        selected = self._selected_packages()
        if not selected:
            self._snack('请先选择要拦截的应用')
            return

        # 如果透明代理未运行，自动启动
        if not self.transparent_running:
            self.start_transparent()
            if not self.transparent_running:
                self._snack('透明代理启动失败')
                return

        uids = []
        for pkg in selected:
            uid = iptables_manager.get_app_uid(pkg)
            if uid:
                uids.append(uid)

        if not uids:
            self._snack('无法获取应用 UID')
            return

        success = iptables_manager.add_uid_rules(uids)
        if success:
            self.iptables_active = True
            self.refresh_iptables_status()
            self._snack(
                f'Mode B 就绪: {len(uids)} 个应用 → 端口 {iptables_manager.redirect_port}'
            )
            logging.info(f'Mode B: {len(uids)} UIDs REDIRECT → :{iptables_manager.redirect_port}')

    def apply_iptables_global(self):
        """全局 REDIRECT — 劫持所有 TCP 流量"""
        if not iptables_manager.check_root():
            self._snack('需要 Root 权限')
            return

        if not self.transparent_running:
            self.start_transparent()
            if not self.transparent_running:
                self._snack('透明代理启动失败')
                return

        success = iptables_manager.add_global_rules()
        if success:
            self.iptables_active = True
            self.refresh_iptables_status()
            self._snack('Mode B 全局模式已启用 - 所有应用 TCP 流量经过代理')
            logging.info('Mode B 全局 REDIRECT 已应用')

    def remove_iptables_rules(self):
        """移除所有 iptables 规则"""
        iptables_manager.remove_redirect_rules()
        self.iptables_active = False
        self.refresh_iptables_status()
        self._snack('iptables 规则已移除')
        logging.info('iptables 规则已清除')

    # ── Packet Handling ─────────────────────────────────────────────

    def _on_packet_intercepted(self, direction, hex_data, size, port, client):
        packet = packet_manager.add_packet(
            direction=direction,
            hex_data=hex_data,
            size=size,
            port=port,
            client=client,
        )
        if packet:
            self._add_packet_row(packet)

    @mainthread
    def _add_packet_row(self, packet):
        try:
            screen = self.root.get_screen('packets')
            list_box = screen.ids.packet_list

            if len(list_box.children) > 500:
                for _ in range(50):
                    if list_box.children:
                        list_box.remove_widget(list_box.children[-1])

            content = packet.get('content', '')
            content_short = content[:30] + ('...' if len(content) > 30 else '')

            row = MDBoxLayout(
                orientation='horizontal',
                adaptive_height=True,
                padding=[4, 6, 4, 6],
                spacing=4,
                size_hint_y=None,
                height=36,
            )

            dir_colors = {
                'C→S': hex_color('#4CAF50'),
                'S→C': hex_color('#FF9800'),
                '连接': hex_color('#2196F3'),
                '透明代理': hex_color('#9C27B0'),
                '自定义发送': hex_color('#00BCD4'),
            }
            dir_color = dir_colors.get(packet['direction'], hex_color('#757575'))

            row.add_widget(MDLabel(
                text=str(packet['id']), font_style='Caption',
                size_hint_x=0.08, theme_text_color='Secondary',
            ))
            row.add_widget(MDLabel(
                text=packet['direction'], font_style='Caption',
                size_hint_x=0.12, theme_text_color='Custom', text_color=dir_color,
            ))
            row.add_widget(MDLabel(
                text=str(packet.get('port', '-')), font_style='Caption',
                size_hint_x=0.1, theme_text_color='Secondary',
            ))
            row.add_widget(MDLabel(
                text=f"{packet.get('size', 0)}B", font_style='Caption',
                size_hint_x=0.1, theme_text_color='Secondary',
            ))
            row.add_widget(MDLabel(
                text=packet.get('timestamp', '-'), font_style='Caption',
                size_hint_x=0.15, theme_text_color='Secondary',
            ))
            row.add_widget(MDLabel(
                text=content_short, font_style='Caption',
                size_hint_x=0.45, theme_text_color='Secondary', shorten=True,
            ))

            list_box.add_widget(row, index=0)
        except Exception:
            pass

    def clear_packets(self):
        packet_manager.clear_packets()
        try:
            self.root.get_screen('packets').ids.packet_list.clear_widgets()
        except Exception:
            pass
        logging.info('数据包已清除')

    def export_packets(self):
        filepath = '/sdcard/Download/packetproxy_export.json'
        try:
            if packet_manager.export_packets(filepath):
                self._snack(f'已导出到 {filepath}')
            else:
                self._snack('导出失败')
        except Exception as e:
            self._snack(f'导出失败: {e}')

    # ── Interception Toggle ─────────────────────────────────────────

    def toggle_interception(self):
        screen = self.root.get_screen('server')
        if self.intercepting:
            packet_manager.stop_interception()
            self.intercepting = False
            screen.ids.intercept_btn.text = '开始拦截'
            screen.ids.intercept_btn.md_bg_color = hex_color('#2E7D32')
        else:
            packet_manager.start_interception()
            self.intercepting = True
            screen.ids.intercept_btn.text = '停止拦截'
            screen.ids.intercept_btn.md_bg_color = hex_color('#C62828')

        if self._update_scheduled is None:
            self._update_scheduled = Clock.schedule_interval(self._update_stats, 1.0)

    # ── Custom Packet Send ──────────────────────────────────────────

    def send_custom_packet(self):
        screen = self.root.get_screen('send')
        port_text = screen.ids.target_port_input.text.strip()
        hex_text = screen.ids.hex_data_input.text.strip()

        if not port_text or not hex_text:
            self._snack('请输入端口和十六进制数据')
            return
        try:
            port = int(port_text)
        except ValueError:
            self._snack('端口号无效')
            return
        try:
            clean = hex_text.replace(' ', '').replace('\n', '')
            if len(clean) % 2 != 0:
                self._snack('十六进制数据长度必须是偶数')
                return
            data = bytes.fromhex(clean)
        except ValueError:
            self._snack('十六进制数据格式无效')
            return

        success = packet_manager.send_custom_packet(port, data)
        if success:
            self._add_send_history(port, hex_text, '成功')
            self._snack(f'已发送 {len(data)}B → 端口 {port}')
        else:
            self._add_send_history(port, hex_text, '失败')
            self._snack(f'发送失败，端口 {port} 无活跃连接')

    @mainthread
    def _add_send_history(self, port, hex_data, status):
        try:
            box = self.root.get_screen('send').ids.send_history
            color = hex_color('#4CAF50') if status == '成功' else hex_color('#F44336')
            row = MDBoxLayout(orientation='horizontal', adaptive_height=True,
                              spacing=8, padding=[4, 4, 4, 4])
            row.add_widget(MDLabel(text=datetime.now().strftime('%H:%M:%S'),
                                   font_style='Caption', size_hint_x=0.2))
            row.add_widget(MDLabel(text=f'端口:{port}', font_style='Caption', size_hint_x=0.2))
            row.add_widget(MDLabel(
                text=hex_data[:25] + ('...' if len(hex_data) > 25 else ''),
                font_style='Caption', size_hint_x=0.4, shorten=True,
            ))
            row.add_widget(MDLabel(
                text=status, font_style='Caption', size_hint_x=0.2,
                theme_text_color='Custom', text_color=color,
            ))
            box.add_widget(row, index=0)
        except Exception:
            pass

    # ── Stats ───────────────────────────────────────────────────────

    @mainthread
    def _update_stats(self, dt):
        try:
            screen = self.root.get_screen('server')
            stats = packet_manager.get_statistics()
            screen.ids.stat_total.text = f"总计: {stats['total']}"
            screen.ids.stat_sent.text = f"上行: {stats['sent']}"
            screen.ids.stat_recv.text = f"下行: {stats['recv']}"
        except Exception:
            pass

    # ── UI Updates ──────────────────────────────────────────────────

    @mainthread
    def _update_server_buttons(self):
        try:
            screen = self.root.get_screen('server')
            screen.ids.start_btn.disabled = self.server_running
            screen.ids.stop_btn.disabled = not self.server_running
            screen.ids.transparent_start_btn.disabled = self.transparent_running
            screen.ids.transparent_stop_btn.disabled = not self.transparent_running

            parts = []
            if self.server_running:
                parts.append(f'SOCKS5 运行中 (端口 {self.server.port})')
            if self.transparent_running:
                parts.append(f'透明代理运行中 (端口 {self.transparent.port})')
            screen.ids.status_label.text = (
                ' | '.join(parts) if parts else '服务器未启动'
            )
        except Exception:
            pass

    @mainthread
    def update_log_display(self):
        try:
            self.root.get_screen('logs').ids.log_text.text = (
                self.log_handler.get_logs()
            )
        except Exception:
            pass

    def clear_logs(self):
        if self.log_handler:
            self.log_handler.clear()
        self._snack('日志已清除')

    def copy_logs(self):
        try:
            from kivy.core.clipboard import Clipboard
            Clipboard.copy(self.log_handler.get_logs())
            self._snack('日志已复制到剪贴板')
        except Exception:
            self._snack('复制失败')

    # ── Helpers ──────────────────────────────────────────────────────

    def _snack(self, text):
        try:
            MDSnackbar(
                MDSnackbarText(text=text),
                y=24,
                pos_hint={'center_x': 0.5},
                size_hint_x=0.9,
                duration=1.5,
            ).open()
        except Exception:
            pass

    def on_start(self):
        logging.info('UI 初始化完成')

    def on_stop(self):
        if self.transparent and self.transparent_running:
            self.transparent.stop()
        if self.server and self.server_running:
            self.server.stop_server()
        iptables_manager.remove_redirect_rules()
        if self._update_scheduled:
            self._update_scheduled.cancel()
        logging.info('应用已关闭')


def run_app():
    """Entry point for Chaquopy / python-for-android."""
    try:
        PacketProxyApp().run()
    except Exception as e:
        print(f'Fatal error: {e}')
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    run_app()
