#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据包管理模块（Android版 - 无psutil依赖）
"""

import json
import os
import time
from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PacketManager:
    def __init__(self):
        self.current_packets = []
        self.packet_id_counter = 1
        self.interception_enabled = False
        self.background_interception = True
        self.max_packets = 500
        self.ui_callback = None

    def set_ui_callback(self, callback):
        self.ui_callback = callback

    def add_packet(
        self,
        direction: str = '',
        hex_data: str = '',
        size: int = 0,
        port: int = 0,
        client: str = '',
    ) -> Dict[str, Any]:
        if not self.background_interception:
            return None

        packet = {
            'id': self.packet_id_counter,
            'direction': direction,
            'content': hex_data,
            'size': size,
            'port': port,
            'client': client,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'created_time': datetime.now().isoformat(),
        }

        if self.interception_enabled:
            if len(self.current_packets) >= self.max_packets:
                remove_count = min(50, len(self.current_packets) // 10)
                self.current_packets = self.current_packets[remove_count:]
            self.current_packets.append(packet)

            if self.ui_callback:
                self.ui_callback(packet)

        self.packet_id_counter += 1
        return packet

    def get_packets(self) -> List[Dict[str, Any]]:
        return self.current_packets.copy()

    def start_interception(self):
        self.interception_enabled = True
        logger.info("Interception started")

    def stop_interception(self):
        self.interception_enabled = False
        logger.info("Interception stopped")

    def is_interception_enabled(self) -> bool:
        return self.interception_enabled

    def clear_packets(self):
        self.current_packets.clear()
        self.packet_id_counter = 1
        logger.info("Packets cleared")

    def send_custom_packet(self, target_port: int, data: bytes) -> bool:
        try:
            from socks5_server import get_server_instance
            server = get_server_instance()
            if server is None:
                logger.error("Server not running")
                return False
            success = server.send_custom_packet(target_port, data)
            if success:
                self.add_packet(
                    direction='自定义发送',
                    hex_data=data.hex().upper(),
                    size=len(data),
                    port=target_port,
                    client='用户自定义',
                )
            return success
        except Exception as e:
            logger.error(f"Send custom packet error: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        total = len(self.current_packets)
        if total == 0:
            return {'total': 0, 'sent': 0, 'recv': 0, 'custom': 0}

        sent = sum(1 for p in self.current_packets if p['direction'] == 'C→S')
        recv = sum(1 for p in self.current_packets if p['direction'] == 'S→C')
        custom = sum(1 for p in self.current_packets if p['direction'] == '自定义发送')
        return {
            'total': total,
            'sent': sent,
            'recv': recv,
            'custom': custom,
        }

    def export_packets(self, filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.current_packets, f, ensure_ascii=False, indent=2)
            logger.info(f"Exported {len(self.current_packets)} packets to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


packet_manager = PacketManager()
