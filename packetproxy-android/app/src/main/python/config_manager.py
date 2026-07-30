#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块（Android版）
"""

import os
import json
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config_data = {}
        self.default_config = self._get_default_config()
        self.load_config()

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'server': {
                'host': '127.0.0.1',
                'port': 3160,
                'max_connections': 100,
                'timeout': 30,
                'buffer_size': 4096,
            },
            'security': {
                'enable_auth': False,
                'username': '',
                'password': '',
            },
            'ui': {
                'theme': 'Dark',
                'auto_refresh': True,
                'refresh_interval': 1.0,
            },
            'packet': {
                'max_packets': 500,
            },
            'network': {
                'connect_timeout': 10,
                'read_timeout': 30,
            },
        }

    def load_config(self) -> bool:
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_data = json.load(f)
                self.config_data = self._merge_config(
                    self.default_config, self.config_data
                )
                logger.info("Config loaded")
                return True
            else:
                self.config_data = self.default_config.copy()
                self.save_config()
                logger.info("Using default config")
                return True
        except Exception as e:
            logger.error(f"Load config failed: {e}")
            self.config_data = self.default_config.copy()
            return False

    def save_config(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.config_file) or '.', exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"Save config failed: {e}")
            return False

    def _merge_config(self, default, user):
        result = default.copy()
        for key, value in user.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, key: str, default: Any = None) -> Any:
        try:
            keys = key.split('.')
            value = self.config_data
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
        except Exception:
            return default

    def set(self, key: str, value: Any) -> bool:
        try:
            keys = key.split('.')
            config = self.config_data
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            config[keys[-1]] = value
            return True
        except Exception as e:
            logger.error(f"Set config failed: {e}")
            return False

    def get_server_config(self):
        return self.get('server', {})

    def get_ui_config(self):
        return self.get('ui', {})


config_manager = ConfigManager()
