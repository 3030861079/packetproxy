#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
软件特征随机化模块（Android版）
"""

import random
import string
import hashlib


class AppRandomizer:
    def __init__(self):
        self.title_templates = [
            "Network Monitor - {}",
            "System Analyzer - {}",
            "Connection Manager - {}",
            "Traffic Inspector - {}",
            "Protocol Viewer - {}",
            "Data Monitor - {}",
            "Network Tool - {}",
            "System Utility - {}",
        ]
        self.version_formats = [
            "v{}.{}.{}",
            "Version {}.{}",
            "Build {}.{}.{}",
        ]
        self.color_schemes = [
            {"primary": "#1565C0", "secondary": "#0D47A1"},
            {"primary": "#2E7D32", "secondary": "#1B5E20"},
            {"primary": "#E65100", "secondary": "#BF360C"},
            {"primary": "#6A1B9A", "secondary": "#4A148C"},
            {"primary": "#00838F", "secondary": "#006064"},
        ]

    def generate_random_title(self) -> str:
        template = random.choice(self.title_templates)
        version_format = random.choice(self.version_formats)
        major = random.randint(1, 9)
        minor = random.randint(0, 99)
        patch = random.randint(0, 999)
        if "{}.{}.{}" in version_format:
            version = version_format.format(major, minor, patch)
        else:
            version = version_format.format(major, minor)
        return template.format(version)

    def get_random_color_scheme(self) -> dict:
        return random.choice(self.color_schemes)

    def generate_random_md5(self, length: int = 32) -> str:
        random_string = ''.join(
            random.choices(string.ascii_letters + string.digits, k=64)
        )
        return hashlib.md5(random_string.encode()).hexdigest()[:length]

    def generate_session_id(self) -> str:
        return self.generate_random_md5(16)


app_randomizer = AppRandomizer()


def get_random_app_features() -> dict:
    return {
        'title': app_randomizer.generate_random_title(),
        'color_scheme': app_randomizer.get_random_color_scheme(),
        'session_id': app_randomizer.generate_session_id(),
    }
