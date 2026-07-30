#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
十六进制模式搜索工具类（Android版）
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


class HexPatternUtils:

    @staticmethod
    def clean_hex_string(hex_string: str) -> str:
        return hex_string.replace(" ", "").replace("-", "").replace(":", "").upper()

    @staticmethod
    def search_pattern(hex_data: str, pattern: str) -> int:
        try:
            clean_pattern = HexPatternUtils.clean_hex_string(pattern)
            clean_hex_data = HexPatternUtils.clean_hex_string(hex_data)
            if len(clean_pattern) == 0 or len(clean_hex_data) == 0:
                return -1
            if len(clean_pattern) % 2 != 0:
                return -1
            count = 0
            start_pos = 0
            while True:
                pos = clean_hex_data.find(clean_pattern, start_pos)
                if pos == -1:
                    break
                count += 1
                start_pos = pos + 2
            return count if count > 0 else -1
        except Exception as e:
            logger.error(f"search_pattern error: {e}")
            return -1

    @staticmethod
    def find_pattern_positions(hex_data: str, pattern: str) -> List[int]:
        try:
            clean_pattern = HexPatternUtils.clean_hex_string(pattern)
            clean_hex_data = HexPatternUtils.clean_hex_string(hex_data)
            if len(clean_pattern) == 0 or len(clean_hex_data) == 0:
                return []
            if len(clean_pattern) % 2 != 0:
                return []
            positions = []
            start_pos = 0
            while True:
                pos = clean_hex_data.find(clean_pattern, start_pos)
                if pos == -1:
                    break
                positions.append(pos // 2)
                start_pos = pos + 2
            return positions
        except Exception as e:
            logger.error(f"find_pattern_positions error: {e}")
            return []
