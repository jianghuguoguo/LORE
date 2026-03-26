"""
LORE 日志工具
====================
提供统一的结构化日志打印（通过 Python logging + structlog-like 格式）。
避免引入重度外部依赖，使用标准库即可运行。
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Optional


def get_logger(name: str) -> logging.Logger:
    """获取格式化 logger"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)-8s] %(name)-40s %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

