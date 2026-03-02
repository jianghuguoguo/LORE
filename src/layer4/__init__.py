"""
Layer 4 — 知识库主动维护层
缺口感知 · 外部知识获取 · 冲突清理

主要入口：
  from src.layer4.gap_queue import GapQueue
  from src.layer4.models import GapSignal, GapPriority
  from src.layer4.dispatcher import get_dispatcher_instance, Layer4Dispatcher
"""

from .models import GapSignal, GapPriority, CrawlResult, ConflictRequest
from .gap_queue import GapQueue

__all__ = [
    "GapSignal", "GapPriority", "CrawlResult", "ConflictRequest",
    "GapQueue",
]
