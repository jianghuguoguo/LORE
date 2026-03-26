"""
LORE Layer 0 包
======================
Layer 0：日志标准化层（含格式适配子层）

子模块职责（严格按技术方案 六.Layer0）：

  格式适配子层（Pre-Layer0，对上层透明）：
    canonical_types.py   – 规范内部格式 CanonicalAgentTurn / SessionMeta / RagQueryInfo
    log_adapter.py       – LogAdapter 抽象基类 + AdapterRegistry 注册表
    adapters/            – 内置适配器：CAI / LangChain / OpenAI Assistants / Generic JSONL

  解析与提取子层（Layer0 核心）：
    parser.py    – Step 1：轮次重建状态机，从 JSONL 行流重建 Turn 三段式结构
    extractor.py – Step 2：事件原子提取，从 Turn 对象提取 AtomicEvent 列表
    assembler.py – Step 3/4：序列构建，标注 has_rag_context 与脚本关联
"""
from .parser import LogParser
from .extractor import EventExtractor
from .assembler import TurnSequenceAssembler
from .pipeline import run_layer0

# 格式适配层公共 API
from .log_adapter import AdapterRegistry, LogAdapter
from .canonical_types import CanonicalAgentTurn, SessionMeta, RagQueryInfo
from . import adapters  # 触发所有内置适配器注册（side-effect import）

__all__ = [
    # Layer0 核心
    "LogParser",
    "EventExtractor",
    "TurnSequenceAssembler",
    "run_layer0",
    # 格式适配层
    "AdapterRegistry",
    "LogAdapter",
    "CanonicalAgentTurn",
    "SessionMeta",
    "RagQueryInfo",
    "adapters",
]

