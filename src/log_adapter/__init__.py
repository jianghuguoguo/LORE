"""
src/log_adapter  兼容性转发模块
===================================
此模块已并入 src.layer0，保留此包仅供向后兼容。

新代码请直接从 src.layer0 导入：
    from src.layer0 import AdapterRegistry, CanonicalAgentTurn, SessionMeta

.. deprecated::
    使用 ``from src.layer0 import ...`` 代替。
"""
# Re-export everything from the canonical location
from src.layer0.log_adapter import AdapterRegistry, LogAdapter
from src.layer0.canonical_types import CanonicalAgentTurn, SessionMeta, RagQueryInfo
from src.layer0 import adapters  # ensure adapters are registered

__all__ = [
    "AdapterRegistry",
    "LogAdapter",
    "CanonicalAgentTurn",
    "SessionMeta",
    "RagQueryInfo",
    "adapters",
]
