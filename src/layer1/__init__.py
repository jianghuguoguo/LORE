"""
Layer 1：语义标注层
===================
Phase 2 实现：确定性规则部分（失败根因规则层）
Phase 3 实现：LLM 语义理解（attack_phase / failure_cause / RAG 因果 / session_outcome）

对外暴露：
    run_layer1           — 规则层（Phase 2），单个 TurnSequence
    run_layer1_batch     — 规则层批量处理
    run_layer1_with_llm  — 完整 Layer 1（规则 + LLM），单个 TurnSequence（Phase 3）
    run_layer1_llm_batch — 完整 Layer 1 批量处理（Phase 3）
"""

from .pipeline import (
    run_layer1,
    run_layer1_batch,
    run_layer1_with_llm,
    run_layer1_llm_batch,
)

__all__ = [
    "run_layer1",
    "run_layer1_batch",
    "run_layer1_with_llm",
    "run_layer1_llm_batch",
]
