"""
src/layer4/reflux_document_builder.py
=====================================
Reflux 文档构建适配层。

对外提供稳定接口：
  - build_retrieval_document(exp, llm_client) -> str
  - validate_document_for_retrieval(doc_text, exp) -> list[str]
  - resolve_reflux_dataset_id(ragflow_client, knowledge_layer, quality_issues) -> (dataset_id, route)

内部复用 retrieval_document_builder 的实现，保证 llm_client=None 时可优雅降级。
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .retrieval_document_builder import (
    build_retrieval_document as _build_doc_result,
    normalize_layer,
    validate_retrieval_document,
)
from ..utils.config_loader import get_config


def build_retrieval_document(
    exp: Dict[str, Any],
    llm_client: Any,
) -> str:
    """把结构化 exp JSON 转换成适合 RAGFlow 检索的文档文本。"""
    result = _build_doc_result(exp, llm_client=llm_client)
    return (result.content_text or "").strip()


def validate_document_for_retrieval(
    doc_text: str,
    exp: Dict[str, Any],
) -> List[str]:
    """验证文档质量，返回问题列表（空列表=通过）。"""
    return validate_retrieval_document(exp, doc_text)


def resolve_reflux_dataset_id(
    ragflow_client: Any,
    knowledge_layer: str,
    quality_issues: List[str],
) -> Tuple[str, str]:
    """根据层类型和质量问题决定写入 dataset，返回 (dataset_id, route)。"""
    primary_dataset = getattr(ragflow_client, "dataset_id", "") or ""
    try:
        secondary_dataset = get_config().layer4_secondary_dataset_id or primary_dataset
    except Exception:
        secondary_dataset = primary_dataset

    _ = normalize_layer(knowledge_layer)
    if quality_issues:
        return secondary_dataset, "secondary"
    return primary_dataset, "primary"
