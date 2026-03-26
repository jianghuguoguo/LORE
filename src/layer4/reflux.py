"""
src/layer4/reflux.py
=====================
经验回流（Reflux）管道：将 KLM 中 active+consolidated 的经验写入 RAGFlow。

核心函数：
  format_exp_for_rag(exp)                → 纯文本（RAGFlow 存储格式）
  flush_reflux_ready_to_ragflow(...)     → 批量写入并更新 KLM 回流标记
  remove_conflicted_from_ragflow(...)    → 删除已被标记 conflicted 的文档

设计原则（文档 §2.3）：
  - RAGFlow 是只读缓存，本地 KLM 是 Source of Truth
  - 冲突检测在本地完成，通过后才调用此模块写入
  - conflicted/suspended 经验永远不写入 RAGFlow
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .reflux_document_builder import (
    resolve_reflux_dataset_id,
    validate_document_for_retrieval,
)

if TYPE_CHECKING:
    from ..layer4.conflict import LocalKLMBackend
    from ..ragflow.client import RAGFlowExpClient

logger = logging.getLogger(__name__)


MATURITY_LABEL: Dict[str, str] = {
    "consolidated": "★★★ consolidated",
    "validated": "★★☆ validated",
    "raw": "★☆☆ raw",
}


def _normalize_layer(layer: str) -> str:
    if str(layer).startswith("FACTUAL_"):
        return "FACTUAL"
    return layer or "UNKNOWN"


def _to_list(value: Any) -> List[str]:
    """把字符串/列表统一为字符串列表，便于 THEN/NOT 等字段拼接。"""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _collect_factual_cve_status(content: Dict[str, Any]) -> Dict[str, str]:
    """聚合 FACTUAL CVE 状态，兼容 consolidated 与 LLM 原始 schema。"""
    result: Dict[str, str] = {}

    cve_map = content.get("cve_exploitation_map", {})
    if isinstance(cve_map, dict):
        for cve, info in cve_map.items():
            cve_id = str(cve).strip().upper()
            if not cve_id:
                continue
            status = ""
            if isinstance(info, dict):
                status = str(
                    info.get("consensus_status")
                    or info.get("consensus_category")
                    or info.get("status")
                    or ""
                ).strip()
            else:
                status = str(info).strip()
            result[cve_id] = status or "attempted"

    cve_ctx = content.get("cve_context", {})
    if isinstance(cve_ctx, dict):
        status_map: Dict[str, Any] = {}
        for key in ("exploitation_status", "exploitation_results"):
            raw_map = cve_ctx.get(key, {})
            if isinstance(raw_map, dict):
                status_map.update(raw_map)

        attempted = cve_ctx.get("attempted", [])
        if isinstance(attempted, list):
            for cve in attempted:
                cve_raw = str(cve).strip()
                cve_id = cve_raw.upper()
                if not cve_id or cve_id in result:
                    continue
                status = status_map.get(cve_raw)
                if status is None:
                    status = status_map.get(cve_id)
                if isinstance(status, dict):
                    status = status.get("status") or status.get("consensus_status")
                result[cve_id] = str(status).strip() if status else "attempted"

    return result


def _format_conceptual_body(content: Dict[str, Any]) -> List[str]:
    """格式化 CONCEPTUAL 层，避免回落到 dict repr。"""
    lines: List[str] = []
    core_insight = str(content.get("core_insight", "")).strip()
    pattern_type = str(content.get("pattern_type", "")).strip()

    if core_insight:
        lines.append(f"Insight: {core_insight}")
    if pattern_type:
        lines.append(f"Pattern: {pattern_type}")

    conditions = content.get("applicable_conditions", {})
    if isinstance(conditions, dict):
        positive = _to_list(conditions.get("positive"))
        negative = _to_list(conditions.get("negative"))
        triggers = _to_list(conditions.get("retrieval_triggers"))
        if positive:
            lines.append("Applies when: " + "; ".join(positive[:5]))
        if negative:
            lines.append("Not for: " + "; ".join(negative[:3]))
        if triggers:
            lines.append("Retrieval triggers: " + "; ".join(triggers[:8]))

    evidence = _to_list(content.get("supporting_evidence"))
    if evidence:
        lines.append("Evidence: " + "; ".join(evidence[:3]))

    return lines or ["(no conceptual content)"]


def _format_metacognitive_body(content: Dict[str, Any]) -> List[str]:
    """格式化 METACOGNITIVE 层，优先使用已知结构字段。"""
    lines: List[str] = []

    goal = str(content.get("session_goal", "")).strip()
    outcome = str(content.get("session_outcome", "")).strip()
    if goal:
        lines.append(f"Session goal: {goal}")
    if outcome:
        lines.append(f"Outcome: {outcome}")

    lessons = _to_list(content.get("key_lessons"))
    structured = content.get("key_lessons_structured", [])
    if isinstance(structured, list):
        for item in structured:
            if not isinstance(item, dict):
                continue
            lesson = str(item.get("lesson") or item.get("rule") or "").strip()
            if lesson:
                lessons.append(lesson)

    uniq_lessons: List[str] = []
    seen: set = set()
    for lesson in lessons:
        if lesson and lesson not in seen:
            seen.add(lesson)
            uniq_lessons.append(lesson)
    if uniq_lessons:
        lines.append("Key lessons: " + "; ".join(uniq_lessons[:5]))

    mistakes = content.get("decision_mistakes", [])
    if isinstance(mistakes, list):
        rendered: List[str] = []
        for item in mistakes[:3]:
            if not isinstance(item, dict):
                continue
            mistake = str(item.get("mistake", "")).strip()
            rule = str(item.get("rule", "")).strip()
            if mistake and rule:
                rendered.append(f"{mistake} => {rule}")
        if rendered:
            lines.append("Decision mistakes: " + "; ".join(rendered))

    optimal = _to_list(content.get("optimal_decision_path"))
    if optimal:
        lines.append("Optimal path: " + "; ".join(optimal[:6]))

    missed = _to_list(content.get("missed_opportunities"))
    if missed:
        lines.append("Missed opportunities: " + "; ".join(missed[:4]))

    failure_pattern = str(content.get("failure_pattern", "")).strip()
    if failure_pattern and failure_pattern.lower() not in {"none", "null"}:
        lines.append(f"Failure pattern: {failure_pattern}")

    success_factor = str(content.get("success_factor", "")).strip()
    if success_factor and success_factor.lower() not in {"none", "null"}:
        lines.append(f"Success factor: {success_factor}")

    return lines or ["(no metacognitive content)"]


# ─────────────────────────────────────────────────────────────────────────────
# 格式化：经验 → RAGFlow 文档文本
# ─────────────────────────────────────────────────────────────────────────────

def format_chunk_for_ragflow(exp: Dict[str, Any]) -> str:
    """
    将 LORE 经验条目格式化为写入 RAGFlow 的 chunk 文本。

    关键要求：
    1. 首行嵌入成熟度标签（Agent 可直接读取）。
    2. FACTUAL 仅保留稳定事实，过滤瞬态键（open_port/http_status/output_summary）。
    3. 保持 QUERY_HINTS 段，兼容现有质量校验与检索路由。
    """
    exp_id = exp.get("exp_id", "UNKNOWN")
    layer = _normalize_layer(str(exp.get("knowledge_layer", "UNKNOWN")))
    content = exp.get("content") or {}
    metadata = exp.get("metadata") or {}
    constraints = metadata.get("applicable_constraints") or {}

    maturity = str(exp.get("maturity", "raw") or "raw").lower()
    p_fused = float(exp.get("p_fused") or exp.get("confidence") or 0.0)
    n_sess = int(exp.get("n_independent_sessions") or 1)
    label = MATURITY_LABEL.get(maturity, MATURITY_LABEL["raw"])

    target_service = (
        exp.get("target_service")
        or content.get("target_service")
        or constraints.get("target_service")
        or "unknown"
    )

    # 问题 3 修复：同步 content.cve_context.attempted 到顶层 cve_ids 做 RAG 检索标签
    cve_ids = (
        exp.get("cve_ids")
        or content.get("cve_ids")
        or constraints.get("cve_ids")
    )
    if not cve_ids:
        # 深度扫描 content.cve_context.attempted (FACTUAL_LLM 逻辑)
        cve_ids = content.get("cve_context", {}).get("attempted", [])
    
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids] if cve_ids else []
    
    cve_ids = [str(c).upper() for c in cve_ids if str(c).strip()]

    header_lines: List[str] = [
        f"[{label} | {n_sess} sessions | p={p_fused:.2f}]",
        f"[XPEC] {layer} | {exp_id}",
        f"knowledge_layer: {layer}",
        f"target_service: {target_service}",
        f"confidence: {p_fused:.4f}",
    ]
    if cve_ids:
        header_lines.append("cve_ids: " + ", ".join(cve_ids))

    body_lines: List[str] = []
    if layer == "PROCEDURAL_NEG":
        dr = content.get("decision_rule", {}) if isinstance(content.get("decision_rule"), dict) else {}
        then_items = _to_list(dr.get("THEN"))
        not_items = _to_list(dr.get("NOT"))
        body_lines.append(f"IF {str(dr.get('IF', '')).strip()}")
        body_lines.append(f"THEN {'; '.join(then_items)}")
        body_lines.append(f"NOT {'; '.join(not_items)}")
    elif layer == "PROCEDURAL_POS":
        context_condition = (
            str(content.get("context_condition", "")).strip()
            or "; ".join(_to_list(content.get("preconditions")))
            or str(content.get("attack_phase", "")).strip()
        )
        command = str(content.get("command_template", "")).strip()
        expected = (
            str(content.get("expected_signal", "")).strip()
            or "; ".join(_to_list(content.get("success_indicators")))
        )
        body_lines.append(f"Context: {context_condition}")
        body_lines.append(f"Command: {command}")
        body_lines.append(f"Expected: {expected}")
    elif layer == "FACTUAL":
        stable_lines: List[str] = []
        facts = content.get("discovered_facts", [])
        if isinstance(facts, list):
            for fact in facts:
                if not isinstance(fact, dict):
                    continue
                key = str(fact.get("key", "")).strip()
                if key == "open_port":
                    # 与 layer2 factual._is_semantic_fact 对齐：仅保留带 service/version 的端口事实。
                    service = str(fact.get("service", "")).strip()
                    version = str(fact.get("version", "")).strip()
                    if not (service or version):
                        continue
                    value = str(fact.get("value", "")).strip()
                    details: List[str] = []
                    if value:
                        details.append(value)
                    if service:
                        details.append(f"service={service}")
                    if version:
                        details.append(f"version={version}")
                    stable_lines.append("open_port: " + " | ".join(details))
                    continue
                if key in {"http_status", "output_summary", "open_port_evidence"}:
                    continue
                value = str(fact.get("value", "")).strip()
                if key and value:
                    stable_lines.append(f"{key}: {value}")

        # LLM 来源 FACTUAL 可能没有 discovered_facts，这里补充稳定语义字段。
        if not stable_lines:
            svc = str(content.get("target_service", "")).strip()
            ver = str(content.get("target_version", "")).strip()
            status = str(content.get("exploitation_status", "")).strip()
            if svc:
                stable_lines.append(f"target_service: {svc}")
            if ver and ver.lower() not in {"none", "null"}:
                stable_lines.append(f"target_version: {ver}")
            if status:
                stable_lines.append(f"exploitation_status: {status}")

            cve_map = _collect_factual_cve_status(content)
            for cve, cve_status in cve_map.items():
                stable_lines.append(f"{cve}: {cve_status}")

        body_lines.extend(stable_lines or ["(no stable facts)"])
    elif layer in ("META_CONCEPTUAL", "CONCEPTUAL"):
        body_lines.extend(_format_conceptual_body(content))
    elif layer == "METACOGNITIVE":
        body_lines.extend(_format_metacognitive_body(content))
    else:
        body_lines.append(str(content))

    hint_items: List[str] = [layer]
    if target_service and target_service != "unknown":
        hint_items.append(str(target_service))
    hint_items.extend(cve_ids[:8])
    hint_items = [h for h in hint_items if str(h).strip()]

    out: List[str] = []
    out.extend(header_lines)
    out.append("")
    out.extend(body_lines)
    out.append("")
    out.append("QUERY_HINTS:")
    for item in hint_items:
        out.append(f"- {item}")
    return "\n".join(out)

def format_exp_for_rag(exp: Dict[str, Any]) -> str:
    """兼容旧调用：统一走新的成熟度可见 chunk 模板。"""
    return format_chunk_for_ragflow(exp)


# ─────────────────────────────────────────────────────────────────────────────
# 结果数据类
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RefluxResult:
    """flush_reflux_ready_to_ragflow 的执行结果摘要。"""
    total_candidates:   int = 0
    uploaded:           int = 0
    skipped_already:    int = 0
    failed:             int = 0
    deleted_conflicted: int = 0
    uploaded_primary:   int = 0
    uploaded_secondary: int = 0
    dry_run:            bool = False
    uploaded_ids:       List[str] = field(default_factory=list)
    failed_ids:         List[str] = field(default_factory=list)
    deleted_ids:        List[str] = field(default_factory=list)
    ran_at:             str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


# ─────────────────────────────────────────────────────────────────────────────
# 主流程：回流到 RAGFlow
# ─────────────────────────────────────────────────────────────────────────────

def flush_reflux_ready_to_ragflow(
    klm_backend: "LocalKLMBackend",
    ragflow_client: "RAGFlowExpClient",
    llm_client: Optional[Any] = None,
    dry_run: bool = False,
    commit: bool = True,
) -> RefluxResult:
    """
    将 KLM 中所有符合「回流就绪」条件的经验写入 RAGFlow。

    回流条件（来自文档 §2.2）：
      lifecycle_status = 'active'
      maturity         = 'consolidated'
      should_reflux    = True（或 klm_reflux_timestamp 存在）
      ragflow_doc_id   = null（尚未写入）

    每次写入成功后立即调用 klm_backend.mark_refluxed()，
    最后调用 klm_backend.commit() 持久化（若 commit=True）。
    """
    result = RefluxResult(dry_run=dry_run)

    candidates = klm_backend.query(
        lifecycle="active",
        maturity="consolidated",
        should_reflux=True,
        refluxed=False,
    )
    result.total_candidates = len(candidates)

    if not candidates:
        logger.info("[reflux] 无待回流经验")
        return result

    logger.info("[reflux] 发现 %d 条待回流经验", len(candidates))

    for exp in candidates:
        exp_id = exp.get("exp_id", "UNKNOWN")
        layer  = _normalize_layer(str(exp.get("knowledge_layer", "UNKNOWN")))

        # 额外安全门：lifecycle 必须是 active
        if exp.get("lifecycle_status") != "active":
            logger.warning("[reflux] SKIP %s lifecycle=%s 非 active，跳过",
                           exp_id, exp.get("lifecycle_status"))
            result.skipped_already += 1
            continue

        content_text = format_chunk_for_ragflow(exp)
        quality_issues = validate_document_for_retrieval(content_text, exp)
        target_dataset, route = resolve_reflux_dataset_id(
            ragflow_client=ragflow_client,
            knowledge_layer=layer,
            quality_issues=quality_issues,
        )

        if dry_run:
            logger.info(
                "[reflux][dry-run] 模拟上传 %s [%s] route=%s issues=%d dataset=%s",
                exp_id,
                layer,
                route,
                len(quality_issues),
                target_dataset,
            )
            result.uploaded += 1
            result.uploaded_ids.append(exp_id)
            if route == "secondary":
                result.uploaded_secondary += 1
            else:
                result.uploaded_primary += 1
            continue

        title = f"[XPEC][{route.upper()}] {layer} {exp_id}"
        # 上传
        doc_id = ragflow_client.upload_exp(
            exp_id=exp_id,
            title=title,
            content_text=content_text,
            dataset_id=target_dataset,
        )
        if doc_id:
            klm_backend.update_fields(
                exp_id,
                reflux_bucket=route,
                reflux_dataset_id=target_dataset,
                retrieval_doc_quality_issues=quality_issues,
                retrieval_doc_word_count=len(content_text.split()),
            )
            klm_backend.mark_refluxed(exp_id, ragflow_doc_id=doc_id)
            result.uploaded += 1
            result.uploaded_ids.append(exp_id)
            if route == "secondary":
                result.uploaded_secondary += 1
            else:
                result.uploaded_primary += 1
            logger.info(
                "[reflux] OK exp_id=%s route=%s dataset=%s doc_id=%s issues=%s",
                exp_id,
                route,
                target_dataset,
                doc_id,
                quality_issues[:3],
            )
        else:
            result.failed += 1
            result.failed_ids.append(exp_id)
            logger.error("[reflux] FAIL exp_id=%s 上传失败", exp_id)

    # 持久化 KLM
    if commit and not dry_run:
        klm_backend.commit()

    logger.info(
        "[reflux] 完成 candidates=%d uploaded=%d(primary=%d secondary=%d) failed=%d skipped=%d",
        result.total_candidates,
        result.uploaded,
        result.uploaded_primary,
        result.uploaded_secondary,
        result.failed,
        result.skipped_already,
    )
    return result


def remove_conflicted_from_ragflow(
    klm_backend: "LocalKLMBackend",
    ragflow_client: "RAGFlowExpClient",
    newly_conflicted_ids: List[str],
    dry_run: bool = False,
    commit: bool = True,
) -> RefluxResult:
    """
    对新近被标记为 conflicted 的经验，若已存在于 RAGFlow，则删除。

    设计（文档 §2.4 Step 8）：
      for exp_id in newly_conflicted:
          exp = klm.get(exp_id)
          if exp.ragflow_doc_id:
              ragflow_client.delete_document(exp.ragflow_doc_id)
              klm.clear_ragflow_doc_id(exp_id)
    """
    result = RefluxResult(dry_run=dry_run)

    for exp_id in newly_conflicted_ids:
        exp = klm_backend.get(exp_id)
        if not exp:
            continue
        doc_id = exp.get("ragflow_doc_id")
        if not doc_id:
            continue  # 未写入 RAGFlow，无需删除

        result.total_candidates += 1

        if dry_run:
            logger.info("[remove_conflicted][dry-run] 模拟删除 %s doc_id=%s", exp_id, doc_id)
            result.deleted_conflicted += 1
            result.deleted_ids.append(exp_id)
            continue

        ok = ragflow_client.delete_document(doc_id)
        if ok:
            klm_backend.clear_ragflow_doc_id(exp_id)
            result.deleted_conflicted += 1
            result.deleted_ids.append(exp_id)
            logger.info("[remove_conflicted] OK exp_id=%s doc_id=%s", exp_id, doc_id)
        else:
            result.failed += 1
            result.failed_ids.append(exp_id)
            logger.error("[remove_conflicted] FAIL exp_id=%s doc_id=%s", exp_id, doc_id)

    if commit and not dry_run and result.deleted_conflicted > 0:
        klm_backend.commit()

    logger.info(
        "[remove_conflicted] 完成 candidates=%d deleted=%d failed=%d",
        result.total_candidates, result.deleted_conflicted, result.failed,
    )
    return result
