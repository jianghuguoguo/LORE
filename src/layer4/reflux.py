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

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..layer4.conflict import LocalKLMBackend
    from ..ragflow.client import RAGFlowExpClient

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# WAF-safe 序列化辅助：递归移除会触发 WAF 的可执行命令字段
# ─────────────────────────────────────────────────────────────────────────────

_WAF_SENSITIVE_KEYS = frozenset({"command", "cmd", "exec", "payload", "exploit_code"})


def _strip_commands(obj: Any) -> Any:
    """
    递归遍历 dict/list，将 _WAF_SENSITIVE_KEYS 对应的字段值替换为占位符，
    避免上传到 RAGFlow 时触发服务器 WAF（502）。
    完整命令仍保留在本地 KLM，RAGFlow 只存储可供语义检索的描述性字段。
    """
    if isinstance(obj, dict):
        return {
            k: ("[COMMAND_REDACTED]" if k in _WAF_SENSITIVE_KEYS else _strip_commands(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_strip_commands(item) for item in obj]
    return obj

# ─────────────────────────────────────────────────────────────────────────────
# 格式化：经验 → RAGFlow 文档文本
# ─────────────────────────────────────────────────────────────────────────────

def              format_exp_for_rag(exp: Dict[str, Any]) -> str:
    """
    将 KLM 经验条目格式化为 RAGFlow 可检索的纯文本文档。

    文档结构（纯文本，方便 naive 分块器处理）：
    ```
    [XPEC] {knowledge_layer} | {exp_id}
    目标服务: ...
    CVE: ...
    融合置信度: ...
    会话数: ...

    === 核心内容 ===
    ...（根据 knowledge_layer 输出不同字段）

    === 适用约束 ===
    ...

    === 来源溯源 ===
    source_exp_ids: ...
    n_independent_sessions: ...
    ```
    """
    exp_id        = exp.get("exp_id", "UNKNOWN")
    layer         = exp.get("knowledge_layer", "UNKNOWN")
    maturity      = exp.get("maturity", "unknown")
    p_fused       = exp.get("p_fused") or exp.get("confidence") or 0.0
    n_sessions    = exp.get("n_independent_sessions") or 1
    metadata      = exp.get("metadata") or {}
    constraints   = metadata.get("applicable_constraints") or {}
    target_svc    = (
        exp.get("target_service")
        or constraints.get("target_service", "")
    )
    cve_ids       = (
        exp.get("cve_ids")
        or constraints.get("cve_ids")
        or []
    )
    provenance    = exp.get("provenance") or {}
    source_ids    = (
        exp.get("source_exp_ids")
        or provenance.get("source_exp_ids")
        or []
    )
    content       = exp.get("content") or {}

    lines: List[str] = []

    # ── 头部 ──────────────────────────────────────────────────────────────────
    lines.append(f"[XPEC] {layer} | {exp_id}")
    if target_svc:
        lines.append(f"目标服务: {target_svc}")
    if cve_ids:
        cve_str = ", ".join(cve_ids) if isinstance(cve_ids, list) else str(cve_ids)
        lines.append(f"CVE: {cve_str}")
    lines.append(f"融合置信度 (p_fused): {p_fused:.4f}")
    lines.append(f"独立会话数: {n_sessions}  成熟度: {maturity}")
    lines.append("")

    # ── 核心内容（按 layer 分派）──────────────────────────────────────────────
    lines.append("=== 核心内容 ===")
    if layer in ("PROCEDURAL_NEG", "PROCEDURAL_POS"):
        failure_dim = content.get("failure_dimension") or content.get("success_dimension", "")
        failure_sub = content.get("failure_sub_dimension") or content.get("success_sub_dimension", "")
        if failure_dim:
            lines.append(f"维度: {failure_dim}/{failure_sub}")
        dr = content.get("decision_rule")
        if dr:
            if isinstance(dr, dict):
                for key, val in dr.items():
                    if val:
                        val_str = (
                            json.dumps(_strip_commands(val), ensure_ascii=False)
                            if isinstance(val, (list, dict))
                            else str(val)
                        )
                        lines.append(f"  {key}: {val_str}")
            else:
                lines.append(f"  决策规则: {dr}")
        evidence = content.get("evidence", "")
        if evidence:
            lines.append(f"证据: {evidence[:300]}")

    elif layer in ("FACTUAL_RULE", "FACTUAL_LLM"):
        rule_content = content.get("rule") or content.get("knowledge", "")
        if rule_content:
            lines.append(str(rule_content)[:500])
        src = content.get("source") or content.get("reference", "")
        if src:
            lines.append(f"来源: {src}")

    elif layer == "CONCEPTUAL":
        concept = content.get("concept") or content.get("description", "")
        if concept:
            lines.append(str(concept)[:500])

    elif layer == "METACOGNITIVE":
        goal = content.get("session_goal", "")
        lessons = content.get("key_lessons") or []
        if goal:
            lines.append(f"会话目标: {goal}")
        if lessons:
            lines.append("关键经验:")
            for lesson in lessons[:5]:
                lines.append(f"  - {lesson}")

    elif layer == "RAG_EVALUATION":
        util = content.get("rag_utility_score")
        ctx = content.get("context_coverage", "")
        if util is not None:
            lines.append(f"RAG 效用评分: {util}")
        if ctx:
            lines.append(f"上下文覆盖: {ctx}")

    else:
        # 通用序列化
        for k, v in list(content.items())[:8]:
            lines.append(f"  {k}: {str(v)[:200]}")

    lines.append("")

    # ── 适用约束 ─────────────────────────────────────────────────────────────
    version_family = (
        exp.get("version_family")
        or constraints.get("version_family", "")
    )
    cond_kw = constraints.get("condition_keywords") or []
    if any([target_svc, cve_ids, version_family, cond_kw]):
        lines.append("=== 适用约束 ===")
        if target_svc:
            lines.append(f"  target_service: {target_svc}")
        if cve_ids:
            lines.append(f"  cve_ids: {cve_ids}")
        if version_family:
            lines.append(f"  version_family: {version_family}")
        if cond_kw:
            lines.append(f"  keywords: {cond_kw[:10]}")
        lines.append("")

    # ── 来源溯源 ─────────────────────────────────────────────────────────────
    if source_ids or n_sessions > 1:
        lines.append("=== 来源溯源 ===")
        if source_ids:
            lines.append(f"  source_exp_ids: {source_ids}")
        lines.append(f"  n_independent_sessions: {n_sessions}")
        lines.append("")

    return "\n".join(lines)


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
        layer  = exp.get("knowledge_layer", "UNKNOWN")

        # 额外安全门：lifecycle 必须是 active
        if exp.get("lifecycle_status") != "active":
            logger.warning("[reflux] SKIP %s lifecycle=%s 非 active，跳过",
                           exp_id, exp.get("lifecycle_status"))
            result.skipped_already += 1
            continue

        if dry_run:
            logger.info("[reflux][dry-run] 模拟上传 %s [%s]", exp_id, layer)
            result.uploaded += 1
            result.uploaded_ids.append(exp_id)
            continue

        # 格式化
        title        = f"[XPEC] {layer} {exp_id}"
        content_text = format_exp_for_rag(exp)

        # 上传
        doc_id = ragflow_client.upload_exp(
            exp_id=exp_id,
            title=title,
            content_text=content_text,
        )
        if doc_id:
            klm_backend.mark_refluxed(exp_id, ragflow_doc_id=doc_id)
            result.uploaded += 1
            result.uploaded_ids.append(exp_id)
            logger.info("[reflux] OK exp_id=%s doc_id=%s", exp_id, doc_id)
        else:
            result.failed += 1
            result.failed_ids.append(exp_id)
            logger.error("[reflux] FAIL exp_id=%s 上传失败", exp_id)

    # 持久化 KLM
    if commit and not dry_run:
        klm_backend.commit()

    logger.info(
        "[reflux] 完成 candidates=%d uploaded=%d failed=%d skipped=%d",
        result.total_candidates, result.uploaded, result.failed, result.skipped_already,
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
