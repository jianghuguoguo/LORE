"""
Phase 4 — Bayesian Confidence Calibration (BCC)
================================================
基于贝叶斯独立证据公式，对 Phase 3 RME 的融合结果计算合并置信度，
并根据阈值决定成熟度（raw / validated / consolidated）。

核心公式：
  P_fused = 1 - ∏ᵢ (1 - Pᵢ × W(Eᵢ))

成熟度判定（基于三元组）：
  consolidated : P_fused ≥ 0.80  且 n_independent ≥ 3  且 contradiction ≤ 阈值
  validated    : P_fused ≥ 0.60  且 n_independent ≥ 2
  raw          : 其余

ConsolidatedExp schema 与 Layer 2 经验一致，可直接写回主库。
"""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import (
    BccResult,
    ConsolidatedExp,
    MergeResult,
    Provenance,
    WeightedEquivalenceSet,
    WeightedExperience,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 阈值常量
# ─────────────────────────────────────────────────────────────────────────────
_P_VALIDATED    = 0.60
_P_CONSOLIDATED = 0.80
_N_VALIDATED    = 2
_N_CONSOLIDATED = 3
_CONTRA_MAX     = 0.60
_CONTRA_MAX_META = 0.30  # METACOGNITIVE/CONCEPTUAL 层专用
_STRONG_COUNTEREX_W = 0.70


# ─────────────────────────────────────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────────────────────────────────────

def _count_independent_sessions(wes: WeightedEquivalenceSet) -> int:
    """统计等价集内的独立 session 数量。"""
    for we in wes.weighted_exps:
        ss = we.exp.get("metadata", {}).get("source_sessions", [])
        if ss and isinstance(ss, list):
            return len(ss)

    session_ids = set()
    for we in wes.weighted_exps:
        sid = we.exp.get("metadata", {}).get("source_session_id", "")
        if sid:
            session_ids.add(sid)
    return len(session_ids)


def _bcc_independent(weighted_exps: List[WeightedExperience]) -> float:
    """独立证据贝叶斯融合。"""
    if not weighted_exps:
        return 0.0
    log_prod = 0.0
    for we in weighted_exps:
        p_i = we.exp.get("confidence", 0.3)
        w_i = we.weight_effective if we.weight_effective > 0 else 0.01
        term = max(1.0 - p_i * w_i, 1e-9)
        log_prod += math.log(term)
    p_fused = 1.0 - math.exp(log_prod)
    return min(max(p_fused, 0.0), 1.0)


def _bcc_mixed(weighted_exps: List[WeightedExperience]) -> float:
    """混合相关性贝叶斯融合（同 session 内保守折叠，跨 session 独立融合）。"""
    if not weighted_exps:
        return 0.0

    session_groups: Dict[str, List[WeightedExperience]] = {}
    for we in weighted_exps:
        sid = we.exp.get("metadata", {}).get("source_session_id", "unknown")
        session_groups.setdefault(sid, []).append(we)

    session_p: List[float] = []
    session_w: List[float] = []
    for sid, group in session_groups.items():
        p_best = max(we.exp.get("confidence", 0.3) for we in group)
        w_best = max(we.weight_effective for we in group)
        session_p.append(min(p_best, 1.0))
        session_w.append(w_best)

    log_prod = sum(
        math.log(max(1.0 - p * w, 1e-9))
        for p, w in zip(session_p, session_w)
    )
    p_fused = 1.0 - math.exp(log_prod)
    return min(max(p_fused, 0.0), 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# 成熟度判定（基于三元组：P_fused, n_independent, contradiction）
# ─────────────────────────────────────────────────────────────────────────────

def _decide_maturity(
    p_fused: float,
    n_independent: int,
    contradiction_score: float,
    knowledge_layer: str = "",
    n_strong_counterex: int = 0,
) -> Tuple[str, str, bool]:
    """基于贝叶斯融合置信度与独立证据数判定成熟度。

    Returns:
        (new_maturity, reason, upgraded)
    """
    effective_contra_max = (
        _CONTRA_MAX_META
        if knowledge_layer in ("METACOGNITIVE", "CONCEPTUAL")
        else _CONTRA_MAX
    )

    # consolidated: P ≥ 0.80, n ≥ 3, 矛盾低
    if (
        p_fused >= _P_CONSOLIDATED
        and n_independent >= _N_CONSOLIDATED
        and contradiction_score <= effective_contra_max
    ):
        return (
            "consolidated",
            f"P={p_fused:.3f}≥{_P_CONSOLIDATED}, n_ind={n_independent}≥{_N_CONSOLIDATED}, contra={contradiction_score:.3f}≤{effective_contra_max}",
            True,
        )

    # validated: P ≥ 0.60, n ≥ 2
    if p_fused >= _P_VALIDATED and n_independent >= _N_VALIDATED:
        return (
            "validated",
            f"P={p_fused:.3f}≥{_P_VALIDATED}, n_ind={n_independent}≥{_N_VALIDATED}",
            True if p_fused >= _P_VALIDATED else False,
        )

    return ("raw", f"P={p_fused:.3f}, n_ind={n_independent} 不足升级条件", False)


# ─────────────────────────────────────────────────────────────────────────────
# 主入口：calibrate()（单 Pass）
# ─────────────────────────────────────────────────────────────────────────────

def calibrate(
    merge_result: MergeResult,
    wes: WeightedEquivalenceSet,
) -> BccResult:
    """对单个 MergeResult 执行贝叶斯置信度校准与成熟度判定。

    Args:
        merge_result : Phase 3 RME 的单个融合结果
        wes          : 对应的带权重等价集

    Returns:
        BccResult
    """
    weighted_exps = wes.weighted_exps
    n_independent = _count_independent_sessions(wes)
    n_total = len(weighted_exps)

    # 选择融合公式
    is_fully_independent = (n_independent == n_total)
    if is_fully_independent:
        p_fused = _bcc_independent(weighted_exps)
        formula_used = "independent_bayesian"
    else:
        p_fused = _bcc_mixed(weighted_exps)
        formula_used = "mixed_session_bayesian"

    p_fused = round(p_fused, 6)

    # 统计强反例
    dominant_exp = weighted_exps[0].exp if weighted_exps else {}
    dominant_outcome = dominant_exp.get("metadata", {}).get("session_outcome", "failure")
    n_strong_counterex = sum(
        1 for we in weighted_exps
        if we.exp.get("metadata", {}).get("session_outcome", "") != dominant_outcome
        and we.weight_effective > _STRONG_COUNTEREX_W
    )

    # 成熟度判定
    new_maturity, upgrade_reason, upgraded = _decide_maturity(
        p_fused=p_fused,
        n_independent=n_independent,
        contradiction_score=merge_result.contradiction_score,
        knowledge_layer=merge_result.knowledge_layer,
        n_strong_counterex=n_strong_counterex,
    )

    logger.info(
        "[BCC] %s: P_fused=%.4f %s n_ind=%d/%d cont=%.3f → %s%s",
        merge_result.cluster_id,
        p_fused, formula_used,
        n_independent, n_total,
        merge_result.contradiction_score,
        new_maturity,
        " ↑UPGRADE" if upgraded else "",
    )

    return BccResult(
        cluster_id=merge_result.cluster_id,
        p_fused=p_fused,
        n_independent=n_independent,
        n_total=n_total,
        old_maturity="raw",
        new_maturity=new_maturity,
        upgraded=upgraded,
        upgrade_reason=upgrade_reason,
        downgraded=False,
        new_confidence=round(p_fused, 4),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 组合：构建 ConsolidatedExp（schema 与 Layer 2 一致）
# ─────────────────────────────────────────────────────────────────────────────

def build_consolidated_exp(
    merge_result: MergeResult,
    bcc_result: BccResult,
    wes: WeightedEquivalenceSet,
) -> ConsolidatedExp:
    """将 MergeResult + BccResult 组合为最终可写回知识库的 ConsolidatedExp。"""
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    exp_id = _make_consolidated_exp_id(merge_result.cluster_id)

    def _dedupe(items: Iterable[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for item in items:
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    source_sessions_full = _dedupe(
        we.exp.get("metadata", {}).get("source_session_id", "")
        for we in wes.weighted_exps
    )
    source_event_ids: List[str] = []
    for we in wes.weighted_exps:
        source_event_ids.extend(
            we.exp.get("metadata", {}).get("source_event_ids", [])
        )
    source_event_ids = _dedupe(source_event_ids)
    source_exp_ids = _dedupe(we.exp_id for we in wes.weighted_exps)

    metadata = {
        "source_session_id": "consolidated",
        "source_sessions": source_sessions_full,
        "source_event_ids": source_event_ids,
        "source_exp_ids": source_exp_ids,
        "extraction_source": "xpec_rme_v1.2",
        "session_outcome": _infer_outcome(wes),
        "created_at": now_iso,
        "extractor_version": "layer3-1.0.0",
        "fusion_algorithm": "XPEC-RME-v1.2_BCC-v1.0",
        "fusion_timestamp": now_iso,
        "applicable_constraints": {
            "target_service": merge_result.target_service,
            "target_version": merge_result.version_family,
            "cve_ids": merge_result.cve_ids,
        },
        "tags": _build_tags(merge_result),
        "fusion_stats": {
            "p_fused": bcc_result.p_fused,
            "n_independent_sessions": bcc_result.n_independent,
            "contradiction_score": merge_result.contradiction_score,
        },
    }

    prov_dict = None
    try:
        prov_dict = asdict(merge_result.provenance)
    except Exception:
        pass

    return ConsolidatedExp(
        exp_id=exp_id,
        knowledge_layer=merge_result.knowledge_layer,
        content=merge_result.fused_content,
        metadata=metadata,
        maturity=bcc_result.new_maturity,
        confidence=bcc_result.new_confidence,
        p_fused=bcc_result.p_fused,
        n_independent_sessions=bcc_result.n_independent,
        contradiction_score=merge_result.contradiction_score,
        minority_opinions=merge_result.minority_opinions,
        provenance=prov_dict,
    )


def _make_consolidated_exp_id(cluster_id: str) -> str:
    h = hashlib.md5(cluster_id.encode()).hexdigest()[:10]
    return f"exp_consolidated_{h}"


def _infer_outcome(wes: WeightedEquivalenceSet) -> str:
    success_w, failure_w = 0.0, 0.0
    for we in wes.weighted_exps:
        outcome = we.exp.get("metadata", {}).get("session_outcome", "")
        if outcome == "success":
            success_w += we.weight_effective
        else:
            failure_w += we.weight_effective
    if success_w > failure_w:
        return "success"
    elif failure_w > success_w:
        return "failure"
    return "mixed"


def _build_tags(mr: MergeResult) -> List[str]:
    tags = [
        "consolidated",
        mr.knowledge_layer.lower(),
        f"n_src={mr.source_exp_count}",
    ]
    if mr.target_service:
        tags.append(mr.target_service.lower().replace(" ", "_")[:20])
    for cve in mr.cve_ids[:2]:
        tags.append(cve.lower())
    return tags


# ─────────────────────────────────────────────────────────────────────────────
# 批量处理：run_bcc()（单 Pass）
# ─────────────────────────────────────────────────────────────────────────────

def run_bcc(
    merge_results: List[MergeResult],
    wes_map: Dict[str, WeightedEquivalenceSet],
) -> Tuple[List[BccResult], List[ConsolidatedExp]]:
    """对所有 MergeResult 执行 BCC 校准并生成 ConsolidatedExp 列表。

    Args:
        merge_results : Phase 3 RME 的全部融合结果
        wes_map       : cluster_id → WeightedEquivalenceSet 映射

    Returns:
        (bcc_results, consolidated_exps)
    """
    bcc_results: List[BccResult] = []
    consolidated_exps: List[ConsolidatedExp] = []

    for mr in merge_results:
        wes = wes_map.get(mr.cluster_id)
        if wes is None:
            logger.warning("[BCC] 找不到对应 WES，跳过 %s", mr.cluster_id)
            continue

        bcc_r = calibrate(mr, wes)
        bcc_results.append(bcc_r)
        ce = build_consolidated_exp(mr, bcc_r, wes)
        consolidated_exps.append(ce)

    n_upgraded = sum(1 for r in bcc_results if r.upgraded)
    n_consol = sum(1 for r in bcc_results if r.new_maturity == "consolidated")
    n_validated = sum(1 for r in bcc_results if r.new_maturity == "validated")

    logger.info(
        "[BCC] 完成: %d 个等价集, 升级=%d, consolidated=%d, validated=%d",
        len(bcc_results), n_upgraded, n_consol, n_validated,
    )

    return bcc_results, consolidated_exps


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：摘要输出
# ─────────────────────────────────────────────────────────────────────────────

def summarize_bcc_results(
    bcc_results: List[BccResult],
    consolidated_exps: List[ConsolidatedExp],
) -> str:
    """返回可读的 BCC 结果摘要。"""
    lines = [
        "=" * 70,
        f"BCC 校准摘要  共 {len(bcc_results)} 个结果",
        "=" * 70,
    ]
    for bcc, ce in zip(bcc_results, consolidated_exps):
        upg_tag = ""
        if bcc.upgraded:
            upg_tag = f"  ↑{bcc.old_maturity}→{bcc.new_maturity}"
        lines.append(f"[{bcc.cluster_id[:50]}]")
        lines.append(
            f"  P_fused={bcc.p_fused:.4f}  "
            f"n_ind={bcc.n_independent}/{bcc.n_total}  "
            f"maturity={bcc.new_maturity}{upg_tag}"
        )
        lines.append(
            f"  conf={ce.confidence:.4f}  "
            f"contra={ce.contradiction_score:.3f}"
        )
        if bcc.upgraded and bcc.upgrade_reason:
            lines.append(f"  reason: {bcc.upgrade_reason}")
    lines.append("=" * 70)
    return "\n".join(lines)
