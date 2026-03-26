"""
Phase 4 — Bayesian Confidence Calibration (BCC)
================================================
基于贝叶斯独立证据公式，对 Phase 3 RME 的融合结果计算合并置信度，
并根据阈值决定成熟度升级（raw→validated→consolidated）。

核心公式（§8.1 独立证据融合）：
  P_fused = 1 - ∏ᵢ (1 - Pᵢ × W(Eᵢ))

  其中：
    Pᵢ  = 第 i 条经验的置信度（experience.confidence）
    W(Eᵢ) = 第 i 条经验的 weight_effective（来自 Phase 2 EWC）

相关经验保守公式（来自同一 session 的经验视为相关）：
  P_correlated = P_base + Σᵢ (Pᵢ - P_base) × W(Eᵢ) × (1 - ρᵢ)
  ρ = 1 表示完全相关（同靶机重复测试），ρ = 0 表示完全独立

成熟度升级规则（§8.2）：
  raw      → validated   : P_fused ≥ 0.60  且 n_independent ≥ 2
  validated→ consolidated: P_fused ≥ 0.80  且 n_independent ≥ 3  且无严重矛盾
  consolidated → 降级     : 出现 ≥2 条 weight>0.7 的强反例

ConsolidatedExp 输出（§9 KLM 前置）：
  写入 data/layer3_output/phase34_consolidated.jsonl
  标记 lifecycle_status="active"，merged_into=null，refluxed=False
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
    EquivalenceSet,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 阈值常量（§8.2）
# ─────────────────────────────────────────────────────────────────────────────
_P_VALIDATED    = 0.60   # raw → validated 最低置信度
_P_CONSOLIDATED = 0.80   # validated → consolidated 最低置信度
_N_VALIDATED    = 2      # raw → validated 最少独立 session 数
_N_CONSOLIDATED = 3      # validated → consolidated 最少独立 session 数
_CONTRA_MAX     = 0.60   # 超过此矛盾评分则阻止 consolidated 升级（通用层）
# 问题⑤修复：全局决策规则层（METACOGNITIVE/CONCEPTUAL）使用更严格的矛盾阈值，
# 因为这两层经验一旦携带矛盾回流将影响所有任务场景的 Agent 行为
_CONTRA_MAX_META = 0.30  # METACOGNITIVE/CONCEPTUAL 层专用阈值
_STRONG_COUNTEREX_W = 0.70  # 强反例的权重阈值（§8.2 降级条件）


# ─────────────────────────────────────────────────────────────────────────────
# 相关系数估算：来自同一 session 的经验视为强相关
# ─────────────────────────────────────────────────────────────────────────────

def _estimate_correlation(
    exp_a: Dict[str, Any],
    exp_b: Dict[str, Any],
) -> float:
    """估算两条经验的相关系数 ρ ∈ [0, 1]。

    规则：
      - 同一 source_session_id → ρ = 0.8（高度相关，同靶机同轮次）
      - 不同 session           → ρ = 0.0（视为独立证据）
    """
    sid_a = exp_a.get("metadata", {}).get("source_session_id", "")
    sid_b = exp_b.get("metadata", {}).get("source_session_id", "")
    if sid_a and sid_b and sid_a == sid_b:
        return 0.8
    return 0.0


def _count_independent_sessions(wes: WeightedEquivalenceSet) -> int:
    """统计等价集内的独立 session 数量（优先使用 metadata.source_sessions 聚合字段）。"""
    # 优先读取 SEC 注入的 source_sessions 字段
    for we in wes.weighted_exps:
        ss = we.exp.get("metadata", {}).get("source_sessions", [])
        if ss and isinstance(ss, list):
            return len(ss)

    # 兜底：从各经验的 source_session_id 动态生成
    session_ids = set()
    for we in wes.weighted_exps:
        sid = we.exp.get("metadata", {}).get("source_session_id", "")
        if sid:
            session_ids.add(sid)
    return len(session_ids)


# ─────────────────────────────────────────────────────────────────────────────
# 核心 BCC 计算
# ─────────────────────────────────────────────────────────────────────────────

def _bcc_independent(
    weighted_exps: List[WeightedExperience],
) -> float:
    """独立证据贝叶斯融合：P_fused = 1 - ∏ᵢ (1 - Pᵢ × W(Eᵢ))。

    理论基础：每条经验独立支持同一假设 K，
    其"未支持概率"为 (1 - Pᵢ × W(Eᵢ))，
    所有经验均不支持的联合概率为乘积，取补得融合置信度。

    数值稳定性：取对数计算避免极小浮点数下溢。
    """
    if not weighted_exps:
        return 0.0

    log_prod = 0.0
    for we in weighted_exps:
        p_i = we.exp.get("confidence", 0.3)
        w_i = we.weight_effective if we.weight_effective > 0 else 0.01
        # 1 - Pᵢ × W(Eᵢ)，限制在 [ε, 1] 避免 log(0)
        term = max(1.0 - p_i * w_i, 1e-9)
        log_prod += math.log(term)

    p_fused = 1.0 - math.exp(log_prod)
    return min(max(p_fused, 0.0), 1.0)


def _bcc_mixed(
    weighted_exps: List[WeightedExperience],
) -> float:
    """混合相关性贝叶斯融合。

    按 session 分组：
    1. 对每个 session 内部用相关公式合并（保守估计）
    2. 对各 session 间用独立公式融合（视为独立证据）

    这样既避免同 session 多条经验虚增置信度，
    又正确利用跨 session 的独立验证价值。
    """
    if not weighted_exps:
        return 0.0

    # 按 session 分组
    session_groups: Dict[str, List[WeightedExperience]] = {}
    for we in weighted_exps:
        sid = we.exp.get("metadata", {}).get("source_session_id", "unknown")
        session_groups.setdefault(sid, []).append(we)

    # 每个 session 内部：保守折叠——取置信度最高的经验作为 session 代表
    # 问题①修复：session_p 仅存储纯置信度（不预乘权重），避免权重在
    # session 内折叠时和跨 session 贝叶斯融合时被双重计入。
    session_p: List[float] = []
    session_w: List[float] = []
    for sid, group in session_groups.items():
        # 取该 session 最高置信度经验的纯置信度 + 最大有效权重
        p_best = max(we.exp.get("confidence", 0.3) for we in group)
        w_best = max(we.weight_effective for we in group)
        session_p.append(min(p_best, 1.0))
        session_w.append(w_best)

    # 跨 session：独立证据贝叶斯融合（权重只在此处乘入一次）
    log_prod = sum(
        math.log(max(1.0 - p * w, 1e-9))
        for p, w in zip(session_p, session_w)
    )
    p_fused = 1.0 - math.exp(log_prod)
    return min(max(p_fused, 0.0), 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# 成熟度升级决策
# ─────────────────────────────────────────────────────────────────────────────

def _decide_maturity(
    p_fused: float,
    n_independent: int,
    contradiction_score: float,
    dominant_maturity: str,
    n_strong_counterex: int,
    knowledge_layer: str = "",
) -> Tuple[str, str, bool, bool]:
    """根据 BCC 结果决定新的成熟度等级（严格阶梯升级）。

    Args:
        p_fused              : 贝叶斯融合置信度
        n_independent        : 独立 session 数
        contradiction_score  : 矛盾评分（来自 RME）
        dominant_maturity    : 主导经验的当前成熟度
        n_strong_counterex   : 强反例数量（weight > 0.7 的反向经验）
        knowledge_layer      : 经验知识层（影响矛盾阈值，问题⑤修复）

    Returns:
        (new_maturity, upgrade_reason, upgraded, downgraded)

    升级路径（问题②修复：严格阶梯，禁止跳级）：
        raw → validated   （满足 P_VALIDATED + N_VALIDATED）
        validated → consolidated  （满足 P_CONSOLIDATED + N_CONSOLIDATED + 矛盾阈值）
    """
    # 问题⑤：METACOGNITIVE/CONCEPTUAL 层使用更严格的矛盾阈值
    effective_contra_max = (
        _CONTRA_MAX_META
        if knowledge_layer in ("METACOGNITIVE", "CONCEPTUAL")
        else _CONTRA_MAX
    )

    # 问题 4 修正：对于具备 3 个独立 session 证据的样本，
    # 允许 p_fused ≥ 0.75 即可进入 consolidated，
    # 以容忍 EWC 权重归一化带来的累积数值偏差。
    threshold_consolidated = _P_CONSOLIDATED
    if n_independent >= 3:
        threshold_consolidated = 0.75

    # ── 降级检查（优先，有强反例则先降级）──────────────────────────────
    if dominant_maturity == "consolidated" and n_strong_counterex >= 2:
        return (
            "validated",
            f"存在 {n_strong_counterex} 条强反例（weight>{_STRONG_COUNTEREX_W}），consolidated降级",
            False, True,
        )

    # ── 阶梯升级（问题②修复：raw 只能升到 validated，不得跳级）────────
    if dominant_maturity == "raw":
        if p_fused >= _P_VALIDATED and n_independent >= _N_VALIDATED:
            reason = (
                f"P_fused={p_fused:.3f}≥{_P_VALIDATED}, "
                f"n_independent={n_independent}≥{_N_VALIDATED}"
            )
            return "validated", reason, True, False
        return (
            dominant_maturity,
            f"raw经验：P_fused={p_fused:.3f} 或 n_ind={n_independent} 不足raw→validated条件",
            False, False,
        )

    if dominant_maturity == "validated":
        if (p_fused >= threshold_consolidated
                and n_independent >= _N_CONSOLIDATED
                and contradiction_score <= effective_contra_max):
            reason = (
                f"P_fused={p_fused:.3f}≥{threshold_consolidated}, "
                f"n_independent={n_independent}≥{_N_CONSOLIDATED}, "
                f"contra={contradiction_score:.3f}≤{effective_contra_max}"
                + (f"（{knowledge_layer}层专用阈值）"
                   if effective_contra_max == _CONTRA_MAX_META else "")
            )
            return "consolidated", reason, True, False
        return (
            dominant_maturity,
            f"validated经验：未达consolidated条件（P={p_fused:.3f}, n_ind={n_independent}, contra={contradiction_score:.3f})",
            False, False,
        )

    # consolidated 或其他：无变化
    return dominant_maturity, "成熟度无需调整", False, False


# ─────────────────────────────────────────────────────────────────────────────
# 主入口：calibrate()
# ─────────────────────────────────────────────────────────────────────────────

def calibrate(
    merge_result: MergeResult,
    wes: WeightedEquivalenceSet,
    force_dominant_maturity: Optional[str] = None,
) -> BccResult:
    """对单个 MergeResult 执行贝叶斯置信度校准。

    Args:
        merge_result              : Phase 3 RME 的单个融合结果
        wes                       : 对应的带权重等价集
        force_dominant_maturity   : 若不为 None，强制覆盖 dominant_maturity
                                    （用于双 Pass 中模拟 reflux 后的备选成熟度）

    Returns:
        BccResult，含新置信度、新成熟度、是否升级等信息
    """
    weighted_exps = wes.weighted_exps
    n_independent = _count_independent_sessions(wes)

    # 判断是否所有经验来自不同 session（完全独立）
    n_total = len(weighted_exps)
    is_fully_independent = (n_independent == n_total)

    # 选择融合公式
    if is_fully_independent:
        p_fused = _bcc_independent(weighted_exps)
        formula_used = "independent_bayesian"
    else:
        p_fused = _bcc_mixed(weighted_exps)
        formula_used = "mixed_session_bayesian"

    p_fused = round(p_fused, 6)

    # 获取主导经验的成熟度和置信度
    dominant_exp = None
    for we in weighted_exps:
        if we.exp_id == wes.dominant_exp_id:
            dominant_exp = we.exp
            break
    if dominant_exp is None and weighted_exps:
        dominant_exp = weighted_exps[0].exp

    dominant_maturity = (dominant_exp or {}).get("maturity", "raw")
    # 双 Pass 支持：允许外部覆盖 dominant_maturity
    if force_dominant_maturity is not None:
        dominant_maturity = force_dominant_maturity

    # 统计强反例（成功 session 中 weight > 阈值的经验——与失败主导集矛盾）
    dominant_outcome = (dominant_exp or {}).get("metadata", {}).get("session_outcome", "failure")
    n_strong_counterex = 0
    for we in weighted_exps:
        outcome = we.exp.get("metadata", {}).get("session_outcome", "")
        if outcome != dominant_outcome and we.weight_effective > _STRONG_COUNTEREX_W:
            n_strong_counterex += 1

    # 决定新成熟度（传入 knowledge_layer 以启用层级专用矛盾阈值）
    new_maturity, upgrade_reason, upgraded, downgraded = _decide_maturity(
        p_fused             = p_fused,
        n_independent       = n_independent,
        contradiction_score = merge_result.contradiction_score,
        dominant_maturity   = dominant_maturity,
        n_strong_counterex  = n_strong_counterex,
        knowledge_layer     = merge_result.knowledge_layer,
    )

    # lifecycle_status：矛盾超通用阈值（或META/CONCEPTUAL层专用阈值）时标记 conflicted
    effective_contra_max = (
        _CONTRA_MAX_META
        if merge_result.knowledge_layer in ("METACOGNITIVE", "CONCEPTUAL")
        else _CONTRA_MAX
    )
    if merge_result.contradiction_score > effective_contra_max and new_maturity != "consolidated":
        lifecycle_status = "conflicted"
    else:
        lifecycle_status = "active"

    # 问题③修复：should_reflux 在 lifecycle_status 确定后统一判定，
    # 确保 conflicted 经验即使达到 consolidated 也不自动回流生产库
    should_reflux = (new_maturity == "consolidated" and lifecycle_status == "active")

    logger.info(
        f"BCC [{merge_result.cluster_id}]: "
        f"P_fused={p_fused:.4f}  formula={formula_used}  "
        f"n_ind={n_independent}/{n_total}  "
        f"{dominant_maturity}→{new_maturity}  "
        f"{'↑UPGRADE' if upgraded else '↓DOWNGRADE' if downgraded else 'stable'}  "
        f"lifecycle={lifecycle_status}  reflux={should_reflux}"
    )

    return BccResult(
        cluster_id      = merge_result.cluster_id,
        p_fused         = p_fused,
        n_independent   = n_independent,
        n_total         = n_total,
        old_maturity    = dominant_maturity,
        new_maturity    = new_maturity,
        upgraded        = upgraded,
        upgrade_reason  = upgrade_reason,
        downgraded      = downgraded,
        should_reflux   = should_reflux,
        lifecycle_status= lifecycle_status,
        new_confidence  = round(p_fused, 4),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 组合：构建 ConsolidatedExp
# ─────────────────────────────────────────────────────────────────────────────

def build_consolidated_exp(
    merge_result: MergeResult,
    bcc_result: BccResult,
    wes: WeightedEquivalenceSet,
) -> ConsolidatedExp:
    """将 MergeResult + BccResult 组合为最终可写回知识库的 ConsolidatedExp。

    metadata 字段与 Layer2 JSONL 格式保持兼容（可直接追加写入 experience_raw.jsonl）。
    exp_id 格式：exp_consolidated_{cluster_hash}
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    exp_id  = _make_consolidated_exp_id(merge_result.cluster_id)

    def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for item in items:
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    # 收集所有源 session IDs（完整版）
    source_sessions_full = _dedupe_preserve_order(
        we.exp.get("metadata", {}).get("source_session_id", "")
        for we in wes.weighted_exps
    )

    # 收集所有源 event IDs（汇总）
    source_event_ids: List[str] = []
    for we in wes.weighted_exps:
        source_event_ids.extend(
            we.exp.get("metadata", {}).get("source_event_ids", [])
        )
    source_event_ids = _dedupe_preserve_order(source_event_ids)

    source_exp_ids = _dedupe_preserve_order(we.exp_id for we in wes.weighted_exps)

    metadata = {
        "source_session_id":    "consolidated",
        "source_sessions":      source_sessions_full,
        "source_event_ids":     source_event_ids,
        "source_exp_ids":       source_exp_ids,
        "extraction_source":    "xpec_rme_v1.2",
        "session_outcome":      _infer_outcome(wes),
        "created_at":           now_iso,
        "extractor_version":    "layer3-1.0.0",
        "fusion_algorithm":     "XPEC-RME-v1.2_BCC-v1.0",
        "fusion_timestamp":     now_iso,
        "applicable_constraints": {
            "target_service":   merge_result.target_service,
            "target_version":   merge_result.version_family,
            "cve_ids":          merge_result.cve_ids,
        },
        "tags": _build_tags(merge_result),
    }

    prov_dict = None
    try:
        prov_dict = asdict(merge_result.provenance)
    except Exception:
        pass

    return ConsolidatedExp(
        exp_id                  = exp_id,
        knowledge_layer         = merge_result.knowledge_layer,
        content                 = merge_result.fused_content,
        metadata                = metadata,
        maturity                = bcc_result.new_maturity,
        confidence              = bcc_result.new_confidence,
        p_fused                 = bcc_result.p_fused,
        n_independent_sessions  = bcc_result.n_independent,
        contradiction_score     = merge_result.contradiction_score,
        minority_opinions       = merge_result.minority_opinions,
        lifecycle_status        = bcc_result.lifecycle_status,
        merged_into             = None,
        refluxed                = False,
        provenance              = prov_dict,
    )


def _make_consolidated_exp_id(cluster_id: str) -> str:
    h = hashlib.md5(cluster_id.encode()).hexdigest()[:10]
    return f"exp_consolidated_{h}"


def _infer_outcome(wes: WeightedEquivalenceSet) -> str:
    """推断融合经验的会话结果：多数权重决定。"""
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
    """为 consolidated experience 构建标签。"""
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
# 批量处理：run_bcc()
# ─────────────────────────────────────────────────────────────────────────────

def run_bcc(
    merge_results: List[MergeResult],
    wes_map: Dict[str, WeightedEquivalenceSet],
) -> Tuple[List[BccResult], List[ConsolidatedExp]]:
    """对所有 MergeResult 执行 BCC 校准并生成 ConsolidatedExp 列表。

    实现「单轮双 Pass」架构解决成熟度死锁问题：
      Pass 1：所有源经验均为 raw → BCC 判断→ 可能输出 validated
      Pass 2：将 Pass1 中达到 validated 的结果临时修改 dominant_maturity，
             再次判断是否满足 validated→consolidated 条件。
      最终以 Pass2 结果为准。

    注：这是在单次流水线运行中模拟 "Layer5 reflux" 的效果，
    防止因源经验层永远为 raw 而导致 consolidated 永远不可达。

    Args:
        merge_results : Phase 3 RME 的全部融合结果
        wes_map       : cluster_id → WeightedEquivalenceSet 映射（用于取权重数据）

    Returns:
        (bcc_results, consolidated_exps)
        bcc_results        — 每个 MergeResult 的 BccResult
        consolidated_exps  — 可写回知识库的 ConsolidatedExp 列表
    """
    bcc_results: List[BccResult]            = []
    consolidated_exps: List[ConsolidatedExp] = []

    for mr in merge_results:
        wes = wes_map.get(mr.cluster_id)
        if wes is None:
            logger.warning(f"BCC: 找不到对应 WES，跳过 {mr.cluster_id}")
            continue

        # ── Pass 1：以真实 dominant_maturity 运行一次校准 ────────────────
        bcc_r1 = calibrate(mr, wes)

        # ── Pass 2：若 Pass1 得到 validated，在同一 run 内模拟 reflux，
        #        将 dominant_maturity 修改为 validated 后再判断一次 ──────
        if bcc_r1.new_maturity == "validated" and bcc_r1.lifecycle_status == "active":
            bcc_r2 = calibrate(mr, wes, force_dominant_maturity="validated")
            # 只有 Pass2 真实升级到 consolidated 时才替换
            if bcc_r2.new_maturity == "consolidated":
                logger.info(
                    f"BCC [Pass2升级] {mr.cluster_id}: "
                    f"validated→consolidated  P_fused={bcc_r2.p_fused:.4f}"
                )
                bcc_r = bcc_r2
            else:
                bcc_r = bcc_r1
        else:
            bcc_r = bcc_r1

        bcc_results.append(bcc_r)
        ce = build_consolidated_exp(mr, bcc_r, wes)
        consolidated_exps.append(ce)

    # 统计
    n_upgraded   = sum(1 for r in bcc_results if r.upgraded)
    n_downgraded = sum(1 for r in bcc_results if r.downgraded)
    n_consol     = sum(1 for r in bcc_results if r.new_maturity == "consolidated")
    n_validated  = sum(1 for r in bcc_results if r.new_maturity == "validated")
    n_reflux     = sum(1 for r in bcc_results if r.should_reflux)

    logger.info(
        f"BCC 完成: {len(bcc_results)} 个等价集  "
        f"升级={n_upgraded}  降级={n_downgraded}  "
        f"consolidated={n_consol}  validated={n_validated}  "
        f"待回流={n_reflux}"
    )

    return bcc_results, consolidated_exps


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：摘要输出
# ─────────────────────────────────────────────────────────────────────────────

def summarize_bcc_results(
    bcc_results: List[BccResult],
    consolidated_exps: List[ConsolidatedExp],
) -> str:
    """返回可读的 BCC 结果摘要（用于调试/日志）。"""
    lines = [
        "=" * 70,
        f"BCC 校准摘要  共 {len(bcc_results)} 个结果",
        "=" * 70,
    ]
    for bcc, ce in zip(bcc_results, consolidated_exps):
        upg_tag = ""
        if bcc.upgraded:
            upg_tag = f"  ↑{bcc.old_maturity}→{bcc.new_maturity}"
        elif bcc.downgraded:
            upg_tag = f"  ↓{bcc.old_maturity}→{bcc.new_maturity}"
        reflux_tag = "  [待回流]" if bcc.should_reflux else ""
        lines.append(
            f"[{bcc.cluster_id[:50]}]"
        )
        lines.append(
            f"  P_fused={bcc.p_fused:.4f}  "
            f"n_ind={bcc.n_independent}/{bcc.n_total}  "
            f"maturity={bcc.new_maturity}{upg_tag}{reflux_tag}"
        )
        lines.append(
            f"  conf={ce.confidence:.4f}  "
            f"contra={ce.contradiction_score:.3f}  "
            f"lifecycle={ce.lifecycle_status}"
        )
        if bcc.upgrade_reason and (bcc.upgraded or bcc.downgraded):
            lines.append(f"  reason: {bcc.upgrade_reason}")
    lines.append("=" * 70)
    return "\n".join(lines)
