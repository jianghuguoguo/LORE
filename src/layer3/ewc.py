"""
Phase 2 — Evidence Weight Calculation (EWC)
===========================================
为每条经验计算综合权重 W(E)，作为 Phase 3 融合投票的依据。

权重模型（四维向量）：
  w_quality  = confidence                              ∈ [0, 1]
  w_maturity = {raw:0.4, validated:0.7, consolidated:1.0}
  w_outcome  = {success:1.5, partial_success:1.0, failure:0.6}
  w_coverage = len(cve_ids) / MAX_CVE_PER_LAYER × 0.3 + 0.7  ∈ [0.7, 1.0]

最终权重：
  W_raw(E)       = w_quality × w_maturity × w_outcome × w_coverage
  W(E)           = normalize(W_raw) → [0.3, 1.0]
  W_effective(E) = W(E) × exp(-λ × Δt_days)

参考：实现流程文档 §6，分析文档 §3.1 EWC 因子表
"""

from __future__ import annotations

import math
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import EquivalenceSet, WeightedExperience, WeightedEquivalenceSet

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 常数：各维度因子映射
# ─────────────────────────────────────────────────────────────────────────────

# 成熟度因子（原文 §6.1 w_maturity）
_MATURITY_FACTOR: Dict[str, float] = {
    "raw":          0.4,
    "validated":    0.7,
    "consolidated": 1.0,
}
_MATURITY_FACTOR_DEFAULT = 0.4  # 未知成熟度保守取 raw

# 结果因子（原文 §6.1 w_outcome）
_OUTCOME_FACTOR: Dict[str, float] = {
    "success":         1.5,
    "partial_success": 1.0,
    "partial":         1.0,   # 兼容 Layer2 中 "partial" 写法
    "failure":         0.6,
    "unknown":         0.8,   # 无法判断时取中间值
}
_OUTCOME_FACTOR_DEFAULT = 0.8

# 时效性衰减率 λ（每天，对应半衰期）
# 来自分析文档 §3.2   λ_knowledge_layer
_DECAY_LAMBDA: Dict[str, float] = {
    # PROCEDURAL_NEG DEF/PATCHED 类（CVE 利用路径，~140天半衰期）
    "PROCEDURAL_NEG":   0.005,
    # PROCEDURAL_POS（实际成功路径，与 NEG 类似稳定性）
    "PROCEDURAL_POS":   0.005,
    # FACTUAL（版本/服务信息，~230天半衰期）
    "FACTUAL":          0.003,
    # METACOGNITIVE（决策规则，极稳定，~700天半衰期）
    "METACOGNITIVE":    0.001,
    # CONCEPTUAL（抽象规律，极稳定）
    "CONCEPTUAL":       0.001,
}
_DECAY_LAMBDA_DEFAULT = 0.005

# 对于 PROCEDURAL_NEG 的特殊工具类失败（ENV 类工具更新快）
_DECAY_LAMBDA_ENV = 0.010  # ~70天半衰期

# CVE 覆盖度：每层中合理的最大 CVE 数（用于归一化）
_MAX_CVE_PER_LAYER = 5  # 超过5个CVE时 w_coverage 上限 = 1.0

# 归一化输出范围
# BUG-3 修复：_W_MIN 从 0.1 改为 0.3，压缩极值放大效应
# 放大系数从 9× (0.9/0.1) 降为 2.3× (0.7/0.3)，更接近原始 w_raw 的差距比例
_W_MIN = 0.3
_W_MAX = 1.0


# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _get_confidence(exp: Dict[str, Any]) -> float:
    """读取经验置信度，缺省返回 0.5。"""
    c = exp.get("confidence", None)
    if c is None:
        return 0.5
    return float(c)


def _get_maturity_factor(exp: Dict[str, Any]) -> float:
    """读取成熟度因子。"""
    maturity = exp.get("maturity", "raw")
    return _MATURITY_FACTOR.get(str(maturity).lower(), _MATURITY_FACTOR_DEFAULT)


def _get_outcome_factor(exp: Dict[str, Any]) -> float:
    """读取会话结果因子。结果来自 metadata.session_outcome。"""
    outcome = exp.get("metadata", {}).get("session_outcome", "unknown")
    return _OUTCOME_FACTOR.get(str(outcome).lower(), _OUTCOME_FACTOR_DEFAULT)


def _get_cve_coverage(exp: Dict[str, Any]) -> float:
    """计算 CVE 覆盖度加成 w_coverage = n/MAX × 0.3 + 0.7。"""
    meta = exp.get("metadata", {}).get("applicable_constraints", {})
    cves = meta.get("cve_ids", [])
    if not cves:
        # 从 content 兜底
        content = exp.get("content", {})
        cves = content.get("cve_ids", [])
        if not cves:
            ctx = content.get("cve_context", {})
            cves = ctx.get("attempted", [])
    n = min(len(cves), _MAX_CVE_PER_LAYER)
    return (n / _MAX_CVE_PER_LAYER) * 0.3 + 0.7


def _get_decay_lambda(exp: Dict[str, Any]) -> float:
    """获取时效性衰减率 λ。

    特殊情况：PROCEDURAL_NEG 中 failure_dimension=ENV（工具依赖失败）
    的衰减rate 更高（工具更新较快）。
    """
    layer = exp.get("knowledge_layer", "")
    lam = _DECAY_LAMBDA.get(layer, _DECAY_LAMBDA_DEFAULT)
    if layer == "PROCEDURAL_NEG":
        dim = exp.get("content", {}).get("failure_dimension", "")
        if dim == "ENV":
            lam = _DECAY_LAMBDA_ENV
    return lam


def _calc_decay_factor(exp: Dict[str, Any], now: datetime) -> float:
    """计算时效性衰减因子 exp(-λ × Δt_days)。

    Δt 从 metadata.created_at 计算到 now；
    若 created_at 缺失或解析失败，衰减因子默认为 1.0（不衰减）。
    """
    created_str = exp.get("metadata", {}).get("created_at", "")
    if not created_str:
        return 1.0
    try:
        created = datetime.fromisoformat(created_str)
        # 处理无时区的 naive datetime
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now_tz = now.replace(tzinfo=timezone.utc)
        else:
            now_tz = now
        delta_days = (now_tz - created).total_seconds() / 86400.0
        lam = _get_decay_lambda(exp)
        return math.exp(-lam * delta_days)
    except (ValueError, TypeError) as e:
        logger.warning(f"EWC: 时效性衰减计算失败 ({created_str}): {e}")
        return 1.0


def _normalize(raw: float, global_min: float, global_max: float) -> float:
    """将 raw 值归一化到 [W_MIN, W_MAX]。

    使用 Min-Max 缩放；若所有经验权重相同，则返回 0.5（中间值）。
    """
    if global_max <= global_min:
        return (_W_MIN + _W_MAX) / 2
    ratio = (raw - global_min) / (global_max - global_min)
    return _W_MIN + ratio * (_W_MAX - _W_MIN)


# ─────────────────────────────────────────────────────────────────────────────
# 单条经验权重计算
# ─────────────────────────────────────────────────────────────────────────────

def compute_weight_for_exp(
    exp: Dict[str, Any],
    now: Optional[datetime] = None,
) -> Dict[str, float]:
    """计算单条经验的各维度因子（归一化前的原始值）。

    Returns:
        dict with keys: w_quality, w_maturity, w_outcome, w_coverage,
                        w_decay, w_raw (乘积，未归一化)
    """
    if now is None:
        now = datetime.now(tz=timezone.utc)

    w_quality  = _get_confidence(exp)
    w_maturity = _get_maturity_factor(exp)
    w_outcome  = _get_outcome_factor(exp)
    w_coverage = _get_cve_coverage(exp)
    w_decay    = _calc_decay_factor(exp, now)

    # 保留最低影响
    w_raw = max(w_quality * w_maturity * w_outcome * w_coverage, 0.001)

    # BUG-4 修复：slot_in_turn 微量扰动，打破同 session 内多条经验的等权僵局
    # 同 session 的经验共享相同的 bar/conf/maturity/outcome，导致 w_raw 完全相等。
    # 越靠后的 turn（slot 越大）通常包含更完善的成功/失败路径，给予微量加成。
    # 最大偏移量：30 turns × 0.0001 = 0.003，不改变跨 session 的大小关系。
    slot_indices = exp.get("metadata", {}).get("source_turn_indices", [])
    max_slot = max(slot_indices) if slot_indices else 0
    w_raw += max_slot * 0.0001

    return {
        "w_quality":  round(w_quality,  4),
        "w_maturity": round(w_maturity, 4),
        "w_outcome":  round(w_outcome,  4),
        "w_coverage": round(w_coverage, 4),
        "w_decay":    round(w_decay,    4),
        "w_raw":      round(w_raw,      6),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 批量计算：对经验列表计算归一化权重
# ─────────────────────────────────────────────────────────────────────────────

def compute_weights(
    experiences: List[Dict[str, Any]],
    now: Optional[datetime] = None,
) -> List[WeightedExperience]:
    """对经验列表批量计算归一化权重。

    归一化策略：在列表内全局 Min-Max，使权重有相对比较意义。
    若列表只有一条经验，该经验权重为 0.6（中性偏上，避免影响 BCC）。

    Returns:
        WeightedExperience 列表，顺序与输入 experiences 一致
    """
    if not experiences:
        return []

    if now is None:
        now = datetime.now(tz=timezone.utc)

    # 第一遍：计算所有原始值
    raw_results = []
    for exp in experiences:
        factors = compute_weight_for_exp(exp, now)
        raw_results.append((exp, factors))

    # 全局 min/max（用于归一化）
    raw_vals = [r["w_raw"] for _, r in raw_results]
    g_min = min(raw_vals)
    g_max = max(raw_vals)

    # 第二遍：归一化 + 应用时效性衰减
    weighted = []
    for exp, factors in raw_results:
        w_normalized = _normalize(factors["w_raw"], g_min, g_max)
        w_effective  = round(w_normalized * factors["w_decay"], 4)
        # 确保 w_effective 不低于 W_MIN
        w_effective  = max(w_effective, _W_MIN)

        we = WeightedExperience(
            exp_id=exp.get("exp_id", ""),
            w_quality=factors["w_quality"],
            w_maturity=factors["w_maturity"],
            w_outcome=factors["w_outcome"],
            w_coverage=factors["w_coverage"],
            w_decay=factors["w_decay"],
            weight=round(w_normalized, 4),
            weight_effective=w_effective,
            exp=exp,
        )
        weighted.append(we)

    return weighted


# ─────────────────────────────────────────────────────────────────────────────
# 组合 Phase 1 + Phase 2：对等价集列表计算权重
# ─────────────────────────────────────────────────────────────────────────────

def weight_equivalence_sets(
    clusters: List[EquivalenceSet],
    now: Optional[datetime] = None,
) -> List[WeightedEquivalenceSet]:
    """对 SEC 输出的等价集列表，为每个等价集内的经验计算归一化权重。

    注意：归一化在【每个等价集内部】进行，而不是跨等价集全局归一化。
    这确保同一融合组内的相对权重有意义（决定多数投票的比例）。

    Returns:
        WeightedEquivalenceSet 列表，顺序与输入 clusters 相同
    """
    if now is None:
        now = datetime.now(tz=timezone.utc)

    results = []
    for cluster in clusters:
        weighted_exps = compute_weights(cluster.experiences, now)
        # 按权重降序排列（dominant exp 在前）
        weighted_exps.sort(key=lambda x: x.weight_effective, reverse=True)
        wes = WeightedEquivalenceSet(
            cluster=cluster,
            weighted_exps=weighted_exps,
        )
        results.append(wes)
        logger.debug(
            f"EWC [{cluster.cluster_id}]: "
            f"{len(weighted_exps)} 条经验，"
            f"主导={wes.dominant_exp_id}  总权重={wes.total_weight:.3f}"
        )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：打印权重摘要
# ─────────────────────────────────────────────────────────────────────────────

def summarize_weights(wes_list: List[WeightedEquivalenceSet]) -> str:
    """返回可读的权重摘要字符串（用于日志/调试输出）。"""
    lines = [
        f"{'=' * 60}",
        f"EWC 权重摘要  共 {len(wes_list)} 个等价集",
        f"{'=' * 60}",
    ]
    for wes in wes_list:
        c = wes.cluster
        lines.append(
            f"[{c.cluster_id}]  经验数={len(wes.weighted_exps)}"
            f"  满足融合={c.meets_fusion_threshold}"
        )
        for we in wes.weighted_exps:
            dom = "★" if we.exp_id == wes.dominant_exp_id else " "
            lines.append(
                f"  {dom} {we.exp_id:<35}"
                f"  W={we.weight:.3f}  W_eff={we.weight_effective:.3f}"
                f"  (q={we.w_quality:.2f} m={we.w_maturity:.1f}"
                f" o={we.w_outcome:.1f} cov={we.w_coverage:.2f}"
                f" decay={we.w_decay:.3f})"
            )
    lines.append("=" * 60)
    return "\n".join(lines)
