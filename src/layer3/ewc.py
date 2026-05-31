"""
Phase 2 — Evidence Weight Calculation (EWC)
===========================================
为每条经验计算权重 W(E)，作为 Phase 3 融合投票的依据。

权重模型（精简为单维）：
  W(E) = confidence ∈ [0, 1]

缺省置信度（无 confidence 字段时）：0.5

设计原则：
  - 权重由 Layer 2 提取阶段通过置信度计算策略（成功信号质量、会话结果等）确定
  - EWC 在此仅做透明传递，不做二次加工（不乘成熟度/outcome/coverage/衰减因子）
  - weight 与 weight_effective 相等（为保持下游 RME/BCC 接口兼容）
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .models import EquivalenceSet, WeightedExperience, WeightedEquivalenceSet

logger = logging.getLogger(__name__)

_DEFAULT_CONFIDENCE = 0.5


def _get_confidence(exp: Dict[str, Any]) -> float:
    """读取经验置信度，缺省返回 0.5。"""
    c = exp.get("confidence", None)
    if c is None:
        return _DEFAULT_CONFIDENCE
    return float(c)


def compute_weight_for_exp(exp: Dict[str, Any]) -> Dict[str, float]:
    """计算单条经验的权重。

    Returns:
        dict with keys: w_quality (即 confidence), weight, weight_effective
    """
    conf = _get_confidence(exp)
    conf_rounded = round(conf, 4)
    return {
        "w_quality": conf_rounded,
        "weight": conf_rounded,
        "weight_effective": conf_rounded,
    }


def compute_weights(
    experiences: List[Dict[str, Any]],
) -> List[WeightedExperience]:
    """对经验列表批量计算权重。

    Returns:
        WeightedExperience 列表，顺序与输入 experiences 一致
    """
    if not experiences:
        return []

    weighted = []
    for exp in experiences:
        factors = compute_weight_for_exp(exp)
        we = WeightedExperience(
            exp_id=exp.get("exp_id", ""),
            w_quality=factors["w_quality"],
            weight=factors["weight"],
            weight_effective=factors["weight_effective"],
            exp=exp,
        )
        weighted.append(we)

    return weighted


def weight_equivalence_sets(
    clusters: List[EquivalenceSet],
) -> List[WeightedEquivalenceSet]:
    """对 SEC 输出的等价集列表，为每个等价集内的经验计算权重。

    Returns:
        WeightedEquivalenceSet 列表，顺序与输入 clusters 相同
    """
    results = []
    for cluster in clusters:
        weighted_exps = compute_weights(cluster.experiences)
        # 按权重降序排列（dominant exp 在前）
        weighted_exps.sort(key=lambda x: x.weight_effective, reverse=True)
        wes = WeightedEquivalenceSet(
            cluster=cluster,
            weighted_exps=weighted_exps,
        )
        results.append(wes)
        logger.debug(
            "[EWC] %s: %d 条经验, 主导=%s, 总权重=%.3f",
            cluster.cluster_id,
            len(weighted_exps),
            wes.dominant_exp_id,
            wes.total_weight,
        )

    return results


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
                f"  (conf={we.w_quality:.3f})"
            )
    lines.append("=" * 60)
    return "\n".join(lines)
