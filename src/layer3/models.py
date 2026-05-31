"""
LORE Layer 3 数据模型
===========================
定义 XPEC 融合框架各阶段的输入/输出数据结构。

设计原则：
- 非破坏性：所有原始经验通过 exp_id 可溯源，Consolidated 经验携带 provenance
- 可序列化：所有 dataclass 可直接转为 JSON（通过 dataclasses.asdict）
- 与 Layer2 schema 兼容：直接操作 Layer2 JSONL 中的 dict 对象，不做多余转换
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 枚举：成熟度级别（与 Layer2 schema 一致）
# ─────────────────────────────────────────────────────────────────────────────

class Maturity(str, Enum):
    RAW          = "raw"
    VALIDATED    = "validated"
    CONSOLIDATED = "consolidated"


def _fusion_threshold_for_layer(knowledge_layer: str) -> int:
    """返回指定知识层触发 RME 融合所需的最小经验数。"""
    layer = str(knowledge_layer).upper()
    if layer == "CONCEPTUAL":
        return 2
    return 3


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — SEC 输出：等价集（EquivalenceSet）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EquivalenceSet:
    """一个语义等价集合：包含所有「说同一件事」的经验。

    Attributes:
        cluster_id         : 等价集唯一 ID
        knowledge_layer    : 知识层
        target_service     : 规范化后的服务名称
        failure_sub_dim    : PROCEDURAL_NEG 层的子维度，其他层为空
        version_family     : 版本族
        cve_ids            : 覆盖的 CVE ID 集合
        exp_ids            : 属于本等价集的经验 ID 列表
        experiences        : 完整经验 dict 列表
        trigger_level      : 触发匹配的最高层级
        has_conflict       : 等价集内是否检测到互相矛盾的经验
        meets_fusion_threshold : 是否满足融合触发条件
    """
    cluster_id: str
    knowledge_layer: str
    target_service: str
    failure_sub_dim: str
    version_family: str
    cve_ids: List[str]
    exp_ids: List[str]
    experiences: List[Dict[str, Any]]
    trigger_level: str = "L1"
    has_conflict: bool = False
    meets_fusion_threshold: bool = False

    def __post_init__(self) -> None:
        threshold = _fusion_threshold_for_layer(self.knowledge_layer)
        self.meets_fusion_threshold = len(self.experiences) >= threshold


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — EWC 输出：带权重的经验包装
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WeightedExperience:
    """经过 EWC 权重计算后的经验包装对象。

    Attributes:
        exp_id          : 原始经验 ID
        w_quality       : 质量因子 = confidence
        weight          : 归一化权重 W(E)
        weight_effective: 有效权重（与 weight 相等，为下游接口兼容保留）
        exp             : 原始经验 dict 引用
    """
    exp_id: str
    w_quality: float
    weight: float
    weight_effective: float
    exp: Dict[str, Any]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1+2 联合输出：带权重的等价集
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WeightedEquivalenceSet:
    """等价集 + 每条经验的权重，是 RME（Phase 3）的直接输入。
    """
    cluster: EquivalenceSet
    weighted_exps: List[WeightedExperience]
    total_weight: float = 0.0
    dominant_exp_id: str = ""

    def __post_init__(self) -> None:
        if self.weighted_exps:
            self.total_weight = sum(we.weight_effective for we in self.weighted_exps)
            best = max(self.weighted_exps, key=lambda x: x.weight_effective)
            self.dominant_exp_id = best.exp_id


# ─────────────────────────────────────────────────────────────────────────────
# Provenance：consolidated 经验的来源记录
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Provenance:
    """记录一条 consolidated 经验的融合来源，支持完整回滚。"""
    source_exp_ids: List[str]
    source_sessions: List[str]
    weight_distribution: Dict[str, float]
    fusion_algorithm: str = "XPEC-RME-v1.0"
    fusion_timestamp: str = ""
    minority_opinions: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.fusion_timestamp:
            self.fusion_timestamp = datetime.utcnow().isoformat() + "Z"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — RME 输出：融合结果
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MergeResult:
    """Phase 3 RME：单个等价集的融合产物。"""
    cluster_id: str
    knowledge_layer: str
    target_service: str
    version_family: str
    cve_ids: List[str]
    source_exp_count: int
    fused_content: Dict[str, Any]
    provenance: "Provenance"
    minority_opinions: List[Dict[str, Any]] = field(default_factory=list)
    contradiction_score: float = 0.0
    merge_notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — BCC 输出：贝叶斯置信度校准结果
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BccResult:
    """Phase 4 BCC：贝叶斯置信度校准结果。"""
    cluster_id: str
    p_fused: float
    n_independent: int
    n_total: int
    old_maturity: str
    new_maturity: str
    upgraded: bool
    upgrade_reason: str
    downgraded: bool = False
    new_confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.new_confidence == 0.0:
            self.new_confidence = round(self.p_fused, 4)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3+4 联合输出：可写回主库的 Consolidated Experience
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConsolidatedExp:
    """最终可写回知识库的 consolidated experience 结构。

    格式与 Layer2 原始经验 JSONL 保持字段兼容，额外携带融合元数据。
    """
    exp_id: str
    knowledge_layer: str
    content: Dict[str, Any]
    metadata: Dict[str, Any]
    maturity: str
    confidence: float
    p_fused: float
    n_independent_sessions: int
    contradiction_score: float
    minority_opinions: List[Dict[str, Any]]
    provenance: Optional[Dict[str, Any]] = None

