"""
RefPenTest Layer 3 数据模型
===========================
定义 XPEC 融合框架各阶段的输入/输出数据结构。

设计原则：
- 非破坏性：所有原始经验通过 exp_id 可溯源，Consolidated 经验携带 provenance
- 可序列化：所有 dataclass 可直接转为 JSON（通过 dataclasses.asdict）
- 与 Layer2 schema 兼容：直接操作 Layer2 JSONL 中的 dict 对象，不做多余转换

Phase3 (RME) + Phase4 (BCC) 新增数据类：
- MergeResult    — RME 每个等价集的融合输出（fused content + provenance）
- BccResult      — BCC 贝叶斯置信度校准结果（P_fused + 成熟度升级决策）
- ConsolidatedExp — 写回 knowledge base 的完整 consolidated experience 结构
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 枚举：生命周期状态（KLM Phase 5 使用）
# 对应分析文档 §6.2 中新增的 lifecycle_status 字段
# ─────────────────────────────────────────────────────────────────────────────

class LifecycleStatus(str, Enum):
    ACTIVE      = "active"       # 正常可用，参与检索
    ARCHIVED    = "archived"     # 已被更高质量经验覆盖，降权保留
    SUSPENDED   = "suspended"    # 时效性衰减至阈值以下，不参与检索
    CONFLICTED  = "conflicted"   # 存在高权重反例，等待人工确认
    DELETED     = "deleted"      # 已确认无效，软删除


# ─────────────────────────────────────────────────────────────────────────────
# 枚举：成熟度级别（与 Layer2 schema 一致）
# ─────────────────────────────────────────────────────────────────────────────

class Maturity(str, Enum):
    RAW          = "raw"
    VALIDATED    = "validated"
    CONSOLIDATED = "consolidated"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — SEC 输出：等价集（EquivalenceSet）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EquivalenceSet:
    """一个语义等价集合：包含所有「说同一件事」的经验。

    Attributes:
        cluster_id         : 等价集唯一 ID，格式 SEC_{knowledge_layer}_{service_slug}_{sub_dim}_{version_family}
        knowledge_layer    : 知识层（FACTUAL / PROCEDURAL_NEG / METACOGNITIVE / ...）
        target_service     : 规范化后的服务名称（从 applicable_constraints 读取）
        failure_sub_dim    : PROCEDURAL_NEG 层的子维度，其他层为空字符串
        version_family     : 版本族（如 "10.3.x"），"" 表示版本未知
        cve_ids            : 覆盖的 CVE ID 集合（等价集内各经验 CVE 的并集）
        exp_ids            : 属于本等价集的经验 ID 列表
        experiences        : 完整经验 dict 列表（直接来自 Layer2 JSONL）
        trigger_level      : 触发匹配的最高层级（"L1" / "L1+L2" / "L1+L2+L4"）
        has_conflict       : 等价集内是否检测到互相矛盾的经验
        meets_fusion_threshold : 是否满足融合触发条件（≥3 条，Phase 3 RME 入口）
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
    meets_fusion_threshold: bool = False  # len(experiences) >= 3

    def __post_init__(self) -> None:
        self.meets_fusion_threshold = len(self.experiences) >= 3


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — EWC 输出：带权重的经验包装
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WeightedExperience:
    """经过 EWC 权重计算后的经验包装对象。

    Attributes:
        exp_id          : 原始经验 ID
        w_quality       : 质量因子 = session_bar_score × confidence
        w_maturity      : 成熟度因子（raw=0.4, validated=0.7, consolidated=1.0）
        w_outcome       : 结果因子（success=1.5, partial_success=1.0, failure=0.6）
        w_coverage      : CVE 覆盖度加成因子
        w_decay         : 时效性衰减因子（基于 created_at 和 knowledge_layer 的λ）
        weight          : 最终归一化权重 W(E) ∈ [0.1, 1.0]
        weight_effective: 时效折後权重 W_effective(E,t) = weight × w_decay
        exp             : 原始经验 dict 引用（不拷贝，节省内存）
    """
    exp_id: str
    w_quality: float
    w_maturity: float
    w_outcome: float
    w_coverage: float
    w_decay: float
    weight: float
    weight_effective: float
    exp: Dict[str, Any]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1+2 联合输出：带权重的等价集
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WeightedEquivalenceSet:
    """等价集 + 每条经验的权重，是 RME（Phase 3）的直接输入。

    Attributes:
        cluster          : 对应的 EquivalenceSet
        weighted_exps    : 该等价集内各经验的 WeightedExperience 列表（按权重降序）
        total_weight     : 所有经验的 weight_effective 之和（用于归一化）
        dominant_exp_id  : 权重最高的经验 ID（融合时的主导证据）
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
# Provenance：consolidated 经验的来源记录（Phase 3 RME 输出时附加）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Provenance:
    """记录一条 consolidated 经验的融合来源，支持完整回滚。

    与 metadata.source_event_ids（Layer1 事件 ID）含义不同：
    这里记录的是 Layer3 融合的源 *经验* IDs。
    """
    source_exp_ids: List[str]
    source_sessions: List[str]
    weight_distribution: Dict[str, float]   # exp_id -> 归一化权重
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
    """Phase 3 RME：单个等价集的融合产物。

    每个满足融合阈值的 WeightedEquivalenceSet 对应一个 MergeResult。
    fused_content 是层特定的融合后 content dict，结构依 knowledge_layer 而异。

    Attributes:
        cluster_id          : 来源等价集 ID（传递自 EquivalenceSet）
        knowledge_layer     : 融合后的知识层（FACTUAL_RULE / FACTUAL_LLM / ...）
        target_service      : 归一化服务名
        version_family      : 版本族约束
        cve_ids             : 覆盖的 CVE ID 集合
        source_exp_count    : 参与融合的原始经验数量
        fused_content       : 层特定的融合 content 结构（可直接序列化为 JSON）
        provenance          : 来源记录，支持回滚
        minority_opinions   : 未达到融合阈值但保留的少数意见列表
        contradiction_score : 矛盾度评分 [0, 1]，>0.6 时标记 conflicted
        merge_notes         : 融合过程的结构化注释（用于调试和审计）
    """
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
    """Phase 4 BCC：贝叶斯置信度校准结果。

    Attributes:
        cluster_id          : 来源等价集 ID
        p_fused             : 融合后置信度 [0, 1]（贝叶斯公式计算）
        n_independent       : 独立证据来源数（不同 session 数量）
        n_total             : 参与融合的总经验数
        old_maturity        : 融合前的成熟度（dominant experience 的 maturity）
        new_maturity        : 融合后决定的成熟度（raw/validated/consolidated）
        upgraded            : 是否发生了成熟度升级
        upgrade_reason      : 成熟度升级的原因说明
        downgraded          : 是否发生了成熟度降级（存在高权重反例）
        should_reflux       : 是否应将 consolidated 经验回流至主知识库
        lifecycle_status    : 融合后经验的生命周期状态
        new_confidence      : 融合后的最终置信度（= p_fused，但经生命周期因子调整）
    """
    cluster_id: str
    p_fused: float
    n_independent: int
    n_total: int
    old_maturity: str
    new_maturity: str
    upgraded: bool
    upgrade_reason: str
    downgraded: bool = False
    should_reflux: bool = False
    lifecycle_status: str = "active"
    new_confidence: float = 0.0

    def __post_init__(self) -> None:
        if self.new_confidence == 0.0:
            self.new_confidence = round(self.p_fused, 4)
        # 注意：should_reflux 由 bcc.calibrate() 在确定 lifecycle_status 后统一设置，
        # 此处不自动赋值，避免 conflicted 经验错误回流（问题③修复）


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3+4 联合输出：可写回主库的 Consolidated Experience
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConsolidatedExp:
    """最终可写回知识库的 consolidated experience 结构。

    格式与 Layer2 原始经验 JSONL 保持字段兼容，额外携带融合元数据。
    可直接通过 dataclasses.asdict() + json.dumps() 序列化写出。
    """
    exp_id: str                          # 格式：exp_consolidated_{cluster_id_hash}
    knowledge_layer: str
    content: Dict[str, Any]              # = MergeResult.fused_content
    metadata: Dict[str, Any]             # 包含 fusion_timestamp / source_sessions 等
    maturity: str                        # = BccResult.new_maturity
    confidence: float                    # = BccResult.new_confidence
    p_fused: float
    n_independent_sessions: int
    contradiction_score: float
    minority_opinions: List[Dict[str, Any]]
    lifecycle_status: str = "active"
    merged_into: Optional[str] = None    # 回滚时指向更新版本
    refluxed: bool = False               # 是否已回流至向量检索库
    provenance: Optional[Dict[str, Any]] = None  # Provenance.asdict()
