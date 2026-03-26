"""
Layer 2 经验数据模型
====================
定义经验条目的完整 Schema，支持四层知识体系的结构化存储。

设计原则：
- 所有经验条目具备完整的溯源信息（provenance）以便审计与实验复现
- content 字段采用 layer-specific 字典，避免过度抽象
- confidence 与 maturity 分离：confidence 是概率估计，maturity 是认证状态
- 支持跨 session 融合（Layer 3 使用）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
# 枚举
# ─────────────────────────────────────────────────────────────────────────────

class KnowledgeLayer(str, Enum):
    """六层知识模型（技术方案 R-03 扩展）。

    FACTUAL        : 具体事实（端口/服务/路径/版本，去 IP）
    CONCEPTUAL     : 攻击模式概念（LLM 归纳，进入 Agent 检索池）
    PROCEDURAL_POS : 有效操作步骤（成功的命令/代码模板）
    PROCEDURAL_NEG : 无效操作记录（失败命令 + 根因 + 建议）
    METACOGNITIVE  : 会话级元认知反思（决策回顾 + 经验教训）
    """
    FACTUAL        = "FACTUAL"
    CONCEPTUAL     = "CONCEPTUAL"
    PROCEDURAL_POS = "PROCEDURAL_POS"
    PROCEDURAL_NEG = "PROCEDURAL_NEG"
    METACOGNITIVE  = "METACOGNITIVE"


class ExperienceMaturity(str, Enum):
    """经验条目的成熟度状态（技术方案 Layer 3 融合周期）。

    raw         : 首次提取，尚未验证
    validated   : 人工或系统验证通过
    consolidated: 多条 raw/validated 条目融合后的高质量版本
    deprecated  : 已过时（目标已修补/信息过期），不再参与检索
    """
    RAW          = "raw"
    VALIDATED    = "validated"
    CONSOLIDATED = "consolidated"
    DEPRECATED   = "deprecated"


class ExperienceSource(str, Enum):
    """经验提取来源（用于置信度基准估算）。

    rule : 规则提取（确定性，无 LLM）
    llm  : LLM 提取（依赖语义理解）
    mixed: 规则 + LLM 联合提取
    """
    RULE  = "rule"
    LLM   = "llm"
    MIXED = "mixed"


# ─────────────────────────────────────────────────────────────────────────────
# 元数据
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExperienceMetadata:
    """经验条目的来源溯源元数据（provenance）。

    Fields:
        source_session_id  : 产生该经验的会话 ID
        source_event_ids   : 相关原子事件 ID 列表（支持多事件融合）
        source_turn_indices: 相关 Turn 序号列表
        extraction_source  : 提取方式（rule / llm / mixed）
        session_outcome    : 会话结果标签（success / partial_success / failure）
        target_raw         : 渗透目标描述（原始，不解析）
        created_at         : 提取时间戳
        extractor_version  : 提取器版本号（便于重跑时对比）
        tags               : 自由标签（CVE ID / 服务名 / 工具名等，检索用）
    """
    source_session_id: str
    source_event_ids: List[str] = field(default_factory=list)
    source_turn_indices: List[int] = field(default_factory=list)
    extraction_source: ExperienceSource = ExperienceSource.RULE
    session_outcome: str = "unknown"
    target_raw: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    extractor_version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)
    # P1: 检索时可用于精确过滤的结构化约束（如 target_service/cve_ids/version_range 等）
    applicable_constraints: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# 各 layer 的 content schema 辅助类（TypedDict 样式，供文档约束；实际存为 dict）
# ─────────────────────────────────────────────────────────────────────────────

# FACTUAL content 约定字段：
#   service_type    : str      "http" | "ssh" | "ftp" | "smb" | "database" | ...
#   target_indicator: str      IP/域名（已替换为 {TARGET_IP}）
#   discovered_facts: List[Dict[str,str]]  [{"key":"port","value":"8080"},...]
#   raw_evidence    : str      截断的原始输出（max 500 chars）
#   tool_name       : str
#   attack_phase    : str

# PROCEDURAL_POS content 约定字段：
#   command_template: str      参数化后的命令/代码（{TARGET_IP},{PORT} 等占位符）
#   original_command: str      原始命令/代码（前 1000 chars）
#   tool_name       : str
#   attack_phase    : str
#   preconditions   : List[str]
#   success_indicators: List[str]  从输出中提取的成功信号
#   cve_ids         : List[str]    提取的 CVE 编号
#   target_service  : Optional[str]

# PROCEDURAL_NEG content 约定字段：
#   failed_command  : str      失败的命令/代码（前 500 chars）
#   tool_name       : str
#   attack_phase    : Optional[str]
#   failure_dimension: str     ENV/INV/DEF/INT/EFF
#   failure_sub_dimension: str
#   evidence        : str
#   remediation_hint: Optional[str]
#   avoid_pattern   : str      一句话描述应该避免什么

# METACOGNITIVE content 约定字段：
#   session_goal     : str    本次渗透想达成的目标
#   session_outcome  : str    实际结果
#   key_lessons      : List[str]  3-5条经验教训
#   decision_insights: List[str]  关键决策点及其得失
#   rag_effectiveness: str    RAG 对本次会话的影响评估
#   failure_pattern  : Optional[str]  主导失败模式（如多 DEF 事件）
#   success_factor   : Optional[str]  关键成功因素

# CONCEPTUAL content 约定字段：
#   pattern_type         : str  "vulnerability_pattern"|"attack_strategy"|"defense_bypass"
#   applicable_conditions: List[str]  适用条件
#   core_insight         : str  核心洞察（2-3句）
#   supporting_evidence  : List[str]  支撑证据（来自事件摘要）
#   confidence_basis     : str  置信度依据

FACTUAL_CONTENT_KEYS = {
    # 规则提取的基础字段（保留）
    "service_type", "target_indicator", "discovered_facts",
    "raw_evidence", "tool_name", "attack_phase",
    # LLM 提升的可迁移字段（新增）
    "target_service",        # 软件名，如 Oracle WebLogic Server（无 IP）
    "target_version",        # 版本号，如 10.3.6.0
    "cve_context",           # {attempted, exploitation_results, unexplored}
    "applicable_constraints",# {network_topology, service_versions, known_ineffective_vectors}
    "exploitation_status",   # exploited | partial | patched | unknown
}

PROCEDURAL_POS_CONTENT_KEYS = {
    "command_template", "original_command", "tool_name", "attack_phase",
    "preconditions", "success_indicators", "cve_ids", "target_service",
}

PROCEDURAL_NEG_CONTENT_KEYS = {
    "failed_command", "tool_name", "attack_phase",
    "failure_dimension", "failure_sub_dimension",
    "evidence", "remediation_hint", "avoid_pattern",
    # LLM 生成的可迁移决策规则（新增）
    "failure_pattern_detail",  # {trigger_condition, interpretation, certainty}
    "decision_rule",           # {IF, THEN: [...], NOT}  ← 可迁移的 IF-THEN 规则
}

METACOGNITIVE_CONTENT_KEYS = {
    "session_goal", "session_outcome",
    # 结构化决策反思字段（R-05 要求）
    "decision_mistakes",      # [{mistake, consequence, rule: 'IF-THEN'}]
    "missed_opportunities",   # [可能有效但未尝试的路径]
    "optimal_decision_path",  # [最优决策序列]
    # 成功 session 额外字段（M-2 修复）
    "minimal_success_path",       # 最短成功步骤序列（去除冗余步骤后的精简路径）
    "replicability_conditions",   # 复现成功所需的前置条件列表
    "critical_decision_point",    # 整个攻击链中最关键的单一决策（换了就失败）
    # 向后兼容字段
    "key_lessons", "decision_insights",
    "rag_effectiveness", "failure_pattern", "success_factor",
}

CONCEPTUAL_CONTENT_KEYS = {
    "pattern_type",
    # applicable_conditions 现在是 dict 格式：
    # {positive: [...], negative: ["NOT: ..."], priority_over: [...], retrieval_triggers: [...]}
    # （Layer 3 检索时 retrieval_triggers 用于精确匹配触发）
    "applicable_conditions",
    "core_insight",
    "supporting_evidence",
    "confidence_basis",
    # confidence=0.3 (init), maturity=raw; Layer3 升为 validated 时 confidence=min(0.3*n,0.9)
}

# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：Experience
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Experience:
    """单条经验条目（知识库的最小单元）。

    ID 格式：exp_{session_id_prefix8}_{counter:04d}
    例：exp_b3ab5c15_0001

    Fields:
        exp_id          : 全局唯一标识符
        knowledge_layer : 知识层次（FACTUAL/CONCEPTUAL/PROCEDURAL_POS/etc.）
        content         : Layer-specific 内容字典（见上方各 schema 注释）
        metadata        : 溯源元数据
        maturity        : 成熟度状态（raw/validated/consolidated/deprecated）
        confidence      : 置信度 [0.0, 1.0]（规则提取: 0.7，LLM: 0.8，人工验证: 0.95）
        content_hash    : content 字典的 SHA-256 前16位（会话内去重用）
        merged_into     : 若被融合，指向目标 exp_id（None 表示未融合）
        refluxed        : 是否已回流到 RAGFlow 知识库
    """
    exp_id: str
    knowledge_layer: KnowledgeLayer
    content: Dict[str, Any]
    metadata: ExperienceMetadata
    maturity: ExperienceMaturity = ExperienceMaturity.RAW
    confidence: float = 0.7
    content_hash: Optional[str] = None
    merged_into: Optional[str] = None
    refluxed: bool = False

    def __post_init__(self) -> None:
        if self.content_hash is None:
            self.content_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """计算 content 的轻量哈希（用于会话内去重）。"""
        import hashlib
        import json
        try:
            serialized = json.dumps(self.content, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:
            serialized = str(self.content)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：ExperienceBundle
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExperienceBundle:
    """单个会话的经验提取结果（Layer 2 完整输出）。

    Fields:
        session_id           : 来源会话 ID
        experiences          : 提取到的全量经验条目列表（含所有 layer）
        factual_count        : FACTUAL 条目数
        procedural_pos_count : PROCEDURAL_POS 条目数
        procedural_neg_count : PROCEDURAL_NEG 条目数
        metacognitive_count  : METACOGNITIVE 条目数
        conceptual_count     : CONCEPTUAL 条目数
        total_count          : 总条目数
        extraction_errors    : 提取过程中遇到的错误信息
        llm_call_count       : LLM 调用次数
        session_outcome      : 会话结果标签（快速访问）
        target_raw           : 渗透目标原始描述（快速访问）
    """
    session_id: str
    experiences: List[Experience] = field(default_factory=list)
    extraction_errors: List[str] = field(default_factory=list)
    llm_call_count: int = 0
    session_outcome: str = "unknown"
    target_raw: Optional[str] = None

    @property
    def total_count(self) -> int:
        return len(self.experiences)

    @property
    def factual_count(self) -> int:
        return sum(1 for e in self.experiences if e.knowledge_layer == KnowledgeLayer.FACTUAL)

    @property
    def procedural_pos_count(self) -> int:
        return sum(1 for e in self.experiences if e.knowledge_layer == KnowledgeLayer.PROCEDURAL_POS)

    @property
    def procedural_neg_count(self) -> int:
        return sum(1 for e in self.experiences if e.knowledge_layer == KnowledgeLayer.PROCEDURAL_NEG)

    @property
    def metacognitive_count(self) -> int:
        return sum(1 for e in self.experiences if e.knowledge_layer == KnowledgeLayer.METACOGNITIVE)

    @property
    def conceptual_count(self) -> int:
        return sum(1 for e in self.experiences if e.knowledge_layer == KnowledgeLayer.CONCEPTUAL)

    @property
    def rag_evaluation_count(self) -> int:
        """兼容旧汇总字段：当前模型未启用 RAG_EVALUATION 层，固定为 0。"""
        return 0

    def by_layer(self, layer: KnowledgeLayer) -> List[Experience]:
        """按知识层过滤经验条目。"""
        return [e for e in self.experiences if e.knowledge_layer == layer]

    def add(self, exp: Experience) -> None:
        """添加一条经验（自动去重：同一 session 内相同 content_hash 跳过）。"""
        existing_hashes = {e.content_hash for e in self.experiences}
        if exp.content_hash not in existing_hashes:
            self.experiences.append(exp)

    def summary(self) -> str:
        """返回单行汇总字符串（便于日志输出）。"""
        return (
            f"session={self.session_id[:8]}… "
            f"total={self.total_count} "
            f"[F={self.factual_count} "
            f"P+={self.procedural_pos_count} "
            f"P-={self.procedural_neg_count} "
            f"M={self.metacognitive_count} "
            f"C={self.conceptual_count} "
            f"RAG_EVAL={self.rag_evaluation_count}] "
            f"outcome={self.session_outcome} "
            f"errors={len(self.extraction_errors)}"
        )
