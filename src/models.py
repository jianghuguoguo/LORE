"""
RefPenTest Layer 0 核心数据模型
===================================
严格按照技术方案"六、完整项目实现路线图 / Layer 0：日志标准化层"
和"阶段 0：环境准备与基础数据结构"设计。

所有数据结构均为语义中性（Semantically Neutral）– 不包含任何攻击阶段
判断、成功/失败标注，仅记录结构化事实，供 Layer 1 做语义理解。

设计约束：
- 所有 dataclass 均为不可变枚举 + 可选字段组合，便于 JSON 序列化
- 遵循技术方案 2.3 节：工具名原样保留，不做预先分类枚举
- has_rag_context 仅表示"时间窗口内是否有 RAG 调用"，不表示采纳
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 枚举：行为分类（Action Category）
# 依据：技术方案 六.Layer0 Step2.2.3
# 分类依据：结构维度，不依赖工具名语义
# ─────────────────────────────────────────────────────────────────────────────

class ActionCategory(str, Enum):
    """Layer 0 的唯一分类操作：基于结构维度（非语义）判定行为类别。

    - RAG_QUERY           : tool_name 属于知识检索工具（配置驱动）
    - CODE_WRITE          : tool_name 属于代码写入/执行工具（配置驱动）
    - GENERIC_COMMAND_CALL: tool_name 属于通用 Linux/shell 命令执行工具（配置驱动）
    - STRUCTURED_TOOL_CALL: 其余所有工具调用，原样保留，语义交 Layer 1
    """
    RAG_QUERY = "RAG_QUERY"
    CODE_WRITE = "CODE_WRITE"
    GENERIC_COMMAND_CALL = "GENERIC_COMMAND_CALL"
    STRUCTURED_TOOL_CALL = "STRUCTURED_TOOL_CALL"


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：CallDescriptor（调用描述，技术方案 六.Layer0 Step2.2.1）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CallDescriptor:
    """描述一次工具调用的发起侧信息（语义中性）。

    Fields:
        tool_name      : 函数名，原样保留，不做语义分类
        call_args      : 参数字典，原样保留（从 function.arguments JSON 解析）
        call_timestamp : 调用时间戳（来自 assistant_message.timestamp）
        tool_call_id   : OpenAI tool_call id，用于与 ResultDescriptor 关联
        action_category: 基于结构维度的分类（Layer 0 唯一语义判断）
        program_name   : 仅 GENERIC_COMMAND_CALL 填充；command 首个可执行程序名
        code_filename  : 仅 CODE_WRITE 填充；脚本文件名/标识符
        code_language  : 仅 CODE_WRITE 填充；编程语言
    """
    tool_name: str
    call_args: Dict[str, Any]
    call_timestamp: datetime
    tool_call_id: str
    action_category: ActionCategory
    program_name: Optional[str] = None      # GENERIC_COMMAND_CALL 专用
    code_filename: Optional[str] = None     # CODE_WRITE 专用
    code_language: Optional[str] = None     # CODE_WRITE 专用


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：ResultDescriptor（结果描述，技术方案 六.Layer0 Step2.2.2）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ResultDescriptor:
    """描述一次工具执行的结果侧信息（可靠字段原样保留，不做成功/失败判断）。

    技术方案明确：
    "不做任何成功/失败信号词匹配，原样保留，交给 Layer 1 的语义理解层处理。"

    Fields:
        return_code : int，Exit code（0 通常成功，127=命令不存在，126=权限拒绝）
        timed_out   : bool，100% 可靠，工具自报告
        success     : bool|None，工具自报告，部分工具无此字段
        stderr_raw  : 原始标准错误输出，不做信号词匹配
        stdout_raw  : 原始标准输出，不做信号词匹配
        partial_results: 部分工具返回的超时截断标志
        raw_result  : 原始 result_fields 字典（完整保留所有字段）
    """
    return_code: Optional[int] = None
    timed_out: bool = False
    success: Optional[bool] = None
    stderr_raw: str = ""
    stdout_raw: str = ""
    partial_results: bool = False
    raw_result: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：RagQueryRecord（RAG 查询记录）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RagQueryRecord:
    """记录一次 RAG 知识检索调用及其返回内容。

    用于：
    1. has_rag_context 时间窗口标注
    2. Layer 1 RAG 行为因果判定的输入（返回内容对比后续行为）

    Fields:
        tool_call_id : 工具调用 ID，用于关联 ResultDescriptor
        query        : 查询内容（原始字符串）
        rag_timestamp: 查询时间戳
        rag_result   : RAG 返回内容（原始字符串，包含检索到的文档）
        turn_index   : 所在 Turn 序号
    """
    tool_call_id: str
    query: str
    rag_timestamp: datetime
    turn_index: int
    rag_result: Optional[str] = None   # 结果在关联 tool_result 中填充


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：AtomicEvent（原子事件，技术方案 六.Layer0 Step2）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AtomicEvent:
    """Layer 0 输出的最小处理单元：一次工具调用及其结果的完整记录。

    设计原则（技术方案 六.Layer0）：
    - 语义中性：不包含 attack_phase、failure_root_cause 等语义标注
    - 结构完整：call + result + context 三元组
    - 关联追踪：通过 tool_call_id 与 RAG 查询关联，通过 code_script_ref 与脚本执行关联

    Fields:
        event_id        : 全局唯一事件 ID（格式：{session_id}_{turn_index}_{slot}）
        turn_index      : 所在 Turn 的序号（0-based）
        slot_in_turn    : 同一 Turn 内的第几个工具调用（0-based）
        call            : 调用描述（CallDescriptor）
        result          : 结果描述（ResultDescriptor，可空，如工具尚未返回）
        has_rag_context : 前 N=3 步内是否有 RAG 调用（仅表示时间窗口内存在，不判断采纳）
        rag_query_ref   : 关联的 RAG 查询 ID（若 has_rag_context=True，指向最近的 RAG 调用）
        code_script_ref : 仅 GENERIC_COMMAND_CALL 有效；指向生成当前所执行脚本的
                          CODE_WRITE 事件 event_id 列表。空列表表示未检测到关联的 CODE_WRITE。
    """
    event_id: str
    turn_index: int
    slot_in_turn: int
    call: CallDescriptor
    result: Optional[ResultDescriptor] = None
    has_rag_context: bool = False
    rag_query_ref: Optional[str] = None         # 指向 RagQueryRecord.tool_call_id
    code_script_ref: List[str] = field(default_factory=list)  # 仅 CODE_WRITE 有效


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：Turn（轮次，技术方案 六.Layer0 Step1）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Turn:
    """一个完整的三段式交互轮次：assistant_message + API_request + chat.completion。

    技术方案定义：
    "识别三段式结构：assistant_message + API_request + chat.completion，
     构建 Turn 对象，每个 Turn 是最小分析单元。"

    Fields:
        turn_index      : 轮次序号（0-based）
        timestamp       : 轮次时间戳（来自 assistant_message.timestamp）
        session_id      : 所属会话 ID
        assistant_message : 原始 assistant_message 对象（含本轮 tool_calls 声明）
        api_request     : 原始 API 请求对象（含完整 messages 历史链）
        completion      : 原始 chat.completion 响应（含本轮实际 tool_call 决策）
        events          : 本轮提取的原子事件列表（Layer 0 Step2 输出）
        rag_queries     : 本轮内的 RAG 查询记录列表
    """
    turn_index: int
    timestamp: datetime
    session_id: str
    assistant_message: Optional[Dict[str, Any]] = None
    api_request: Optional[Dict[str, Any]] = None
    completion: Optional[Dict[str, Any]] = None
    events: List[AtomicEvent] = field(default_factory=list)
    rag_queries: List[RagQueryRecord] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        """本轮是否包含任何工具调用"""
        return bool(self.events)

    @property
    def rag_call_count(self) -> int:
        """本轮 RAG 查询次数"""
        return len(self.rag_queries)


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：SessionMetadata（会话元数据，技术方案 六.Layer0 Step2.2.5）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionMetadata:
    """从日志中提取的会话级元数据（语义中性，不含任何阶段/成功标注）。

    Fields:
        session_id       : 会话唯一标识符
        start_time       : 会话开始时间戳
        end_time         : 会话结束时间戳（可空，如日志不完整）
        timing_metrics   : 时间统计（active/idle/total）
        total_cost       : 本次会话 LLM API 总费用
        target_raw       : 渗透目标原始字符串（从首条 user_message 提取，不解析）
        source_file      : 原始日志文件路径
        log_filename     : 日志文件名（包含 session_id 等元信息）
        session_end_type : 会话结束方式：
                           "normal"      → 有 session_end 事件且 end_time 非 null
                           "interrupted" → 日志中无 session_end 事件（异常中断）
                           "unknown"     → 默认值（解析前）
    """
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    timing_metrics: Dict[str, Any] = field(default_factory=dict)
    total_cost: float = 0.0
    target_raw: Optional[str] = None
    source_file: Optional[str] = None
    log_filename: Optional[str] = None
    session_end_type: str = "unknown"   # "normal" | "interrupted" | "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# 核心数据类：TurnSequence（轮次序列，Layer 0 最终输出）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TurnSequence:
    """Layer 0 的完整输出：包含一个会话所有 Turn 及全量原子事件的有序序列。

    技术方案定义（六.Layer0 输出）：
    "结构化但语义中性的 TurnSequence，包含所有原始字段、时间顺序、RAG 时间关联。
     不包含任何：阶段判断、失败类型、成功/失败标注。"

    Fields:
        metadata      : 会话级元数据
        turns         : 按时间顺序排列的 Turn 序列
        all_events    : 所有 Turn 的 AtomicEvent 展平后的有序列表（便于 Layer 1 全量扫描）
        rag_index     : {tool_call_id -> RagQueryRecord} 索引，用于 Layer 1 快速查找
        code_write_index: {event_id -> AtomicEvent} CODE_WRITE 事件索引，用于脚本关联
    """
    metadata: SessionMetadata
    turns: List[Turn] = field(default_factory=list)
    all_events: List[AtomicEvent] = field(default_factory=list)
    rag_index: Dict[str, RagQueryRecord] = field(default_factory=dict)
    code_write_index: Dict[str, AtomicEvent] = field(default_factory=dict)

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def event_count(self) -> int:
        return len(self.all_events)

    @property
    def rag_call_count(self) -> int:
        return len(self.rag_index)

    @property
    def rag_context_event_count(self) -> int:
        """has_rag_context=True 的事件数量"""
        return sum(1 for e in self.all_events if e.has_rag_context)

    def get_events_in_window(self, turn_index: int, window: int = 3) -> List[AtomicEvent]:
        """获取某 Turn 前 window 步内的所有事件（不含本 Turn）"""
        return [
            e for e in self.all_events
            if turn_index - window <= e.turn_index < turn_index
        ]

    def get_rag_queries_before_turn(self, turn_index: int, window: int = 3) -> List[RagQueryRecord]:
        """获取某 Turn 之前 window 步内的所有 RAG 查询"""
        result = []
        for turn in self.turns:
            if turn_index - window <= turn.turn_index < turn_index:
                result.extend(turn.rag_queries)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 数据模型
# 依据：技术方案 R-02（失败根因五维分类法）+ 阶段2（确定性规则实现）
# ─────────────────────────────────────────────────────────────────────────────

class FailureRootCauseDimension(str, Enum):
    """失败根因五维分类法（技术方案 R-02）。

    维度定义：
        ENV : 执行环境问题（Execution Environment） — 工具缺失、权限、超时等
        INV : 调用方式问题（Invocation）            — 参数、语法、顺序错误
        DEF : 目标防御问题（Target Defense）         — 认证、拦截、已修补
        INT : 情报/认知问题（Intelligence Gap）       — 版本、拓扑、假设错误
        EFF : 执行效果问题（Execution Effect）        — 盲执行、无回显、部分成功
    """
    ENV = "ENV"
    INV = "INV"
    DEF = "DEF"
    INT = "INT"
    EFF = "EFF"


@dataclass
class FailureRootCause:
    """一次工具调用失败的根因记录（五维框架单条记录）。

    Fields:
        dimension       : 五维分类 (ENV/INV/DEF/INT/EFF)
        sub_dimension   : 子分类标签，如 BINARY_MISSING、TIMEOUT
        evidence        : 证据描述（规则层为机器可读字符串，LLM层为自然语言）
        source          : 来源 "rule" | "llm"
        remediation_hint: 修复建议（规则层可固化；LLM层动态生成，默认 None）
        search_queries  : Layer4 缺口爬取用的英文搜索词列表（LLM层生成，规则层为空列表）
    """
    dimension: FailureRootCauseDimension
    sub_dimension: str
    evidence: str
    source: str = "rule"
    remediation_hint: Optional[str] = None
    reasoning: Optional[str] = None          # LLM层 50-150字推理过程（规则层为空）
    search_queries: Optional[list] = None    # LLM层生成的 2-4 条英文搜索词，Layer4 用于缺口爬取（规则层为空）

    def __post_init__(self):
        if self.search_queries is None:
            self.search_queries = []


@dataclass
class AnnotatedEvent:
    """Layer 1 标注后的原子事件（AtomicEvent + 语义标注字段）。

    设计原则：
    - 不修改 Layer 0 输出，新增标注字段以组合形式附加
    - Phase 2 由规则层填充 failure_root_cause（确定性部分）
    - Phase 3 由 LLM 层填充 attack_phase / outcome_label / remediation_hint

    Fields:
        base             : Layer 0 输出的原始 AtomicEvent（不可变）
        failure_root_cause: 失败根因（规则层/LLM层填充，非失败或未分析时为 None）
        attack_phase     : 七维 Kill Chain 阶段标签（Phase 3 LLM填充）
        outcome_label    : 结果标签 success/partial_success/failure/timeout
                           （Phase 3 LLM填充；规则层可部分预填）
        rule_applied     : 触发的规则名称（调试与审计用，如 "RC-127"）
        needs_llm        : True 表示该事件需要 Phase 3 LLM 语义分析
    """
    base: AtomicEvent
    failure_root_cause: Optional[FailureRootCause] = None
    attack_phase: Optional[str] = None
    outcome_label: Optional[str] = None
    rule_applied: Optional[str] = None
    needs_llm: bool = False
    # ── Phase 3 LLM 填充字段 ───────────────────────────────────────────
    attack_phase_reasoning: Optional[str] = None   # attack_phase 判定依据
    rag_adoption: Optional[Dict[str, Any]] = None  # 仅 has_rag_context=True 的 RAG 事件填充；字段：adoption_level/adoption_label/adoption_weight/reasoning
    rag_adoption_reasoning: Optional[str] = None   # RAG 采纳判定依据
    llm_error: Optional[str] = None                # LLM 调用失败时的错误信息

    # ── 只读代理属性（便于 Layer 1 直接访问 base 字段）───────────────────
    @property
    def event_id(self) -> str:
        return self.base.event_id

    @property
    def turn_index(self) -> int:
        return self.base.turn_index

    @property
    def call(self) -> "CallDescriptor":
        return self.base.call

    @property
    def result(self) -> "Optional[ResultDescriptor]":
        return self.base.result

    @property
    def has_rag_context(self) -> bool:
        return self.base.has_rag_context


@dataclass
class AnnotatedTurnSequence:
    """Layer 1 完整输出：包含语义标注的完整事件序列。

    Fields:
        metadata                  : 继承自 Layer 0 的会话元数据（不修改原始数据）
        annotated_events          : 全量已标注事件列表（对应 TurnSequence.all_events）
        deterministic_hits        : 确定性规则命中次数（Phase 2 规则层填充的事件数）
        llm_pending               : 需要 Phase 3 LLM 处理任意任务的事件总数
                                    （= needs_llm=True 的事件数；涵盖行为分类、
                                    成功语义判断、RAG 采纳度等所有 LLM 任务，
                                    不等于 deterministic_hits 的补集）
        llm_pending_failure_cause : result 存在但失败根因未被规则覆盖、需 LLM
                                    判断失败原因的事件数（仅失败类，是 det_hits
                                    的真正补集；return_code≠0 或 success=False
                                    且无 FailureRootCause 的事件）
    """
    metadata: SessionMetadata
    annotated_events: List[AnnotatedEvent] = field(default_factory=list)
    deterministic_hits: int = 0
    llm_pending: int = 0
    llm_pending_failure_cause: int = 0
    # ── Phase 3 字段 ────────────────────────────────────────────────────────────
    rag_adoption_results: List["RagAdoptionResult"] = field(default_factory=list)
    session_outcome: Optional["SessionOutcome"] = None
    bar_score: float = 0.0        # 行为采纳度（Behaviour Adoption Rate）平均分
    llm_processed: bool = False   # Phase 3 是否已执行
    llm_call_count: int = 0       # Phase 3 实际 LLM 调用次数
    llm_error_count: int = 0      # Phase 3 LLM 调用失败次数

    @property
    def total_events(self) -> int:
        return len(self.annotated_events)

    @property
    def events_with_failure(self) -> List["AnnotatedEvent"]:
        """已确认有失败根因的事件列表"""
        return [e for e in self.annotated_events if e.failure_root_cause is not None]

    @property
    def env_failure_count(self) -> int:
        """ENV 维度失败事件数（执行环境问题）"""
        return sum(
            1 for e in self.annotated_events
            if e.failure_root_cause and e.failure_root_cause.dimension == FailureRootCauseDimension.ENV
        )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 补充数据模型
# 依据：技术方案 Layer 1 ④ RAG行为因果标注 + ③ 成功语义判断
# ─────────────────────────────────────────────────────────────────────────────

class AttackPhase(str, Enum):
    """七维 Kill Chain 行为功能框架（技术方案 Layer 1 ②）。

    扩展自 MITRE ATT&CK，增加 ENV_PREPARATION 维度以捕获 Agent 自我准备行为。
    """
    RECON_WEAPONIZATION = "RECON_WEAPONIZATION"   # 侦察与武器化
    EXPLOITATION        = "EXPLOITATION"           # 漏洞利用（初始访问）
    ESCALATION          = "ESCALATION"             # 权限提升
    LATERAL_MOVEMENT    = "LATERAL_MOVEMENT"       # 横向移动
    EXFILTRATION        = "EXFILTRATION"           # 数据渗出
    COMMAND_CONTROL     = "COMMAND_CONTROL"        # 命令与控制
    ENV_PREPARATION     = "ENV_PREPARATION"        # 环境准备（扩展维度）


class RagAdoptionLevel(int, Enum):
    """RAG 内容行为采纳度级别（技术方案 Layer 1 ④）。

    Level 3: 直接引用（Direct Adoption）      权重 1.0
    Level 2: 参考改写（Informed Adaptation）   权重 0.6
    Level 1: 思路启发（Conceptual Influence）  权重 0.3
    Level 0: 未采纳（Ignored）                权重 0.0
    """
    DIRECT      = 3   # 直接引用：后续行为的命令/代码中含 RAG 内容中的具体字符串
    INFORMED    = 2   # 参考改写：技术路线与 RAG 一致，但由 Agent 自行生成
    CONCEPTUAL  = 1   # 思路启发：影响了攻击方向选择，但具体路线不同
    IGNORED     = 0   # 未采纳：后续行为与 RAG 内容无任何关联


_RAG_ADOPTION_WEIGHTS: dict[int, float] = {3: 1.0, 2: 0.6, 1: 0.3, 0: 0.0}


@dataclass
class RagAdoptionResult:
    """单次 RAG 查询的行为采纳度评估结果（Phase 3 LLM 判定）。

    Fields:
        rag_tool_call_id  : 对应的 RAG 查询 tool_call_id
        query             : RAG 查询内容
        rag_turn_index    : RAG 查询所在 Turn 序号
        adoption_level    : 0-3（见 RagAdoptionLevel）
        adoption_label    : 人类可读标签
        adoption_weight   : 对应权重（用于 BAR 计算）
        reasoning         : LLM 判定依据
        behavior_window   : 分析的行为窗口事件 ID 列表
    """
    rag_tool_call_id: str
    query: str
    rag_turn_index: int
    adoption_level: int = 0
    adoption_label: str = "ignored"
    adoption_weight: float = 0.0
    reasoning: str = ""
    behavior_window: List[str] = field(default_factory=list)   # event_id 列表


@dataclass
class SessionOutcome:
    """会话整体攻击目标达成情况（Phase 3 LLM 判定）。

    Fields:
        is_success            : 是否达成主要攻击目标
        outcome_label         : "success" | "partial_success" | "failure"
        session_goal_achieved : 渗透测试目标是否完成（核心指标）
        achieved_goals        : 已达成的具体目标列表
        failed_goals          : 未达成的目标列表
        bar_score             : 行为采纳度平均分（0.0-1.0）
        reasoning             : LLM 判定依据
    """
    is_success: bool = False
    outcome_label: str = "failure"
    session_goal_achieved: bool = False
    achieved_goals: List[str] = field(default_factory=list)
    failed_goals: List[str] = field(default_factory=list)
    bar_score: float = 0.0
    reasoning: str = ""
    key_signals: List[str] = field(default_factory=list)  # 实际解析到的强募成功信号（uid=0/root@/flag{）
