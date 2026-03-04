"""
canonical_types.py – 内部规范格式定义
========================================
Pre-Layer0 的所有适配器必须将外部日志转换为此格式，
Layer0 及以上层只处理此内部格式，与具体框架完全解耦。

设计约束（来自 §1 格式适配层设计）：
  1. 最小化：只包含 Layer0→Layer2 管道真正需要的字段
  2. 充分化：Layer1 语义理解所需的全部信息均可从中提取
  3. 可扩展：通过 raw_metadata 保留框架特有原始信息

兼容性说明：
  - CanonicalAgentTurn.session_id 须与 SessionMeta.session_id 一致
  - turn_index 在同一会话内单调递增（从 0 开始）
  - 若框架不提供 return_code，设为 None；Layer1 规则层降级为 LLM 语义层
  - rag_info 仅在该 turn 是 RAG 检索调用时填充，其余为 None
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# RAG 检索关联信息
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RagQueryInfo:
    """记录一次 RAG 检索调用的请求与响应信息。

    Attributes:
        query:        检索关键词，原始字符串（如 "WebLogic CVE-2017-10271 exploit"）
        results_raw:  检索结果原始文本，用于 Layer1 RAG 因果判定
        result_count: 返回的文档数量（-1 表示未知）
        dataset_id:   RAGFlow 数据集 ID（如有）
        latency_ms:   检索耗时毫秒数（-1 表示未知）
    """
    query: str
    results_raw: str = ""
    result_count: int = -1
    dataset_id: Optional[str] = None
    latency_ms: float = -1.0


# ─────────────────────────────────────────────────────────────────────────────
# 规范化 Agent Turn（核心类型）
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CanonicalAgentTurn:
    """适配器输出的规范化工具调用单元。

    每个 CanonicalAgentTurn 对应 Agent 在会话中发起的一次工具调用及其结果。
    多工具并行调用（如 CAI 同一 Turn 调用 2 个工具）用 slot_in_turn 区分。

    必填字段（所有适配器必须提供）
    ─────────────────────────────
    session_id:   会话唯一标识（与 SessionMeta.session_id 一致）
    turn_index:   轮次序号（从 0 开始，在会话内单调递增）
    timestamp:    ISO 8601 时间戳字符串；未知时填空字符串
    tool_name:    工具/函数名（如 "nmap_scan", "generic_linux_command"）
    tool_args:    工具参数字典（已反序列化）

    执行结果字段（尽力填写，框架不提供时为 None）
    ─────────────────────────────────────────────
    stdout:       标准输出原文
    stderr:       标准错误原文
    return_code:  退出码（0=成功, 127=命令不存在, 126=权限拒绝 …）
    success:      工具自报告的成功标志
    timed_out:    是否超时（工具自报告，100% 可靠）

    RAG 关联字段（仅 RAG 检索 turn 填写）
    ──────────────────────────────────────
    rag_info:     RagQueryInfo 对象；非 RAG 调用时为 None

    辅助字段
    ─────────
    assistant_reasoning:  Agent 在发起此工具调用前的推理文本
    slot_in_turn:         同一轮内第几个 tool_call（多工具并行时 ≥1）
    raw_metadata:         框架特有的原始信息（不参与核心管道计算）
    """

    # ── 必填字段 ────────────────────────────────────────────────────────────
    session_id: str
    turn_index: int
    timestamp: str
    tool_name: str
    tool_args: Dict[str, Any]

    # ── 执行结果字段 ─────────────────────────────────────────────────────────
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    return_code: Optional[int] = None
    success: Optional[bool] = None
    timed_out: bool = False

    # ── RAG 关联字段 ─────────────────────────────────────────────────────────
    rag_info: Optional[RagQueryInfo] = None

    # ── 辅助字段 ────────────────────────────────────────────────────────────
    assistant_reasoning: Optional[str] = None
    slot_in_turn: int = 0
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    # ── 计算属性 ─────────────────────────────────────────────────────────────

    @property
    def event_id(self) -> str:
        """全局唯一事件 ID（格式：{session_id[:8]}_{turn_index}_{slot_in_turn}）。"""
        prefix = self.session_id[:8] if len(self.session_id) >= 8 else self.session_id
        return f"{prefix}_{self.turn_index}_{self.slot_in_turn}"

    @property
    def is_rag_call(self) -> bool:
        """是否是 RAG 检索调用（rag_info 已填充）。"""
        return self.rag_info is not None

    @property
    def has_result(self) -> bool:
        """是否有执行结果（至少 stdout 或 stderr 不为 None）。"""
        return self.stdout is not None or self.stderr is not None

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典（供 JSON 导出使用）。"""
        return {
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "success": self.success,
            "timed_out": self.timed_out,
            "rag_info": {
                "query": self.rag_info.query,
                "results_raw": self.rag_info.results_raw,
                "result_count": self.rag_info.result_count,
            } if self.rag_info else None,
            "assistant_reasoning": self.assistant_reasoning,
            "slot_in_turn": self.slot_in_turn,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 会话元数据
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionMeta:
    """会话级别的元信息，由适配器解析日志文件后提取。

    Attributes:
        session_id:    会话唯一标识符
        start_time:    会话开始时间戳（ISO 8601 字符串）
        end_time:      会话结束时间戳；异常中断时为 None
        target_raw:    原始靶标描述（如 "http://127.0.0.1:7001"）
        total_cost:    LLM API 调用费用（美元，有则填写）
        session_end_type: "normal" | "interrupted"（适配器能判断时填写）
        total_turns:   解析到的 turn 总数（适配器在完成 parse 后可选回填）
        raw_metadata:  框架特有原始信息
    """
    session_id: str
    start_time: str
    end_time: Optional[str] = None
    target_raw: Optional[str] = None
    total_cost: float = 0.0
    session_end_type: str = "unknown"  # "normal" | "interrupted" | "unknown"
    total_turns: int = -1
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_unknown(cls, session_id: str) -> "SessionMeta":
        """在无法提取元数据时，构造最小化的占位 SessionMeta。"""
        return cls(session_id=session_id, start_time="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "target_raw": self.target_raw,
            "total_cost": self.total_cost,
            "session_end_type": self.session_end_type,
            "total_turns": self.total_turns,
        }
