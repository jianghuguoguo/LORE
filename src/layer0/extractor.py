"""
Layer 0 – Step 2：事件原子提取（Atomic Event Extraction）
=========================================================
职责：遍历 Turn 对象，从 assistant_message.tool_calls 中提取
AtomicEvent 列表，并填充 CallDescriptor 和 ResultDescriptor。

技术方案定义（六.Layer0 Step2）：
    对每个 Turn，提取以下原子字段：
    ① 调用描述（CallDescriptor）：tool_name, call_args, call_timestamp
    ② 结果描述（ResultDescriptor）：return_code, timed_out, success,
                                    stderr_raw, stdout_raw（不做语义判断）
    ③ 行为归类（ActionCategory）：基于结构维度，由配置驱动，不基于工具名语义
    ④ RAG 关联标记：识别 RAG_QUERY 事件，建立 RAG 查询记录
    ⑤ 代码写入特殊处理：提取 code/language/filename 字段

设计约束：
    - tool_name 原样保留，不做任何语义解读
    - 成功/失败判断全部交给 Layer 1，此处不做任何标记
    - program_name 提取仅做纯文本 split，不做语义分类
    - code 内容原样保留，filename/language 交 Layer 1 判断语义
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    ActionCategory,
    AtomicEvent,
    CallDescriptor,
    RagQueryRecord,
    ResultDescriptor,
    Turn,
)
from ..utils.config_loader import Config, get_config
from ..utils.log_utils import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 内部工具函数
# ─────────────────────────────────────────────────────────────────────────────

def _safe_parse_args(arguments_str: Any) -> Dict[str, Any]:
    """安全解析 function.arguments（JSON 字符串 → dict）。

    容忍空字符串、已是 dict 的情况以及格式错误。
    """
    if isinstance(arguments_str, dict):
        return arguments_str
    if not arguments_str:
        return {}
    try:
        return json.loads(arguments_str)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Cannot parse tool_call arguments: %s ... (%s)", str(arguments_str)[:80], exc)
        return {"_raw_arguments": str(arguments_str)}


def _extract_program_name(command: str) -> Optional[str]:
    """从通用命令字符串中提取第一个可执行程序名（纯文本 split）。

    技术方案约束：
        "提取 program_name（command 字符串的首个可执行程序名，纯文本提取）"
        "program_name 和完整 command 均交给 Layer 1 做语义理解"

    处理常见前缀：sudo、env、time、nice 等包装命令。
    """
    if not command or not isinstance(command, str):
        return None
    # 去掉前后空白和 shell 特殊前缀变量赋值（如 FOO=bar cmd）
    cmd = command.strip()
    # 简单分词
    tokens = cmd.split()
    if not tokens:
        return None
    # 跳过常见"透明包装"命令，取下一个 token 作为真正的程序名
    # 仅将"完全透明"的包装命令纳入跳过列表。
    # sh/bash/dash/zsh 本身也是有意义的程序名（如 bash /tmp/reverse.sh），不跳过。
    transparent_wrappers = {"sudo", "env", "time", "nice", "ionice", "strace", "ltrace",
                            "timeout", "nohup"}
    skip_next_numeric = False
    for tok in tokens:
        # timeout/nice/ionice 等命令后紧跟一个数值参数，需要一并跳过
        if skip_next_numeric:
            skip_next_numeric = False
            if re.match(r'^\d+(\.\d+)?$', tok):
                continue  # 跳过数值参数（如 timeout 30 cmd → 跳过 30）
        # 移除路径前缀 /usr/bin/nmap → nmap
        base = tok.split("/")[-1]
        if base in transparent_wrappers:
            # 某些 wrapper 后跟数值参数：timeout 30、nice -n 10、ionice -c 2
            if base in {"timeout", "nice", "ionice"}:
                skip_next_numeric = True
            continue
        if re.match(r'^-', base) or re.match(r'^[A-Z_]+=', base):
            continue
        return base
    return tokens[0].split("/")[-1]


def _build_result_descriptor(
    tool_call_id: str,
    tool_results_map: Dict[str, Dict[str, Any]],
) -> Optional[ResultDescriptor]:
    """从工具执行结果字典构建 ResultDescriptor。

    Args:
        tool_call_id    : 工具调用 ID
        tool_results_map: {tool_call_id -> parsed_result_dict}（来自 parser 注入）

    Returns:
        ResultDescriptor，若结果不存在则返回 None
    """
    raw = tool_results_map.get(tool_call_id)
    if raw is None:
        return None

    # 字段映射（日志中字段名为 stderr/stdout，模型中为 stderr_raw/stdout_raw）
    return_code = raw.get("return_code")
    raw_text: str = raw.get("_raw_text", "")

    # 设计问题2修复：execute_code 等工具的失败结果为纯文本，无结构化 return_code。
    # 匹配固定模式 "Command exited with code N" → 补全 return_code。
    if return_code is None and raw_text:
        m = re.search(r'[Cc]ommand\s+exited\s+with\s+(?:code\s+)?(\d+)', raw_text)
        if m:
            return_code = int(m.group(1))
            logger.debug(
                "Extracted return_code=%d from _raw_text for tool_call_id=%s",
                return_code, tool_call_id,
            )

    return ResultDescriptor(
        return_code=return_code,
        timed_out=bool(raw.get("timed_out", False)),
        success=raw.get("success"),           # None 允许（部分工具不报告）
        stderr_raw=raw.get("stderr", raw.get("stderr_raw", "")),
        stdout_raw=raw.get("stdout", raw.get("stdout_raw", "")),
        partial_results=bool(raw.get("partial_results", False)),
        raw_result=raw,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 主提取器
# ─────────────────────────────────────────────────────────────────────────────

class EventExtractor:
    """Layer 0 Step 2：从 Turn 对象提取 AtomicEvent 和 RagQueryRecord 列表。

    对每个 Turn：
    1. 读取 assistant_message.tool_calls（Agent 本轮决策的工具调用列表）
    2. 从 Turn.api_request["_tool_results"]（由 parser 注入）获取对应执行结果
    3. 构建 CallDescriptor + ResultDescriptor → AtomicEvent
    4. 对 RAG_QUERY 类事件，同时构建 RagQueryRecord
    """

    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or get_config()

    def extract(self, turn: Turn) -> Tuple[List[AtomicEvent], List[RagQueryRecord]]:
        """提取单个 Turn 的全部原子事件和 RAG 查询记录。

        Args:
            turn: LogParser 输出的 Turn 对象

        Returns:
            (events, rag_queries)
            - events     : 本 Turn 的 AtomicEvent 列表，按 tool_call 顺序排列
            - rag_queries: 本 Turn 含有的 RAG 查询记录列表
        """
        am = turn.assistant_message or {}
        raw_tool_calls: List[Dict[str, Any]] = am.get("tool_calls") or []

        # Bug1 修复：assistant_message.tool_calls 为空时，
        # 回退到 completion.choices[0].message.tool_calls
        # 根因：部分 Turn 的 assistant_message 事件不含 tool_calls，
        # 但 chat.completion 响应中包含完整的 tool_calls（如 session 5db69512
        # 的 Turn 10/11）。两者内容理论上一致，结构完全相同。
        if not raw_tool_calls:
            completion = turn.completion or {}
            choices = completion.get("choices", [])
            if choices:
                comp_msg = choices[0].get("message", {})
                raw_tool_calls = comp_msg.get("tool_calls") or []
            if raw_tool_calls:
                logger.debug(
                    "Turn %d: tool_calls not in assistant_message, "
                    "using completion.choices[0].message (%d calls)",
                    turn.turn_index, len(raw_tool_calls),
                )

        if not raw_tool_calls:
            logger.debug("Turn %d: no tool_calls in assistant_message or completion", turn.turn_index)
            return [], []

        # 工具结果字典（由 parser 注入到 api_request["_tool_results"]）
        api_req = turn.api_request or {}
        tool_results: Dict[str, Dict[str, Any]] = api_req.get("_tool_results", {})

        events: List[AtomicEvent] = []
        rag_queries: List[RagQueryRecord] = []

        for slot, tc in enumerate(raw_tool_calls):
            try:
                event, rag_query = self._extract_one(
                    tc=tc,
                    slot=slot,
                    turn=turn,
                    tool_results=tool_results,
                )
            except Exception as exc:
                logger.error(
                    "Error extracting event at turn=%d slot=%d: %s",
                    turn.turn_index, slot, exc,
                )
                continue

            events.append(event)
            if rag_query is not None:
                rag_queries.append(rag_query)

        return events, rag_queries

    def _extract_one(
        self,
        tc: Dict[str, Any],
        slot: int,
        turn: Turn,
        tool_results: Dict[str, Dict[str, Any]],
    ) -> Tuple[AtomicEvent, Optional[RagQueryRecord]]:
        """提取单个 tool_call 的 AtomicEvent 和可选的 RagQueryRecord。"""
        # ── 基础字段 ──────────────────────────────────────────────────────
        function_obj = tc.get("function", {})
        tool_name: str = function_obj.get("name", "_unknown_tool")
        tool_call_id: str = tc.get("id", f"synthetic_{turn.turn_index}_{slot}")
        call_args = _safe_parse_args(function_obj.get("arguments", "{}"))

        # ── 行为归类（ActionCategory）────────────────────────────────────
        category_str = self.cfg.classify_tool(tool_name)
        action_category = ActionCategory(category_str)

        # ── 专用字段提取 ─────────────────────────────────────────────────
        program_name: Optional[str] = None
        code_filename: Optional[str] = None
        code_language: Optional[str] = None

        if action_category == ActionCategory.GENERIC_COMMAND_CALL:
            command = call_args.get("command", "")
            program_name = _extract_program_name(command)

        elif action_category == ActionCategory.CODE_WRITE:
            code_filename = call_args.get("filename")
            code_language = call_args.get("language")

        # ── 构建 CallDescriptor ──────────────────────────────────────────
        call_desc = CallDescriptor(
            tool_name=tool_name,
            call_args=call_args,
            call_timestamp=turn.timestamp,
            tool_call_id=tool_call_id,
            action_category=action_category,
            program_name=program_name,
            code_filename=code_filename,
            code_language=code_language,
        )

        # ── 构建 ResultDescriptor ────────────────────────────────────────
        result_desc = _build_result_descriptor(tool_call_id, tool_results)

        # ── 构建全局唯一事件 ID ──────────────────────────────────────────
        event_id = f"{turn.session_id}_{turn.turn_index:04d}_{slot:02d}"

        # ── 构建 AtomicEvent ─────────────────────────────────────────────
        event = AtomicEvent(
            event_id=event_id,
            turn_index=turn.turn_index,
            slot_in_turn=slot,
            call=call_desc,
            result=result_desc,
            # has_rag_context 由 assembler 阶段填充，此处留默认 False
            has_rag_context=False,
        )

        # ── 构建 RagQueryRecord（仅 RAG_QUERY 类事件）────────────────────
        rag_record: Optional[RagQueryRecord] = None
        if action_category == ActionCategory.RAG_QUERY:
            rag_result_raw = (result_desc.raw_result if result_desc else {})
            # RAG 返回的文档内容通常在 stdout_raw 字段
            rag_result_text = (
                result_desc.stdout_raw if result_desc else
                rag_result_raw.get("stdout", rag_result_raw.get("stdout_raw", ""))
            )
            rag_record = RagQueryRecord(
                tool_call_id=tool_call_id,
                query=call_args.get("query", ""),
                rag_timestamp=turn.timestamp,
                turn_index=turn.turn_index,
                rag_result=rag_result_text or None,
            )

        logger.debug(
            "Turn %d slot %d: tool=%s  category=%s  has_result=%s",
            turn.turn_index, slot, tool_name, action_category.value,
            result_desc is not None,
        )

        return event, rag_record
