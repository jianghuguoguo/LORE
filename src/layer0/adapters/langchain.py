"""
adapters/langchain.py – LangChain Agent 日志适配器
====================================================
支持 LangChain `FileCallbackHandler` 输出的 JSONL 格式。
兼容 LangChain v0.1.x 和 v0.2+ 两代事件格式。

LangChain 日志格式特征（嗅探 key）：
  - 每行是 JSON 对象（或 JSONL）
  - 含 "type" 字段，值为 LangChain callback 事件名称
  - 特征值：agent_action / tool_result / chain_start / on_tool_start / on_tool_end

事件映射关系（v0.1.x）：
  agent_action → tool invocation（含 tool + tool_input + log）
  tool_result  → tool output（含 output）
  llm_end      → LLM 响应（含 agent 推理文本，可选读取）

事件映射关系（v0.2+ Callbacks Protocol）：
  on_tool_start    → 工具调用开始（含 tool_name + tool_input）
  on_tool_end      → 工具调用结束（含 output）
  on_agent_action  → agent 决策（含 tool + tool_input + log）

信息完整度：⭐⭐⭐
  - return_code：❌ 不提供（外部 process 不暴露 exit code）
  - timed_out：❌ 不提供（由 Layer1 LLM 层语义判断）
  - RAG 查询：⚠️  须在 rag_tool_names 配置中声明 RAG 工具名才能识别
  - assistant 推理文本：✅ 来自 agent_action.log 或 on_agent_action.log
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from ..canonical_types import CanonicalAgentTurn, RagQueryInfo, SessionMeta
from ..log_adapter import AdapterRegistry, LogAdapter

logger = logging.getLogger(__name__)

# 最多读取的嗅探行数
_SNIFF_LINES = 15

# v0.1.x 事件类型
_V1_AGENT_ACTION = "agent_action"
_V1_TOOL_RESULT  = "tool_result"
_V1_CHAIN_START  = "chain_start"
_V1_CHAIN_END    = "chain_end"
_V1_LLM_END      = "llm_end"

# v0.2+ Callbacks Protocol 事件类型
_V2_TOOL_START   = "on_tool_start"
_V2_TOOL_END     = "on_tool_end"
_V2_AGENT_ACTION = "on_agent_action"
_V2_CHAIN_START  = "on_chain_start"
_V2_CHAIN_END    = "on_chain_end"
_V2_LLM_END      = "on_llm_end"

# 所有可用于嗅探的特征事件类型
_SNIFF_EVENT_TYPES: Set[str] = {
    _V1_AGENT_ACTION, _V1_TOOL_RESULT, _V1_CHAIN_START,
    _V2_TOOL_START, _V2_TOOL_END, _V2_AGENT_ACTION, _V2_CHAIN_START,
}

# 默认 RAG 工具名集合（用户可扩展）
_DEFAULT_RAG_TOOL_NAMES: Set[str] = {
    "retrieval", "search", "kb_search", "rag_query",
    "retrieve", "vector_search", "knowledge_base_search",
    "similarity_search", "search_knowledge_base",
}


@AdapterRegistry.register
class LangChainAdapter(LogAdapter):
    """LangChain Agent 日志适配器。

    支持两代 LangChain 日志格式（v0.1.x agent_action 和 v0.2+ on_tool_start）。
    可通过 rag_tool_names 参数声明哪些工具名对应 RAG 检索，以填充 rag_info。

    Args:
        rag_tool_names: RAG 工具名集合（不区分大小写）。
                        默认覆盖 retrieval / search / kb_search 等常见名称。
                        追加自定义名称：
                            adapter = LangChainAdapter(rag_tool_names={"my_retriever"})
    """

    def __init__(
        self,
        rag_tool_names: Optional[Set[str]] = None,
    ) -> None:
        self._rag_tool_names: Set[str] = (
            {n.lower() for n in rag_tool_names}
            if rag_tool_names
            else set(_DEFAULT_RAG_TOOL_NAMES)
        )

    @property
    def adapter_name(self) -> str:
        return "langchain"

    # ─── 格式嗅探 ────────────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        """嗅探前 _SNIFF_LINES 行，查找 LangChain 特有的事件类型。"""
        try:
            with open(file_path, encoding="utf-8") as fh:
                for _ in range(_SNIFF_LINES):
                    raw = fh.readline()
                    if not raw:
                        break
                    stripped = raw.strip()
                    if not stripped:
                        continue
                    obj = json.loads(stripped)
                    event_type = obj.get("type", "")
                    if event_type in _SNIFF_EVENT_TYPES:
                        return True
        except Exception:  # noqa: BLE001
            pass
        return False

    # ─── 解析主入口 ──────────────────────────────────────────────────────────

    def parse(
        self,
        file_path: Path,
    ) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        self.validate_file(file_path)
        events = list(self._iter_json_lines(file_path))

        if not events:
            session_id = file_path.stem
            meta = SessionMeta.from_unknown(session_id)
            return meta, iter([])

        # ── 检测协议版本 ────────────────────────────────────────────────────
        is_v2 = any(e.get("type", "").startswith("on_") for e in events[:20])

        # ── 会话元数据提取 ──────────────────────────────────────────────────
        meta = self._extract_session_meta(events, file_path.stem, is_v2)

        # ── 惰性迭代器工厂 ──────────────────────────────────────────────────
        rag_names = self._rag_tool_names
        if is_v2:
            turn_iter = self._iter_v2(events, meta.session_id, rag_names)
        else:
            turn_iter = self._iter_v1(events, meta.session_id, rag_names)

        return meta, turn_iter

    # ─── 内部：v0.1.x 解析（agent_action + tool_result 配对）──────────────

    @staticmethod
    def _iter_v1(
        events: List[Dict[str, Any]],
        session_id: str,
        rag_names: Set[str],
    ) -> Iterator[CanonicalAgentTurn]:
        """解析 LangChain v0.1.x 格式（agent_action → tool_result 配对）。"""
        pending_action: Optional[Dict[str, Any]] = None
        pending_reasoning: Optional[str] = None
        turn_idx = 0

        for obj in events:
            evt = obj.get("type", "")

            # LLM 响应 → 提取推理文本（agent_action 前的 思考文本）
            if evt == _V1_LLM_END:
                pending_reasoning = _extract_v1_llm_reasoning(obj)
                continue

            if evt == _V1_AGENT_ACTION:
                pending_action = obj
                continue

            if evt == _V1_TOOL_RESULT and pending_action is not None:
                tool_name = pending_action.get("tool", "") or ""
                tool_args = _parse_tool_input(pending_action.get("tool_input", ""))
                log_text = pending_action.get("log", "") or ""
                # log 字段通常形如 "Invoking: <tool> with <args>\nReasoning: ..."
                reasoning = pending_reasoning or (_clean_log_text(log_text) or None)

                output_raw = obj.get("output", "") or ""
                # LangChain tool output 通常不含 return_code
                # stdout 使用 output 字段；stderr 尝试从 error_output 取
                error_output = obj.get("error_output") or obj.get("error") or None
                # 构建 RagQueryInfo（若是 RAG 工具）
                rag_info: Optional[RagQueryInfo] = None
                if tool_name.lower() in rag_names:
                    query_str = tool_args.get("query") or tool_args.get("input") or str(tool_args)
                    rag_info = RagQueryInfo(
                        query=query_str,
                        results_raw=output_raw,
                        result_count=_count_rag_docs(output_raw),
                    )

                yield CanonicalAgentTurn(
                    session_id=session_id,
                    turn_index=turn_idx,
                    timestamp=pending_action.get("timestamp") or obj.get("timestamp") or "",
                    tool_name=tool_name,
                    tool_args=tool_args,
                    stdout=output_raw,
                    stderr=str(error_output) if error_output else None,
                    return_code=None,    # LangChain v0.1 不提供
                    success=None,        # 由 Layer1 判断
                    timed_out=False,
                    rag_info=rag_info,
                    assistant_reasoning=reasoning,
                    slot_in_turn=0,
                    raw_metadata={
                        "log": log_text,
                        "langchain_version": "v1",
                    },
                )
                turn_idx += 1
                pending_action = None
                pending_reasoning = None

    # ─── 内部：v0.2+ 解析（on_tool_start + on_tool_end 配对）──────────────

    @staticmethod
    def _iter_v2(
        events: List[Dict[str, Any]],
        session_id: str,
        rag_names: Set[str],
    ) -> Iterator[CanonicalAgentTurn]:
        """解析 LangChain v0.2+ 格式（on_tool_start → on_tool_end 配对）。

        v0.2 的事件按 run_id 对应，通过 run_id 匹配 start/end 对。
        同一 run_id 的 start/end 配对，不同 run_id 可并行出现。
        """
        # 按 run_id 收集 start 事件
        pending: Dict[str, Dict[str, Any]] = {}
        pending_reasoning: Optional[str] = None
        turn_idx = 0

        for obj in events:
            evt = obj.get("type", "")

            if evt == _V2_LLM_END:
                pending_reasoning = _extract_v2_llm_reasoning(obj)
                continue

            if evt in (_V2_AGENT_ACTION, _V2_TOOL_START):
                run_id = obj.get("run_id") or obj.get("id") or str(turn_idx)
                obj["_reasoning"] = pending_reasoning
                pending[run_id] = obj
                pending_reasoning = None
                continue

            if evt == _V2_TOOL_END:
                run_id = obj.get("run_id") or obj.get("id") or ""
                start_obj = pending.pop(run_id, None)
                if start_obj is None:
                    # end 事件无对应 start，跳过
                    logger.debug("on_tool_end without matching start (run_id=%s)", run_id)
                    continue

                tool_name = (
                    start_obj.get("name")
                    or start_obj.get("tool")
                    or obj.get("name")
                    or ""
                )
                tool_input = start_obj.get("input") or start_obj.get("tool_input") or {}
                tool_args = _parse_tool_input(tool_input)

                output = obj.get("output") or obj.get("result") or ""
                output_raw = str(output) if not isinstance(output, str) else output
                error = obj.get("error") or None

                # v0.2 可能携带 run_metadata 中的状态码
                run_meta = obj.get("run_metadata") or {}
                rc: Optional[int] = run_meta.get("return_code")

                reasoning = start_obj.get("_reasoning")

                rag_info: Optional[RagQueryInfo] = None
                if tool_name.lower() in rag_names:
                    q = tool_args.get("query") or tool_args.get("input") or str(tool_args)
                    rag_info = RagQueryInfo(
                        query=q,
                        results_raw=output_raw,
                        result_count=_count_rag_docs(output_raw),
                    )

                yield CanonicalAgentTurn(
                    session_id=session_id,
                    turn_index=turn_idx,
                    timestamp=start_obj.get("start_time") or start_obj.get("timestamp") or "",
                    tool_name=tool_name,
                    tool_args=tool_args,
                    stdout=output_raw,
                    stderr=str(error) if error else None,
                    return_code=rc,
                    success=None if rc is None else (rc == 0),
                    timed_out=False,
                    rag_info=rag_info,
                    assistant_reasoning=reasoning,
                    slot_in_turn=0,
                    raw_metadata={
                        "run_id": run_id,
                        "langchain_version": "v2",
                        "run_metadata": run_meta,
                    },
                )
                turn_idx += 1

    # ─── 内部辅助 ────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_session_meta(
        events: List[Dict[str, Any]],
        fallback_id: str,
        is_v2: bool,
    ) -> SessionMeta:
        """从事件流中提取会话元数据。"""
        session_id = fallback_id
        start_time = ""
        end_time = ""
        end_type = "unknown"

        start_evt = _V2_CHAIN_START if is_v2 else _V1_CHAIN_START
        end_evt   = _V2_CHAIN_END   if is_v2 else _V1_CHAIN_END

        for obj in events:
            evt = obj.get("type", "")
            if evt == start_evt:
                session_id = (
                    obj.get("run_id") or obj.get("id") or fallback_id
                )
                start_time = obj.get("start_time") or obj.get("timestamp") or ""
            elif evt == end_evt:
                end_time = obj.get("end_time") or obj.get("timestamp") or ""
                end_type = "normal"
                break

        if not end_time:
            # 尝试从最后一个事件取时间
            last = events[-1] if events else {}
            end_time = last.get("timestamp") or last.get("end_time") or ""
            end_type = "interrupted" if not end_time else "unknown"

        return SessionMeta(
            session_id=session_id,
            start_time=start_time,
            end_time=end_time or None,
            session_end_type=end_type,
            total_turns=-1,  # 总 turn 数在迭代完成后才知道
        )

    @staticmethod
    def _iter_json_lines(file_path: Path) -> Iterator[Dict[str, Any]]:
        """逐行读取 JSONL 文件，跳过空行和解析失败行。"""
        with open(file_path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    yield json.loads(stripped)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "[LangChainAdapter] JSON parse error at line %d: %s", lineno, exc
                    )


# ─────────────────────────────────────────────────────────────────────────────
# 模块级辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _parse_tool_input(raw: Any) -> Dict[str, Any]:
    """解析 tool_input 字段（可能是字符串、字典或其他类型）。"""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        # 纯字符串命令（如 "nmap -sV 127.0.0.1"）收纳为 command 字段
        return {"command": stripped}
    # list / int / float 等异常情况
    return {"_raw": raw}


def _clean_log_text(log: str) -> str:
    """从 agent_action.log 中提取推理文本（去除 "Invoking: xxx" 前缀）。

    LangChain v0.1.x 的 log 字段格式：
        '\nInvoking: `terminal` with `nmap -sV 127.0.0.1`\n'
        或包含更多 CoT 推理文本的多行字符串。
    """
    if not log:
        return ""
    # 去掉 Invoking 行，保留前面的思考文本
    lines = [
        l for l in log.splitlines()
        if not re.match(r"^\s*Invoking\s*:", l, re.IGNORECASE)
    ]
    return "\n".join(lines).strip()


def _extract_v1_llm_reasoning(obj: Dict[str, Any]) -> Optional[str]:
    """从 v1 llm_end 事件中提取 LLM 生成的文本（Agent 推理）。"""
    try:
        response = obj.get("response", {})
        generations = response.get("generations", [[]])
        if generations and generations[0]:
            text = generations[0][0].get("text", "")
            return text.strip() or None
    except Exception:  # noqa: BLE001
        pass
    return None


def _extract_v2_llm_reasoning(obj: Dict[str, Any]) -> Optional[str]:
    """从 v2 on_llm_end 事件中提取推理文本。"""
    try:
        resp = obj.get("response") or {}
        gens = resp.get("generations", [[]])
        if gens and gens[0]:
            text = gens[0][0].get("text") or ""
            # 如果是 ChatGeneration，尝试取 message.content
            msg = gens[0][0].get("message", {})
            if msg:
                text = msg.get("content") or text
            return text.strip() or None
    except Exception:  # noqa: BLE001
        pass
    return None


def _count_rag_docs(output_raw: str) -> int:
    """从 RAG 工具的输出文本中估算返回的文档数量。"""
    # 粗略启发式：查找 "Document" / "Doc \d+" / 分隔符 "---" 数量
    if not output_raw:
        return 0
    # 计 "Document \d" 类模式
    doc_matches = re.findall(r"\bdocument\b|\bdoc\s+\d+\b", output_raw, re.IGNORECASE)
    if doc_matches:
        return len(doc_matches)
    # 计 "---" 分隔符数 + 1
    separators = output_raw.count("---")
    if separators > 0:
        return separators + 1
    # 若无法判断，返回 -1（未知）
    return -1
