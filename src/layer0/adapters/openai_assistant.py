"""
adapters/openai_assistant.py – OpenAI Assistants API 日志适配器
===============================================================
支持 OpenAI Assistants API 导出的 thread.run.step 日志格式。

格式特征（嗅探 key）：
  - JSON 数组文件（整个文件是 [...] ）或含 "data" 键的翻页响应
  - 最外层对象的 "object" 字段值以 "thread.run.step" 起始，或值为 "list"
    且 data[0].object == "thread.run.step"

每条 step 条目结构（简化）：
```json
{
  "id": "step_abc",
  "object": "thread.run.step",
  "type": "tool_calls",
  "step_details": {
    "tool_calls": [
      {
        "id": "call_xyz",
        "type": "function",
        "function": {
          "name": "nmap_scan",
          "arguments": "{\"target\":\"127.0.0.1\"}",
          "output": "...",
          "_return_code": 0   // 非标准，部分工具日志打补丁后加入
        }
      }
    ]
  },
  "created_at": 1710000000,
  "completed_at": 1710000005,
  "run_id": "run_abc",
  "thread_id": "thread_xyz"
}
```

信息完整度：⭐⭐⭐½
  - return_code：⚠️  非 OpenAI 官方字段，由工具层打补丁后可能存在于
                    function.output 的 JSON 字符串中或 function._return_code
  - timed_out：❌  不提供（若需要由 Layer1 语义判断）
  - RAG 查询：⚠️   须在 rag_tool_names 中声明 RAG 工具名
  - slot_in_turn：✅ 同一 step 内多个 tool_calls→ slot_in_turn = j
"""

from __future__ import annotations

import json
import logging
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from ..canonical_types import CanonicalAgentTurn, RagQueryInfo, SessionMeta
from ..log_adapter import AdapterRegistry, LogAdapter

logger = logging.getLogger(__name__)

_OBJECT_PREFIX = "thread.run.step"

# 默认 RAG 工具名集合
_DEFAULT_RAG_TOOL_NAMES: Set[str] = {
    "retrieval", "search", "kb_search", "rag_query",
    "retrieve", "vector_search", "knowledge_base_search",
    "similarity_search", "search_knowledge_base",
    "file_search",   # OpenAI 内置 RAG 工具名
}


@AdapterRegistry.register
class OpenAIAssistantAdapter(LogAdapter):
    """OpenAI Assistants API 日志适配器。

    解析 thread.run.step 列表，将每个 tool_calls 类型的 step 转换为
    一批 CanonicalAgentTurn（同一 step 的多个 tool call 按 slot_in_turn 区分）。

    Args:
        rag_tool_names: RAG 工具名集合（不区分大小写）。
                        追加自定义名称：
                            adapter = OpenAIAssistantAdapter(rag_tool_names={"my_rag"})
    """

    def __init__(self, rag_tool_names: Optional[Set[str]] = None) -> None:
        self._rag_tool_names: Set[str] = (
            {n.lower() for n in rag_tool_names}
            if rag_tool_names
            else set(_DEFAULT_RAG_TOOL_NAMES)
        )

    @property
    def adapter_name(self) -> str:
        return "openai_assistant"

    # ─── 格式嗅探 ────────────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        """
        嗅探策略：
        1. 读取文件内容（最多 8 KB）并尝试 JSON 解析；
        2. 若根对象是列表且非空，检查第一个元素；
        3. 若根对象是字典且含 "data" 键，检查 data[0]；
        4. 目标对象的 "object" 字段须以 "thread.run.step" 开头。
        """
        try:
            with open(file_path, encoding="utf-8") as fh:
                chunk = fh.read(8192)
            root = json.loads(chunk)
            first = cls._get_first_step(root)
            if first is None:
                return False
            obj_type = first.get("object", "")
            return isinstance(obj_type, str) and obj_type.startswith(_OBJECT_PREFIX)
        except Exception:  # noqa: BLE001
            pass
        return False

    # ─── 解析主入口 ──────────────────────────────────────────────────────────

    def parse(
        self,
        file_path: Path,
    ) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        self.validate_file(file_path)

        try:
            with open(file_path, encoding="utf-8") as fh:
                root = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"[OpenAIAssistantAdapter] 无法解析 JSON 文件 {file_path}: {exc}"
            ) from exc

        steps: List[Dict[str, Any]] = self._extract_steps(root)
        if not steps:
            session_id = file_path.stem
            return SessionMeta.from_unknown(session_id), iter([])

        meta = self._extract_session_meta(steps, file_path.stem)
        turn_iter = self._iter_canonical(steps, meta.session_id, self._rag_tool_names)
        return meta, turn_iter

    # ─── 内部：CanonicalAgentTurn 迭代器 ────────────────────────────────────

    @staticmethod
    def _iter_canonical(
        steps: List[Dict[str, Any]],
        session_id: str,
        rag_names: Set[str],
    ) -> Iterator[CanonicalAgentTurn]:
        """将 thread.run.step 列表转换为 CanonicalAgentTurn 序列。

        step.type == "message_creation" 的步骤（最终回复）不产生 CanonicalAgentTurn，
        仅 step.type == "tool_calls" 的步骤才映射到工具调用。
        """
        global_slot = 0

        for step_idx, step in enumerate(steps):
            if step.get("type") != "tool_calls":
                continue

            details = step.get("step_details") or {}
            tool_calls: List[Dict[str, Any]] = details.get("tool_calls") or []

            # 时间戳处理
            created_at = step.get("created_at")
            timestamp = _unix_to_iso(created_at) if created_at else ""

            for slot_j, tc in enumerate(tool_calls):
                tc_type = tc.get("type", "")

                # ── 函数调用 ──────────────────────────────────────────────
                if tc_type == "function":
                    fn = tc.get("function") or {}
                    tool_name = fn.get("name") or ""
                    tool_args = _parse_function_arguments(fn.get("arguments"))
                    # output 可能是 JSON 字符串，也可能是纯文本或 None
                    raw_output = fn.get("output") or ""
                    stdout, stderr, return_code = _parse_output(raw_output, fn)

                # ── 内置 file_search / retrieval ──────────────────────────
                elif tc_type in ("file_search", "retrieval"):
                    tool_name = tc_type
                    tool_args = {}
                    # file_search 的结果放在 tc["file_search"]["results"]
                    fs_results = tc.get("file_search") or tc.get("retrieval") or {}
                    raw_output = json.dumps(fs_results, ensure_ascii=False)
                    stdout, stderr, return_code = raw_output, None, None

                # ── code_interpreter ──────────────────────────────────────
                elif tc_type == "code_interpreter":
                    tool_name = "code_interpreter"
                    ci = tc.get("code_interpreter") or {}
                    tool_args = {"input": ci.get("input", "")}
                    # outputs 是 [{type:"logs"/image_file, logs:"...", ...}]
                    outputs = ci.get("outputs") or []
                    log_parts = [
                        o.get("logs", "") for o in outputs if o.get("type") == "logs"
                    ]
                    stdout = "\n".join(log_parts) if log_parts else ""
                    # 若存在 image 输出，记录文件 ID
                    images = [
                        o.get("image", {}).get("file_id", "")
                        for o in outputs if o.get("type") == "image_file"
                    ]
                    stderr = None
                    return_code = None
                    if images:
                        raw_output = stdout + "\n[images:" + ",".join(images) + "]"
                    else:
                        raw_output = stdout

                else:
                    # 未知工具类型，记录并跳过
                    logger.debug(
                        "[OpenAIAssistantAdapter] 未知 tool_call type: %s（step %d slot %d）",
                        tc_type, step_idx, slot_j,
                    )
                    continue

                # ── RAG 识别 ─────────────────────────────────────────────
                rag_info: Optional[RagQueryInfo] = None
                if tool_name.lower() in rag_names:
                    query_str = (
                        tool_args.get("query")
                        or tool_args.get("input")
                        or str(tool_args)
                    )
                    rag_info = RagQueryInfo(
                        query=query_str,
                        results_raw=stdout or raw_output,
                        result_count=_count_rag_results(stdout or raw_output),
                    )

                yield CanonicalAgentTurn(
                    session_id=session_id,
                    turn_index=step_idx,
                    timestamp=timestamp,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    stdout=stdout or None,
                    stderr=stderr,
                    return_code=return_code,
                    success=None if return_code is None else (return_code == 0),
                    timed_out=False,
                    rag_info=rag_info,
                    assistant_reasoning=None,  # Assistants API 不暴露 CoT
                    slot_in_turn=slot_j,
                    raw_metadata={
                        "step_id":    step.get("id", ""),
                        "run_id":     step.get("run_id", ""),
                        "thread_id":  step.get("thread_id", ""),
                        "call_id":    tc.get("id", ""),
                        "tc_type":    tc_type,
                        "completed_at": step.get("completed_at"),
                        "usage":      step.get("usage"),
                    },
                )
                global_slot += 1

    # ─── 内部辅助 ────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_steps(root: Any) -> List[Dict[str, Any]]:
        """从 JSON 根对象中提取 step 列表，支持裸数组和翻页响应。"""
        if isinstance(root, list):
            return root
        if isinstance(root, dict):
            data = root.get("data")
            if isinstance(data, list):
                return data
        return []

    @staticmethod
    def _get_first_step(root: Any) -> Optional[Dict[str, Any]]:
        """取第一个 step 条目（用于嗅探）。"""
        if isinstance(root, list) and root:
            return root[0] if isinstance(root[0], dict) else None
        if isinstance(root, dict):
            data = root.get("data", [])
            if isinstance(data, list) and data:
                return data[0] if isinstance(data[0], dict) else None
        return None

    @staticmethod
    def _extract_session_meta(
        steps: List[Dict[str, Any]],
        fallback_id: str,
    ) -> SessionMeta:
        """从 step 列表中提取会话元数据。"""
        # session_id 候选字段：thread_id > run_id > 文件名
        thread_id: str = ""
        run_id: str = ""
        start_ts: Optional[int] = None
        end_ts: Optional[int] = None

        for step in steps:
            if not thread_id:
                thread_id = step.get("thread_id", "")
            if not run_id:
                run_id = step.get("run_id", "")
            created = step.get("created_at")
            completed = step.get("completed_at")
            if created is not None:
                if start_ts is None or created < start_ts:
                    start_ts = created
            if completed is not None:
                if end_ts is None or completed > end_ts:
                    end_ts = completed

        session_id = thread_id or run_id or fallback_id
        return SessionMeta(
            session_id=session_id,
            start_time=_unix_to_iso(start_ts) if start_ts else "",
            end_time=_unix_to_iso(end_ts) if end_ts else None,
            session_end_type="normal" if end_ts else "unknown",
            total_turns=len([s for s in steps if s.get("type") == "tool_calls"]),
            raw_metadata={
                "thread_id": thread_id,
                "run_id":    run_id,
                "total_steps": len(steps),
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# 模块级辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _parse_function_arguments(raw: Any) -> Dict[str, Any]:
    """解析 function.arguments 字段（JSON 字符串 → dict）。"""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        return {"command": stripped}
    return {"_raw": raw}


def _parse_output(
    raw_output: Any,
    fn_dict: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """从 function.output 字段提取 stdout、stderr、return_code。

    OpenAI 官方 output 是工具返回的字符串。
    部分经过二次封装的工具日志（非官方标准）会在 JSON 输出中额外嵌入：
      {"stdout": "...", "stderr": "...", "return_code": 0}

    策略：
    1. 若 raw_output 为 JSON，尝试从中提取上述三字段；
    2. 否则全量作为 stdout，其余为 None；
    3. 非标准字段 function._return_code / ._status_code 作为 return_code 兜底。
    """
    if not raw_output:
        raw_str = ""
    else:
        raw_str = raw_output if isinstance(raw_output, str) else json.dumps(raw_output, ensure_ascii=False)

    stdout: Optional[str] = None
    stderr: Optional[str] = None
    return_code: Optional[int] = None

    # 尝试 JSON 解析
    if raw_str.strip().startswith("{"):
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, dict):
                stdout = parsed.get("stdout") or parsed.get("output") or raw_str
                stderr = parsed.get("stderr") or parsed.get("error") or None
                rc = parsed.get("return_code") or parsed.get("exit_code") or parsed.get("rc")
                return_code = int(rc) if rc is not None else None
                return stdout, stderr, return_code
        except (json.JSONDecodeError, ValueError):
            pass

    stdout = raw_str if raw_str else None

    # 非标准补丁字段（function 层）
    rc_patch = fn_dict.get("_return_code") or fn_dict.get("_status_code")
    if rc_patch is not None:
        try:
            return_code = int(rc_patch)
        except (ValueError, TypeError):
            pass

    return stdout, stderr, return_code


def _unix_to_iso(ts: Any) -> str:
    """Unix 时间戳（整数/浮点）→ ISO 8601 字符串。"""
    if ts is None:
        return ""
    try:
        f = float(ts)
        if math.isnan(f) or math.isinf(f):
            return ""
        return datetime.fromtimestamp(f, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(ts)


def _count_rag_results(output_raw: Optional[str]) -> int:
    """从 RAG 工具输出文本中估算返回的文档数量。"""
    if not output_raw:
        return 0
    # 若是 JSON 列表，直接取长度
    if output_raw.strip().startswith("["):
        try:
            items = json.loads(output_raw)
            if isinstance(items, list):
                return len(items)
        except (json.JSONDecodeError, ValueError):
            pass
    # 若是 JSON 对象，查找 results / items / data 字段
    if output_raw.strip().startswith("{"):
        try:
            obj = json.loads(output_raw)
            for key in ("results", "items", "data", "chunks"):
                if isinstance(obj.get(key), list):
                    return len(obj[key])
        except (json.JSONDecodeError, ValueError):
            pass
    # 文本模式：计分隔符
    separators = output_raw.count("---")
    if separators > 0:
        return separators + 1
    matches = re.findall(r"\bdocument\s+\d+\b|\bchunk\s+\d+\b", output_raw, re.IGNORECASE)
    if matches:
        return len(matches)
    return -1
