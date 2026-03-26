"""
adapters/generic.py – 通用 JSONL 兜底适配器
============================================
当所有专用适配器均无法识别文件格式时，GenericJsonlAdapter 作为兜底，
依赖字段映射规则（field_map）从任意 JSONL 中提取工具调用信息。

设计原则：
  - can_handle() 始终返回 True（必须注册在所有专用适配器之后）
  - 字段映射支持多候选 + 点路径解析：
      ["tool_name", "tool", "action.tool", "function.name"]
      按顺序取第一个非 None、非空字符串的值
  - tool_args 候选可能是 JSON 字符串或已解析的 dict
  - 若无 return_code，可通过 infer_success 从 stdout 内容语义推断
  - 数字型 turn_index 自增兜底

默认 _default_field_map（完全可覆盖）：
  session_id  : [session_id, run_id, conversation_id, trace_id]
  turn_index  : [turn_index, step, index, turn, step_number]
  timestamp   : [timestamp, created_at, time, ts, datetime]
  tool_name   : [tool_name, tool, action.tool, function.name, name]
  tool_args   : [tool_args, tool_input, action.params, function.arguments, args, input]
  stdout      : [stdout, output, observation, result, response, content]
  stderr      : [stderr, error_output, error, error_message]
  return_code : [return_code, exit_code, rc, status_code]
  success     : [success, is_success, ok, status]
  reasoning   : [reasoning, thought, observation_prefix, log]

使用示例（自定义 field_map）：
```python
adapter = GenericJsonlAdapter(
    field_map={
        "tool_name": ["action_type"],
        "tool_args": ["parameters"],
        "stdout":    ["execution_output"],
    },
    rag_tool_names={"my_search_tool"},
    session_id_field="conversation_id",  # 单字段快捷方式
)
```
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from ..canonical_types import CanonicalAgentTurn, RagQueryInfo, SessionMeta
from ..log_adapter import AdapterRegistry, LogAdapter

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 默认字段映射（多候选列表，优先级从左到右）
# ─────────────────────────────────────────────────────────────────────────────

_FieldCandidates = List[str]  # 类型别名，每个元素可含点路径

DEFAULT_FIELD_MAP: Dict[str, _FieldCandidates] = {
    "session_id":  ["session_id", "run_id", "conversation_id", "trace_id", "thread_id"],
    "turn_index":  ["turn_index", "step", "index", "turn", "step_number"],
    "timestamp":   ["timestamp", "created_at", "time", "ts", "datetime", "date_time"],
    "tool_name":   ["tool_name", "tool", "action.tool", "function.name", "name", "action_type"],
    "tool_args":   [
        "tool_args", "tool_input", "action.params",
        "function.arguments", "args", "inputs", "input", "parameters",
    ],
    "stdout":      ["stdout", "output", "observation", "result", "response", "content", "text"],
    "stderr":      ["stderr", "error_output", "error", "error_message", "exception"],
    "return_code": ["return_code", "exit_code", "rc", "status_code", "returncode"],
    "success":     ["success", "is_success", "ok", "status"],
    "reasoning":   ["reasoning", "thought", "observation_prefix", "log", "thinking"],
}

# 默认 RAG 工具名集合
_DEFAULT_RAG_TOOL_NAMES: Set[str] = {
    "retrieval", "search", "kb_search", "rag_query",
    "retrieve", "vector_search", "knowledge_base_search",
    "similarity_search", "search_knowledge_base",
}


@AdapterRegistry.register   # ← 必须最后注册，can_handle 永远为 True
class GenericJsonlAdapter(LogAdapter):
    """通用 JSONL 兜底适配器。

    对任意每行一个 JSON 对象的文件执行字段映射提取。
    每行对应一次工具调用记录。

    Args:
        field_map: 字段映射，覆盖或追加到 DEFAULT_FIELD_MAP。
                   键为目标字段名，值为多候选路径列表（左优先）。
        rag_tool_names: 声明 RAG 工具的名称集合。
        session_id_field: 单字段快捷方式（覆盖 field_map["session_id"][0]）。
                          设置后，该字段优先级最高。
        skip_lines_without_tool: 若 True，跳过无法提取 tool_name 的行（默认 True）。
    """

    def __init__(
        self,
        field_map: Optional[Dict[str, _FieldCandidates]] = None,
        rag_tool_names: Optional[Set[str]] = None,
        session_id_field: Optional[str] = None,
        skip_lines_without_tool: bool = True,
    ) -> None:
        # 合并自定义 field_map 到默认映射（自定义优先）
        merged: Dict[str, _FieldCandidates] = {
            k: list(v) for k, v in DEFAULT_FIELD_MAP.items()
        }
        if field_map:
            for k, v in field_map.items():
                # 自定义候选列表放在前面
                merged[k] = list(v) + [c for c in merged.get(k, []) if c not in v]

        # session_id 快捷字段
        if session_id_field:
            sid_list = merged.setdefault("session_id", [])
            if session_id_field not in sid_list:
                sid_list.insert(0, session_id_field)

        self._field_map = merged
        self._rag_tool_names: Set[str] = (
            {n.lower() for n in rag_tool_names}
            if rag_tool_names
            else set(_DEFAULT_RAG_TOOL_NAMES)
        )
        self._skip_no_tool = skip_lines_without_tool

    @property
    def adapter_name(self) -> str:
        return "generic"

    # ─── 格式嗅探 ────────────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        """兜底适配器：始终返回 True（由 AdapterRegistry 注册顺序保证最后调用）。"""
        return True

    # ─── 解析主入口 ──────────────────────────────────────────────────────────

    def parse(
        self,
        file_path: Path,
    ) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        self.validate_file(file_path)

        first_record: Optional[Dict[str, Any]] = None
        last_record: Optional[Dict[str, Any]] = None
        valid_count = 0
        for rec in self._iter_records(file_path):
            if first_record is None:
                first_record = rec
            last_record = rec
            valid_count += 1

        if first_record is None or last_record is None:
            meta = SessionMeta.from_unknown(file_path.stem)
            return meta, iter([])

        meta = self._extract_session_meta(
            first_record=first_record,
            last_record=last_record,
            fallback_id=file_path.stem,
            total_turns=valid_count,
        )
        turn_iter = self._iter_canonical(
            file_path, meta.session_id, self._field_map,
            self._rag_tool_names, self._skip_no_tool,
        )
        return meta, turn_iter

    # ─── 内部：CanonicalAgentTurn 迭代器 ────────────────────────────────────

    @staticmethod
    def _iter_canonical(
        file_path: Path,
        session_id: str,
        field_map: Dict[str, _FieldCandidates],
        rag_names: Set[str],
        skip_no_tool: bool,
    ) -> Iterator[CanonicalAgentTurn]:
        auto_turn_idx = 0

        for rec in GenericJsonlAdapter._iter_records(file_path):
            get = _FieldResolver(rec, field_map)

            # ── tool_name ─────────────────────────────────────────────────
            tool_name = get.str("tool_name") or ""
            if not tool_name and skip_no_tool:
                continue

            # ── turn_index ────────────────────────────────────────────────
            raw_idx = get.raw("turn_index")
            try:
                turn_index = int(raw_idx) if raw_idx is not None else auto_turn_idx
            except (ValueError, TypeError):
                turn_index = auto_turn_idx

            # ── tool_args ────────────────────────────────────────────────
            tool_args = _resolve_tool_args(get.raw("tool_args"))

            # ── 执行结果 ──────────────────────────────────────────────────
            stdout_raw = get.str("stdout")
            stderr_raw = get.str("stderr")

            rc_raw = get.raw("return_code")
            return_code: Optional[int] = None
            if rc_raw is not None:
                try:
                    return_code = int(rc_raw)
                except (ValueError, TypeError):
                    pass

            success_raw = get.raw("success")
            success: Optional[bool] = None
            if success_raw is not None:
                if isinstance(success_raw, bool):
                    success = success_raw
                elif isinstance(success_raw, (int, float)):
                    success = bool(success_raw)
                elif isinstance(success_raw, str):
                    success = success_raw.lower() in ("true", "1", "ok", "success", "yes")
            elif return_code is not None:
                success = return_code == 0

            # ── 时间戳 ────────────────────────────────────────────────────
            timestamp = get.str("timestamp") or ""

            # ── session_id 兜底 ───────────────────────────────────────────
            rec_session_id = get.str("session_id") or session_id

            # ── RAG 识别 ──────────────────────────────────────────────────
            rag_info: Optional[RagQueryInfo] = None
            if tool_name.lower() in rag_names:
                query_str = (
                    tool_args.get("query")
                    or tool_args.get("input")
                    or str(tool_args)
                )
                rag_info = RagQueryInfo(
                    query=query_str,
                    results_raw=stdout_raw or "",
                    result_count=_count_rag_docs(stdout_raw or ""),
                )

            # ── 推理文本 ──────────────────────────────────────────────────
            reasoning = get.str("reasoning")

            # ── 元数据（保留原始行的其他所有字段）───────────────────────
            known_paths: Set[str] = set()
            for candidates in field_map.values():
                for c in candidates:
                    known_paths.add(c.split(".")[0])  # 顶层 key
            raw_meta = {
                k: v for k, v in rec.items()
                if k not in known_paths
            }
            raw_meta["_source_record"] = {k: v for k, v in rec.items()}

            yield CanonicalAgentTurn(
                session_id=rec_session_id,
                turn_index=turn_index,
                timestamp=timestamp,
                tool_name=tool_name,
                tool_args=tool_args,
                stdout=stdout_raw,
                stderr=stderr_raw,
                return_code=return_code,
                success=success,
                timed_out=False,
                rag_info=rag_info,
                assistant_reasoning=reasoning,
                slot_in_turn=0,
                raw_metadata=raw_meta,
            )
            auto_turn_idx += 1

    @staticmethod
    def _iter_records(file_path: Path) -> Iterator[Dict[str, Any]]:
        """流式读取 JSONL 记录，跳过非对象与坏行。"""
        with open(file_path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "[GenericJsonlAdapter] 行 %d JSON 解析失败: %s", lineno, exc
                    )
                    continue

                if isinstance(obj, dict):
                    yield obj
                else:
                    logger.debug("[GenericJsonlAdapter] 行 %d 非对象类型，跳过", lineno)

    # ─── 内部：会话元数据提取 ────────────────────────────────────────────────

    def _extract_session_meta(
        self,
        first_record: Dict[str, Any],
        last_record: Dict[str, Any],
        fallback_id: str,
        total_turns: int,
    ) -> SessionMeta:
        get_first = _FieldResolver(first_record, self._field_map)
        get_last  = _FieldResolver(last_record, self._field_map)

        session_id = get_first.str("session_id") or fallback_id
        start_time = get_first.str("timestamp") or ""
        end_time   = get_last.str("timestamp") or None

        return SessionMeta(
            session_id=session_id,
            start_time=start_time,
            end_time=end_time,
            session_end_type="unknown",
            total_turns=total_turns,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 内部辅助：字段解析器
# ─────────────────────────────────────────────────────────────────────────────

class _FieldResolver:
    """从单个 JSON 对象中，按多候选列表（含点路径）解析字段值。"""

    def __init__(
        self,
        obj: Dict[str, Any],
        field_map: Dict[str, _FieldCandidates],
    ) -> None:
        self._obj = obj
        self._field_map = field_map

    def raw(self, field: str) -> Any:
        """返回第一个能解析到非 None 值的候选路径的原始值。"""
        for path in self._field_map.get(field, [field]):
            val = _get_dotpath(self._obj, path)
            if val is not None:
                return val
        return None

    def str(self, field: str) -> Optional[str]:
        """同 raw()，但将结果规范化为字符串（空字符串返回 None）。"""
        val = self.raw(field)
        if val is None:
            return None
        if isinstance(val, str):
            return val.strip() or None
        # dict / list → JSON 字符串
        if isinstance(val, (dict, list)):
            try:
                return json.dumps(val, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(val)
        return str(val)


def _get_dotpath(obj: Dict[str, Any], path: str) -> Any:
    """解析点分路径（如 "action.tool" → obj["action"]["tool"]）。"""
    parts = path.split(".")
    cur: Any = obj
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _resolve_tool_args(raw: Any) -> Dict[str, Any]:
    """将 tool_args 候选值规范化为 dict。"""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        return {"command": stripped}
    if isinstance(raw, list):
        return {"_list": raw}
    return {"_raw": raw}


def _count_rag_docs(output_raw: str) -> int:
    """从 RAG 工具输出文本中估算文档数量。"""
    if not output_raw:
        return 0
    stripped = output_raw.strip()
    if stripped.startswith("["):
        try:
            items = json.loads(stripped)
            if isinstance(items, list):
                return len(items)
        except (json.JSONDecodeError, ValueError):
            pass
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            for key in ("results", "items", "data", "chunks", "documents"):
                if isinstance(obj.get(key), list):
                    return len(obj[key])
        except (json.JSONDecodeError, ValueError):
            pass
    separators = output_raw.count("---")
    if separators > 0:
        return separators + 1
    matches = re.findall(r"\bdocument\s*\d+\b|\bchunk\s*\d+\b", output_raw, re.IGNORECASE)
    return len(matches) if matches else -1
