"""
LORE 序列化工具
=====================
提供 TurnSequence / AtomicEvent 等数据类与 JSON/JSONL 格式之间的
序列化与反序列化功能，保证跨阶段（Layer 0 → Layer 1）数据传递的一致性。

设计原则：
- 使用标准 json 模块，避免引入重度依赖
- datetime 统一序列化为 ISO 8601 字符串
- Enum 序列化为其 .value（字符串）
- dataclass 递归序列化
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar

from ..models import (
    ActionCategory,
    AtomicEvent,
    CallDescriptor,
    RagQueryRecord,
    ResultDescriptor,
    SessionMetadata,
    Turn,
    TurnSequence,
)

T = TypeVar("T")


# ─────────────────────────────────────────────────────────────────────────────
# JSON 编码器
# ─────────────────────────────────────────────────────────────────────────────

class LOREEncoder(json.JSONEncoder):
    """支持 datetime、Enum、dataclass 的 JSON 编码器"""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj) and not isinstance(obj, type):
            return _dataclass_to_dict(obj)
        return super().default(obj)


def _dataclass_to_dict(obj: Any) -> Dict[str, Any]:
    """将 dataclass 递归转换为字典（保留 None 字段）"""
    if not (is_dataclass(obj) and not isinstance(obj, type)):
        raise TypeError(f"Expected dataclass, got {type(obj)}")

    result = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        if isinstance(value, datetime):
            result[f.name] = value.isoformat()
        elif isinstance(value, Enum):
            result[f.name] = value.value
        elif is_dataclass(value) and not isinstance(value, type):
            result[f.name] = _dataclass_to_dict(value)
        elif isinstance(value, list):
            result[f.name] = [
                _dataclass_to_dict(item) if (is_dataclass(item) and not isinstance(item, type))
                else (item.value if isinstance(item, Enum) else
                      (item.isoformat() if isinstance(item, datetime) else item))
                for item in value
            ]
        elif isinstance(value, dict):
            result[f.name] = {
                k: (_dataclass_to_dict(v) if (is_dataclass(v) and not isinstance(v, type)) else v)
                for k, v in value.items()
            }
        else:
            result[f.name] = value
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 序列化函数
# ─────────────────────────────────────────────────────────────────────────────

def serialize_turn_sequence(seq: TurnSequence, indent: Optional[int] = None) -> str:
    """将 TurnSequence 序列化为 JSON 字符串"""
    d = _dataclass_to_dict(seq)
    return json.dumps(d, ensure_ascii=False, indent=indent)


def save_turn_sequence(seq: TurnSequence, output_path: Path) -> None:
    """将 TurnSequence 保存至文件（indent=2 缩进格式，便于人工阅读）"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    d = _dataclass_to_dict(seq)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
        f.write("\n")


def save_events_jsonl(events: List[AtomicEvent], output_path: Path) -> None:
    """将 AtomicEvent 列表以每行一个 JSON 的 JSONL 格式保存（便于流式处理）"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for event in events:
            d = _dataclass_to_dict(event)
            json.dump(d, f, ensure_ascii=False)
            f.write("\n")


# ─────────────────────────────────────────────────────────────────────────────
# 反序列化辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _parse_datetime(v: Any) -> Optional[datetime]:
    """将字符串解析为 datetime，容错处理多种 ISO 8601 格式"""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    try:
        # Python 3.11+ 支持 fromisoformat 处理带 timezone 的字符串
        return datetime.fromisoformat(str(v))
    except ValueError:
        # 降级处理
        import re
        # 去掉 timezone 偏移后再解析
        s = re.sub(r'[+-]\d{2}:\d{2}$', '', str(v))
        return datetime.fromisoformat(s)


def deserialize_turn_sequence(data: Dict[str, Any]) -> TurnSequence:
    """从字典反序列化 TurnSequence（用于从 JSONL 文件加载已处理数据）"""
    meta_d = data.get("metadata", {})
    metadata = SessionMetadata(
        session_id=meta_d.get("session_id", ""),
        start_time=_parse_datetime(meta_d.get("start_time")),
        end_time=_parse_datetime(meta_d.get("end_time")),
        timing_metrics=meta_d.get("timing_metrics", {}),
        total_cost=float(meta_d.get("total_cost", 0.0)),
        target_raw=meta_d.get("target_raw"),
        source_file=meta_d.get("source_file"),
        log_filename=meta_d.get("log_filename"),
        session_end_type=meta_d.get("session_end_type", "unknown"),
    )

    turns = [_deserialize_turn(t) for t in data.get("turns", [])]
    all_events = [_deserialize_atomic_event(e) for e in data.get("all_events", [])]

    rag_index: Dict[str, RagQueryRecord] = {}
    for v in data.get("rag_index", {}).values():
        rq = _deserialize_rag_query(v)
        rag_index[rq.tool_call_id] = rq

    return TurnSequence(
        metadata=metadata,
        turns=turns,
        all_events=all_events,
        rag_index=rag_index,
    )


def _deserialize_turn(d: Dict[str, Any]) -> Turn:
    events = [_deserialize_atomic_event(e) for e in d.get("events", [])]
    rag_queries = [_deserialize_rag_query(r) for r in d.get("rag_queries", [])]
    return Turn(
        turn_index=int(d.get("turn_index", 0)),
        timestamp=_parse_datetime(d.get("timestamp")),
        session_id=d.get("session_id", ""),
        assistant_message=d.get("assistant_message"),
        api_request=d.get("api_request"),
        completion=d.get("completion"),
        events=events,
        rag_queries=rag_queries,
    )


def _deserialize_call_descriptor(d: Dict[str, Any]) -> CallDescriptor:
    return CallDescriptor(
        tool_name=d.get("tool_name", ""),
        call_args=d.get("call_args", {}),
        call_timestamp=_parse_datetime(d.get("call_timestamp")),
        tool_call_id=d.get("tool_call_id", ""),
        action_category=ActionCategory(d.get("action_category", "STRUCTURED_TOOL_CALL")),
        program_name=d.get("program_name"),
        code_filename=d.get("code_filename"),
        code_language=d.get("code_language"),
    )


def _deserialize_result_descriptor(d: Optional[Dict[str, Any]]) -> Optional[ResultDescriptor]:
    if d is None:
        return None
    return ResultDescriptor(
        return_code=d.get("return_code"),
        timed_out=bool(d.get("timed_out", False)),
        success=d.get("success"),
        stderr_raw=d.get("stderr_raw", ""),
        stdout_raw=d.get("stdout_raw", ""),
        partial_results=bool(d.get("partial_results", False)),
        raw_result=d.get("raw_result", {}),
    )


def _deserialize_rag_query(d: Dict[str, Any]) -> RagQueryRecord:
    return RagQueryRecord(
        tool_call_id=d.get("tool_call_id", ""),
        query=d.get("query", ""),
        rag_timestamp=_parse_datetime(d.get("rag_timestamp")),
        turn_index=int(d.get("turn_index", 0)),
        rag_result=d.get("rag_result"),
    )


def _deserialize_atomic_event(d: Dict[str, Any]) -> AtomicEvent:
    return AtomicEvent(
        event_id=d.get("event_id", ""),
        turn_index=int(d.get("turn_index", 0)),
        slot_in_turn=int(d.get("slot_in_turn", 0)),
        call=_deserialize_call_descriptor(d.get("call", {})),
        result=_deserialize_result_descriptor(d.get("result")),
        has_rag_context=bool(d.get("has_rag_context", False)),
        rag_query_ref=d.get("rag_query_ref"),
        code_script_ref=d.get("code_script_ref", []),
    )


def load_turn_sequence(input_path: Path) -> TurnSequence:
    """从已序列化的 JSON 文件加载 TurnSequence（支持单行紧凑格式与多行缩进格式）"""
    with open(input_path, encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            raise ValueError(f"Empty file: {input_path}")
        data = json.loads(content)
    return deserialize_turn_sequence(data)

