"""
Layer 0 完整流水线（Pipeline）
================================
职责：先通过 AdapterRegistry 自动识别日志格式，再走：
    - CAI 原生路径：LogParser → EventExtractor → TurnSequenceAssembler
    - 非 CAI 路径：LogAdapter.parse(CanonicalAgentTurn) → TurnSequenceAssembler
对单个日志文件或整个日志目录输出 TurnSequence 对象。

这是 Layer 0 的唯一对外入口，Layer 1 仅需调用 run_layer0()。

技术方案对应输入/输出：
    输入：原始日志文件（支持 CAI / LangChain / OpenAI Assistants / Generic JSONL）
    输出：结构化但语义中性的 TurnSequence
          不含任何阶段判断、失败类型、成功/失败标注
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

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
from ..utils.config_loader import Config, get_config
from ..utils.log_utils import get_logger
from ..utils.serializer import save_turn_sequence
from . import adapters as _adapters  # noqa: F401
from .assembler import TurnSequenceAssembler
from .canonical_types import CanonicalAgentTurn, SessionMeta
from .extractor import EventExtractor
from .log_adapter import AdapterRegistry
from .parser import LogParser

logger = get_logger(__name__)


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    text = str(value)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        text = re.sub(r"[+-]\d{2}:\d{2}$", "", text)
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None


def _extract_program_name(command: str) -> Optional[str]:
    if not command:
        return None
    tokens = str(command).strip().split()
    if not tokens:
        return None
    wrappers = {"sudo", "env", "time", "nice", "ionice", "strace", "ltrace", "timeout", "nohup"}
    skip_numeric = False
    for tok in tokens:
        if skip_numeric:
            skip_numeric = False
            if re.match(r"^\d+(\.\d+)?$", tok):
                continue
        base = tok.split("/")[-1]
        if base in wrappers:
            if base in {"timeout", "nice", "ionice"}:
                skip_numeric = True
            continue
        if re.match(r"^-", base) or re.match(r"^[A-Z_]+=", base):
            continue
        return base
    return tokens[0].split("/")[-1]


def _resolve_action_category(cfg: Config, ct: CanonicalAgentTurn) -> ActionCategory:
    if ct.rag_info is not None:
        return ActionCategory.RAG_QUERY
    try:
        return ActionCategory(cfg.classify_tool(ct.tool_name))
    except ValueError:
        return ActionCategory.STRUCTURED_TOOL_CALL


def _build_sequence_from_canonical(
    adapter_meta: SessionMeta,
    canonical_turns: Iterator[CanonicalAgentTurn],
    log_path: Path,
    cfg: Config,
) -> TurnSequence:
    turns_by_index: Dict[int, Turn] = {}
    session_id = adapter_meta.session_id or log_path.stem

    for ct in canonical_turns:
        session_id = ct.session_id or session_id
        turn_ts = _parse_iso_datetime(ct.timestamp) or datetime.utcnow()

        turn = turns_by_index.get(ct.turn_index)
        if turn is None:
            turn = Turn(
                turn_index=ct.turn_index,
                timestamp=turn_ts,
                session_id=session_id,
                assistant_message={"tool_calls": []},
                api_request={"_tool_results": {}},
                completion=None,
            )
            turns_by_index[ct.turn_index] = turn
        elif turn_ts < turn.timestamp:
            turn.timestamp = turn_ts

        tool_args: Dict[str, Any] = ct.tool_args if isinstance(ct.tool_args, dict) else {}
        tool_call_id = str(
            ct.raw_metadata.get("call_id")
            or ct.raw_metadata.get("tool_call_id")
            or f"{session_id}_{ct.turn_index}_{ct.slot_in_turn}"
        )

        try:
            args_json = json.dumps(tool_args, ensure_ascii=False, default=str)
        except TypeError:
            args_json = json.dumps({"_raw": str(tool_args)}, ensure_ascii=False)

        assistant_message = turn.assistant_message if isinstance(turn.assistant_message, dict) else {}
        assistant_message.setdefault("tool_calls", []).append({
            "id": tool_call_id,
            "type": "function",
            "function": {
                "name": ct.tool_name,
                "arguments": args_json,
            },
        })
        turn.assistant_message = assistant_message

        api_request = turn.api_request if isinstance(turn.api_request, dict) else {}
        api_request.setdefault("_tool_results", {})[tool_call_id] = {
            "return_code": ct.return_code,
            "timed_out": bool(ct.timed_out),
            "success": ct.success,
            "stdout": ct.stdout or "",
            "stderr": ct.stderr or "",
            "_raw_text": ct.stdout or "",
        }
        turn.api_request = api_request

        category = _resolve_action_category(cfg, ct)
        program_name = None
        code_filename = None
        code_language = None
        if category == ActionCategory.GENERIC_COMMAND_CALL:
            program_name = _extract_program_name(str(tool_args.get("command", "")))
        elif category == ActionCategory.CODE_WRITE:
            code_filename = tool_args.get("filename")
            code_language = tool_args.get("language")

        call_desc = CallDescriptor(
            tool_name=ct.tool_name,
            call_args=tool_args,
            call_timestamp=turn_ts,
            tool_call_id=tool_call_id,
            action_category=category,
            program_name=program_name,
            code_filename=code_filename,
            code_language=code_language,
        )

        result_desc = ResultDescriptor(
            return_code=ct.return_code,
            timed_out=bool(ct.timed_out),
            success=ct.success,
            stderr_raw=ct.stderr or "",
            stdout_raw=ct.stdout or "",
            partial_results=False,
            raw_result=dict(ct.raw_metadata or {}),
        )

        event = AtomicEvent(
            event_id=f"{session_id}_{ct.turn_index:04d}_{ct.slot_in_turn:02d}",
            turn_index=ct.turn_index,
            slot_in_turn=ct.slot_in_turn,
            call=call_desc,
            result=result_desc,
        )
        turn.events.append(event)

        if category == ActionCategory.RAG_QUERY:
            rag_query = ""
            rag_result = ct.stdout or ""
            if ct.rag_info is not None:
                rag_query = ct.rag_info.query
                rag_result = ct.rag_info.results_raw or rag_result
            if not rag_query:
                rag_query = str(tool_args.get("query") or tool_args.get("input") or "")
            turn.rag_queries.append(
                RagQueryRecord(
                    tool_call_id=tool_call_id,
                    query=rag_query,
                    rag_timestamp=turn_ts,
                    turn_index=ct.turn_index,
                    rag_result=rag_result or None,
                )
            )

    turns = [turns_by_index[idx] for idx in sorted(turns_by_index)]
    start_time = _parse_iso_datetime(adapter_meta.start_time)
    if start_time is None:
        start_time = turns[0].timestamp if turns else datetime.utcnow()

    metadata = SessionMetadata(
        session_id=session_id,
        start_time=start_time,
        end_time=_parse_iso_datetime(adapter_meta.end_time),
        timing_metrics=(
            adapter_meta.raw_metadata.get("timing_metrics", {})
            if isinstance(adapter_meta.raw_metadata, dict)
            else {}
        ),
        total_cost=float(getattr(adapter_meta, "total_cost", 0.0) or 0.0),
        target_raw=getattr(adapter_meta, "target_raw", None),
        source_file=str(log_path),
        log_filename=log_path.name,
        session_end_type=adapter_meta.session_end_type or "unknown",
    )

    assembler = TurnSequenceAssembler(cfg)
    return assembler.assemble(metadata, turns)


def run_layer0(
    log_path: Path,
    config: Optional[Config] = None,
) -> TurnSequence:
    """对单个 JSONL 日志文件执行完整的 Layer 0 处理流水线。

    Args:
        log_path: 原始 JSONL 日志文件路径
        config  : 配置对象（None 时使用全局默认配置）

    Returns:
        完整的 TurnSequence（语义中性，供 Layer 1 消费）
    """
    cfg = config or get_config()

    adapter = AdapterRegistry.auto_detect(log_path)
    logger.info("Layer 0 adapter selected: %s (%s)", adapter.adapter_name, log_path.name)

    # CAI 走原生 parser/extractor 路径，保持与既有行为一致。
    if adapter.adapter_name == "cai":
        parser = LogParser(cfg)
        extractor = EventExtractor(cfg)
        assembler = TurnSequenceAssembler(cfg)

        metadata, turns = parser.parse_file(log_path)
        for turn in turns:
            events, rag_queries = extractor.extract(turn)
            turn.events = events
            turn.rag_queries = rag_queries
        return assembler.assemble(metadata, turns)

    adapter_meta, canonical_turns = adapter.parse(log_path)
    return _build_sequence_from_canonical(adapter_meta, canonical_turns, log_path, cfg)


def run_layer0_batch(
    log_dir: Path,
    output_dir: Optional[Path] = None,
    config: Optional[Config] = None,
    save: bool = True,
) -> Iterator[TurnSequence]:
    """批量处理日志目录下所有日志文件。

    Args:
        log_dir   : 日志文件目录
        output_dir: 输出目录（None 时使用 config.output_dir）
        config    : 配置对象
        save      : 是否将每个 TurnSequence 序列化保存

    Yields:
        TurnSequence（每文件一个）
    """
    cfg = config or get_config()

    if output_dir is None:
        # 输出目录相对于日志目录
        output_dir = log_dir.parent / "data" / "processed"

    pattern = cfg.log_glob
    files = sorted(log_dir.glob(pattern))
    logger.info("Layer 0 batch: found %d files in %s", len(files), log_dir)

    for log_path in files:
        try:
            logger.info("Processing: %s", log_path.name)

            sequence = run_layer0(log_path, cfg)

            if save:
                filename = cfg.output_filename_template.format(
                    session_id=sequence.metadata.session_id
                )
                out_path = output_dir / filename
                save_turn_sequence(sequence, out_path)
                logger.info(
                    "Saved: %s  (turns=%d, events=%d)",
                    out_path.name, sequence.turn_count, sequence.event_count,
                )

            yield sequence

        except Exception as exc:
            logger.error("Failed to process %s: %s", log_path.name, exc, exc_info=True)
