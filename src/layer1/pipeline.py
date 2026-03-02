"""
Layer 1 处理流水线（Pipeline）
================================
Phase 2 实现：对 TurnSequence 应用确定性规则，输出 AnnotatedTurnSequence。
Phase 3 扩展：集成 LLM 语义理解（attack_phase / failure_cause / RAG 因果 / session_outcome）。

职责：
    1. 从 Layer 0 输出（TurnSequence）中读取全量原子事件
    2. 对每个事件应用确定性规则（规则层，Phase 2）
    3. 标注 needs_llm 标志（为 Phase 3 LLM 层准备）
    4. （Phase 3）调用 LLM 补充语义标注
    5. 生成 AnnotatedTurnSequence 并可选保存至文件

输入：
    TurnSequence 对象（内存）或 layer0_*.jsonl 文件（磁盘）

输出：
    AnnotatedTurnSequence 对象 / layer1_*.jsonl 文件

技术方案来源：阶段 2：Layer 1 确定性规则实现（失败根因规则部分）
技术方案来源：阶段 3：集成 LLM 进行语义理解
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List, Optional

from ..models import AnnotatedTurnSequence, TurnSequence
from ..utils.config_loader import get_config
from ..utils.log_utils import get_logger
from ..utils.serializer import load_turn_sequence
from .deterministic_rules import annotate_event

logger = get_logger(__name__)


def run_layer1(seq: TurnSequence) -> AnnotatedTurnSequence:
    """对单个 TurnSequence 应用 Layer 1 规则层处理。

    Phase 2 实现：
        - 确定性规则：RC-127 / RC-126 / TOUT
        - needs_llm 标注

    Args:
        seq: Layer 0 输出的 TurnSequence

    Returns:
        AnnotatedTurnSequence（规则层标注完毕，LLM字段留空待 Phase 3）
    """
    annotated_events = []
    deterministic_hits = 0
    llm_pending = 0
    llm_pending_failure_cause = 0

    for event in seq.all_events:
        ann = annotate_event(event)
        annotated_events.append(ann)

        if ann.failure_root_cause is not None:
            deterministic_hits += 1
        if ann.needs_llm:
            llm_pending += 1
        # 失败根因待 LLM 判定：有结果、无确定性根因、且表现为失败
        # （return_code 非 0/None 或 success=False，排除 result=None）
        if (
            ann.base.result is not None
            and ann.failure_root_cause is None
            and (
                (ann.base.result.return_code not in (None, 0))
                or ann.base.result.success is False
            )
        ):
            llm_pending_failure_cause += 1

    result = AnnotatedTurnSequence(
        metadata=seq.metadata,
        annotated_events=annotated_events,
        deterministic_hits=deterministic_hits,
        llm_pending=llm_pending,
        llm_pending_failure_cause=llm_pending_failure_cause,
    )

    logger.debug(
        "[layer1] session=%s events=%d det_hits=%d llm_pending=%d llm_pfc=%d",
        seq.metadata.session_id,
        result.total_events,
        deterministic_hits,
        llm_pending,
        llm_pending_failure_cause,
    )
    return result


def run_layer1_batch(
    input_dir: Path,
    output_dir: Optional[Path] = None,
    save: bool = True,
) -> Iterator[AnnotatedTurnSequence]:
    """批量处理 input_dir 下所有 layer0_*.jsonl 文件。

    Args:
        input_dir : Layer 0 输出目录（含 layer0_{session_id}.jsonl）
        output_dir: Layer 1 输出目录（None 时默认为 input_dir/../layer1_output）
        save      : 是否将结果序列化保存

    Yields:
        每个会话的 AnnotatedTurnSequence
    """
    cfg = get_config()

    if output_dir is None:
        output_dir = input_dir.parent / "layer1_output"

    input_files = sorted(input_dir.glob("layer0_*.jsonl"))
    if not input_files:
        logger.warning("[layer1_batch] No layer0_*.jsonl found in %s", input_dir)
        return

    for log_path in input_files:
        session_id = _extract_session_id(log_path)
        try:
            seq = load_turn_sequence(log_path)
            ann_seq = run_layer1(seq)

            if save:
                out_path = output_dir / f"layer1_{session_id}.jsonl"
                save_annotated_turn_sequence(ann_seq, out_path)
                logger.info("[layer1_batch] saved %s", out_path.name)

            yield ann_seq

        except Exception as exc:
            logger.error("[layer1_batch] Failed %s: %s", log_path.name, exc, exc_info=True)


def run_layer1_with_llm(
    seq: TurnSequence,
    client=None,
) -> AnnotatedTurnSequence:
    """Phase 3 入口：规则层 + LLM 语义理解（完整 Layer 1 流水线）。

    先执行确定性规则（run_layer1），再调用 LLM 补充语义标注。

    Args:
        seq    : Layer 0 TurnSequence
        client : LLMClient 实例；若为 None，则尝试从 configs/config.yaml 构建

    Returns:
        完整 AnnotatedTurnSequence（规则层 + LLM 层）
    """
    from ..llm_client import build_llm_client_from_config
    from .llm_annotator import run_layer1_llm

    ann_seq = run_layer1(seq)

    if client is None:
        try:
            client = build_llm_client_from_config()
        except Exception as exc:
            logger.error(
                "[layer1_with_llm] 无法构建 LLMClient，跳过 LLM 标注: %s", exc
            )
            return ann_seq

    return run_layer1_llm(ann_seq, seq, client)


def run_layer1_llm_batch(
    input_dir: Path,
    output_dir: Optional[Path] = None,
    client=None,
    save: bool = True,
) -> Iterator[AnnotatedTurnSequence]:
    """批量执行完整 Layer 1（规则 + LLM）流水线。

    Args:
        input_dir : Layer 0 输出目录（含 layer0_{session_id}.jsonl）
        output_dir: Layer 1 输出目录（None 时默认为 input_dir/../layer1_output）
        client    : LLMClient 实例；None 时从配置文件自动构建
        save      : 是否保存结果

    Yields:
        每个会话的 AnnotatedTurnSequence（含 LLM 标注字段）
    """
    from ..llm_client import build_llm_client_from_config

    if output_dir is None:
        output_dir = input_dir.parent / "layer1_output"

    if client is None:
        try:
            client = build_llm_client_from_config()
        except Exception as exc:
            logger.error(
                "[layer1_llm_batch] 无法构建 LLMClient，终止批量 LLM 任务: %s", exc
            )
            return

    input_files = sorted(input_dir.glob("layer0_*.jsonl"))
    if not input_files:
        logger.warning("[layer1_llm_batch] No layer0_*.jsonl found in %s", input_dir)
        return

    total = len(input_files)
    for i, log_path in enumerate(input_files, 1):
        session_id = _extract_session_id(log_path)
        logger.info("[layer1_llm_batch] [%d/%d] processing %s", i, total, log_path.name)
        try:
            seq = load_turn_sequence(log_path)
            ann_seq = run_layer1_with_llm(seq, client=client)

            if save:
                out_path = output_dir / f"layer1_{session_id}.jsonl"
                save_annotated_turn_sequence(ann_seq, out_path)
                logger.info("[layer1_llm_batch] saved %s", out_path.name)

            yield ann_seq

        except Exception as exc:
            logger.error(
                "[layer1_llm_batch] Failed %s: %s", log_path.name, exc, exc_info=True
            )


def _extract_session_id(path: Path) -> str:
    """从 layer0_{session_id}.jsonl 中提取 session_id。"""
    stem = path.stem  # e.g. "layer0_abc123"
    if stem.startswith("layer0_"):
        return stem[len("layer0_"):]
    return stem


# ─────────────────────────────────────────────────────────────────────────────
# AnnotatedTurnSequence 序列化（简单版，仅用于 Phase 2 持久化）
# ─────────────────────────────────────────────────────────────────────────────

def _to_dict(obj) -> dict:
    """递归将 AnnotatedTurnSequence 转为可 JSON 序列化的字典。"""
    from dataclasses import fields, is_dataclass
    from datetime import datetime
    from enum import Enum

    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def save_annotated_turn_sequence(ann_seq: AnnotatedTurnSequence, output_path: Path) -> None:
    """将 AnnotatedTurnSequence 序列化保存至 JSONL 文件。"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    d = _to_dict(ann_seq)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)
        f.write("\n")


def load_annotated_turn_sequence(input_path: Path) -> AnnotatedTurnSequence:
    """从 layer1_*.jsonl 文件反序列化 AnnotatedTurnSequence（支持 Phase 2 & 3）。"""
    from ..utils.serializer import (
        _deserialize_atomic_event,
        _deserialize_rag_query,
        _parse_datetime,
        deserialize_turn_sequence,
    )
    from ..models import (
        AnnotatedEvent,
        AnnotatedTurnSequence,
        FailureRootCause,
        FailureRootCauseDimension,
        RagAdoptionResult,
        SessionOutcome,
        SessionMetadata,
    )

    with open(input_path, encoding="utf-8") as f:
        data = json.loads(f.readline().strip())

    # 元数据
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

    def _deser_failure(d) -> Optional[FailureRootCause]:
        if d is None:
            return None
        return FailureRootCause(
            dimension=FailureRootCauseDimension(d["dimension"]),
            sub_dimension=d.get("sub_dimension", ""),
            evidence=d.get("evidence", ""),
            source=d.get("source", "rule"),
            remediation_hint=d.get("remediation_hint"),
            reasoning=d.get("reasoning"),
        )

    annotated_events = []
    for ae_d in data.get("annotated_events", []):
        base = _deserialize_atomic_event(ae_d.get("base", {}))
        annotated_events.append(AnnotatedEvent(
            base=base,
            failure_root_cause=_deser_failure(ae_d.get("failure_root_cause")),
            attack_phase=ae_d.get("attack_phase"),
            outcome_label=ae_d.get("outcome_label"),
            rule_applied=ae_d.get("rule_applied"),
            needs_llm=bool(ae_d.get("needs_llm", False)),
            # Phase 3 新字段
            attack_phase_reasoning=ae_d.get("attack_phase_reasoning"),
            rag_adoption=ae_d.get("rag_adoption"),
            rag_adoption_reasoning=ae_d.get("rag_adoption_reasoning"),
            llm_error=ae_d.get("llm_error"),
        ))

    # Phase 3：反序列化 rag_adoption_results
    rar_list = []
    for r in data.get("rag_adoption_results", []):
        rar_list.append(RagAdoptionResult(
            rag_tool_call_id=r.get("rag_tool_call_id", ""),
            query=r.get("query", ""),
            rag_turn_index=int(r.get("rag_turn_index", 0)),
            adoption_level=int(r.get("adoption_level", 0)),
            adoption_label=r.get("adoption_label", "ignored"),
            adoption_weight=float(r.get("adoption_weight", 0.0)),
            reasoning=r.get("reasoning", ""),
            behavior_window=r.get("behavior_window", []),
        ))

    # Phase 3：反序列化 session_outcome
    so_d = data.get("session_outcome")
    session_outcome = None
    if so_d:
        session_outcome = SessionOutcome(
            is_success=bool(so_d.get("is_success", False)),
            outcome_label=so_d.get("outcome_label", "failure"),
            session_goal_achieved=bool(so_d.get("session_goal_achieved", False)),
            achieved_goals=so_d.get("achieved_goals", []),
            failed_goals=so_d.get("failed_goals", []),
            bar_score=float(so_d.get("bar_score", 0.0)),
            reasoning=so_d.get("reasoning", ""),
            key_signals=so_d.get("key_signals", []),  # P2修复
        )

    return AnnotatedTurnSequence(
        metadata=metadata,
        annotated_events=annotated_events,
        deterministic_hits=int(data.get("deterministic_hits", 0)),
        llm_pending=int(data.get("llm_pending", 0)),
        llm_pending_failure_cause=int(data.get("llm_pending_failure_cause", 0)),
        # Phase 3
        rag_adoption_results=rar_list,
        session_outcome=session_outcome,
        bar_score=float(data.get("bar_score", 0.0)),
        llm_processed=bool(data.get("llm_processed", False)),
        llm_call_count=int(data.get("llm_call_count", 0)),
        llm_error_count=int(data.get("llm_error_count", 0)),
    )
