"""
Layer 1 LLM 标注器（Phase 3）
==============================
职责：对 Phase 2 规则层输出的 AnnotatedTurnSequence，补充 LLM 语义标注：

  任务 A：attack_phase / outcome_label     → 全量事件（含 result=None）
  任务 B：failure_root_cause（LLM 兜底）   → llm_pending_failure_cause 事件
  任务 C：RAG 行为因果判定                 → has_rag_context=true 的 RAG 查询
  任务 D：会话整体目标达成判定             → 每个 session 执行一次

调用入口：
    annotate_with_llm(ann_seq, seq, client) → AnnotatedTurnSequence
    run_layer1_llm(ann_seq, seq, client)    → 同上（别名，接口统一）

设计原则：
  - 每个 LLM 任务独立可重试
  - 任意任务失败不阻断其他任务（记录 llm_error 字段后继续）
  - 结果就地更新 AnnotatedEvent 字段，不修改 base（Layer 0 数据只读）
  - 所有 prompt 在 src/prompts.py 中集中管理
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..llm_client import LLMClient
from ..models import (
    ActionCategory,
    AnnotatedEvent,
    AnnotatedTurnSequence,
    AttackPhase,
    FailureRootCause,
    FailureRootCauseDimension,
    SessionOutcome,
    TurnSequence,
)
from ..prompts import (
    ATTACK_PHASE_SYSTEM,
    FAILURE_CAUSE_SYSTEM,
    SESSION_OUTCOME_SYSTEM,
    build_attack_phase_prompt,
    build_failure_cause_prompt,
    build_session_outcome_prompt,
)
from ..utils.log_utils import get_logger

logger = get_logger(__name__)

# 有效的 attack_phase 标签集合（用于校验 LLM 输出）
_VALID_ATTACK_PHASES = {e.value for e in AttackPhase}
# 有效的 outcome_label
_VALID_OUTCOMES = {"success", "partial_success", "failure", "timeout", "unknown"}


# ─────────────────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────────────────

def annotate_with_llm(
    ann_seq: AnnotatedTurnSequence,
    seq: TurnSequence,
    client: LLMClient,
) -> AnnotatedTurnSequence:
    """Phase 3 主入口：对 AnnotatedTurnSequence 补充 LLM 语义标注。

    按顧序执行三个子任务：
        A. 全量 attack_phase / outcome_label 分类
        B. 失败根因 LLM 兄底（针对 llm_pending_failure_cause 事件）
        C. 会话整体目标达成判定

    Args:
        ann_seq : Phase 2 规则层输出（会被就地修改并返回）
        seq     : 对应的 Layer 0 TurnSequence（只读，提供 RAG 索引）
        client  : LLMClient 实例

    Returns:
        更新了 Phase 3 字段的 AnnotatedTurnSequence（同一对象）
    """
    target_info = seq.metadata.target_raw
    session_id = seq.metadata.session_id
    llm_call_count = 0
    llm_error_count = 0

    logger.info(
        "[llm_annotator] session=%s events=%d pfc=%d rag_queries=%d",
        session_id, ann_seq.total_events,
        ann_seq.llm_pending_failure_cause, len(seq.rag_index),
    )

    # ── 任务 A：全量 attack_phase / outcome_label ─────────────────────────────
    for ann_event in ann_seq.annotated_events:
        c, e = _run_attack_phase(ann_event, client, target_info)
        llm_call_count += c
        llm_error_count += e

    # ── 任务 B：失败根因 LLM 兜底 ────────────────────────────────────────────
    for ann_event in ann_seq.annotated_events:
        if _needs_failure_cause_llm(ann_event):
            c, e = _run_failure_cause(ann_event, client, target_info)
            llm_call_count += c
            llm_error_count += e

    # ── 任务 C：会话整体目标达成判定 ─────────────────────────────────────────
    outcome, c, e = _run_session_outcome(ann_seq, seq, client)
    llm_call_count += c
    llm_error_count += e
    if outcome:
        ann_seq.session_outcome = outcome

    ann_seq.llm_processed = True
    ann_seq.llm_call_count = llm_call_count
    ann_seq.llm_error_count = llm_error_count

    logger.info(
        "[llm_annotator] DONE session=%s llm_calls=%d errors=%d outcome=%s",
        session_id, llm_call_count, llm_error_count,
        ann_seq.session_outcome.outcome_label if ann_seq.session_outcome else "N/A",
    )
    return ann_seq


# 别名，与 pipeline.py 的调用接口保持一致
run_layer1_llm = annotate_with_llm


# ─────────────────────────────────────────────────────────────────────────────
# 子任务 A：attack_phase / outcome_label
# ─────────────────────────────────────────────────────────────────────────────

def _run_attack_phase(
    ann_event: AnnotatedEvent,
    client: LLMClient,
    target_info: Optional[str],
) -> tuple[int, int]:
    """为单个事件填充 attack_phase 和 outcome_label。返回 (call_count, error_count)。"""
    call = ann_event.base.call
    result = ann_event.base.result
    has_result = result is not None

    raw_text = ""
    if has_result and result.raw_result:
        raw_text = (result.raw_result or {}).get("_raw_text", "") or ""

    user_prompt = build_attack_phase_prompt(
        tool_name=call.tool_name,
        call_args=call.call_args,
        action_category=call.action_category.value,
        return_code=result.return_code if has_result else None,
        success=result.success if has_result else None,
        timed_out=result.timed_out if has_result else False,
        stderr_raw=result.stderr_raw if has_result else "",
        stdout_raw=result.stdout_raw if has_result else "",
        has_result=has_result,
        target_info=target_info,
        program_name=call.program_name,
        raw_text=raw_text,
    )

    llm_result = client.chat_json(
        [{"role": "user", "content": user_prompt}],
        system=ATTACK_PHASE_SYSTEM,
    )

    if not llm_result.success or llm_result.parsed is None:
        ann_event.llm_error = f"attack_phase: {llm_result.error}"
        logger.warning(
            "[llm_annotator] attack_phase FAILED event=%s: %s",
            ann_event.event_id, llm_result.error,
        )
        return 1, 1

    parsed = llm_result.parsed
    phase = parsed.get("attack_phase", "")
    outcome = parsed.get("outcome_label", "unknown")

    # 校验并回填
    ann_event.attack_phase = phase if phase in _VALID_ATTACK_PHASES else "ENV_PREPARATION"
    ann_event.outcome_label = outcome if outcome in _VALID_OUTCOMES else "unknown"
    ann_event.attack_phase_reasoning = parsed.get("reasoning", "")

    logger.debug(
        "[llm_annotator] attack_phase event=%s phase=%s outcome=%s",
        ann_event.event_id, ann_event.attack_phase, ann_event.outcome_label,
    )
    return 1, 0


# ─────────────────────────────────────────────────────────────────────────────
# 子任务 B：失败根因 LLM 兜底
# ─────────────────────────────────────────────────────────────────────────────

def _needs_failure_cause_llm(ann_event: AnnotatedEvent) -> bool:
    """判断事件是否需要 LLM 做失败根因分析。"""
    result = ann_event.base.result
    if result is None:
        return False
    # 规则层已覆盖
    if ann_event.failure_root_cause is not None:
        return False
    # 有失败迹象（return_code 非 0 或 success=False）
    if (result.return_code not in (None, 0)) or (result.success is False):
        return True
    # frc_gap：LLM 已判定为 failure 但 rc/success 均为 None（execute_code 常见情况）
    if ann_event.outcome_label == "failure" and result.return_code is None and result.success is None:
        return True
    # P6修复：工具成功启动（rc=0）但 LLM 判定 outcome=failure
    # （如 sqlmap/nikto 仅输出 banner 无结果，应补充 EFF/INT 级别的 frc）
    if ann_event.outcome_label == "failure" and result.return_code == 0:
        return True
    return False


def _run_failure_cause(
    ann_event: AnnotatedEvent,
    client: LLMClient,
    target_info: Optional[str],
) -> tuple[int, int]:
    """为失败事件补充 LLM 兜底的 failure_root_cause。返回 (call_count, error_count)。"""
    call = ann_event.base.call
    result = ann_event.base.result  # 必不为 None（已由 _needs_failure_cause_llm 保证）

    # 构建近期上下文摘要（attack_phase 如果已填充，作为上下文）
    ctx = f"当前事件 attack_phase={ann_event.attack_phase}" if ann_event.attack_phase else None

    raw_text = (result.raw_result or {}).get("_raw_text", "") or ""

    user_prompt = build_failure_cause_prompt(
        tool_name=call.tool_name,
        call_args=call.call_args,
        return_code=result.return_code,
        stderr_raw=result.stderr_raw,
        stdout_raw=result.stdout_raw,
        success=result.success,
        target_info=target_info,
        context_summary=ctx,
        raw_text=raw_text,
    )

    llm_result = client.chat_json(
        [{"role": "user", "content": user_prompt}],
        system=FAILURE_CAUSE_SYSTEM,
    )

    if not llm_result.success or llm_result.parsed is None:
        ann_event.llm_error = (ann_event.llm_error or "") + f" | failure_cause: {llm_result.error}"
        logger.warning(
            "[llm_annotator] failure_cause FAILED event=%s: %s",
            ann_event.event_id, llm_result.error,
        )
        return 1, 1

    total_calls = 1
    parsed = llm_result.parsed

    # 若 reasoning 为空，重试一次
    if not parsed.get("reasoning", "").strip():
        logger.debug(
            "[llm_annotator] failure_cause reasoning empty, retrying event=%s",
            ann_event.event_id,
        )
        retry_prompt = (
            user_prompt
            + "\n\n【重要提醒】上次输出的 reasoning 字段为空，不符合要求。"
            "请重新输出并确保 reasoning 包含 50-150 字的具体分析推理过程。"
        )
        retry_result = client.chat_json(
            [{"role": "user", "content": retry_prompt}],
            system=FAILURE_CAUSE_SYSTEM,
        )
        total_calls += 1
        if (
            retry_result.success
            and retry_result.parsed
            and retry_result.parsed.get("reasoning", "").strip()
        ):
            parsed = retry_result.parsed

    dim_str = parsed.get("dimension", "ENV")
    try:
        dim = FailureRootCauseDimension(dim_str)
    except ValueError:
        dim = FailureRootCauseDimension.ENV

    # 提取 search_queries：仅保留纯英文、长度 > 8 的条目（防止 LLM 输出中文或空值）
    import re as _re_sq
    raw_sq = parsed.get("search_queries") or []
    search_queries = [
        q.strip() for q in raw_sq
        if isinstance(q, str)
        and q.strip()
        and not _re_sq.search(r"[\u4e00-\u9fff]", q)
        and len(q.strip()) > 8
    ][:4]

    ann_event.failure_root_cause = FailureRootCause(
        dimension=dim,
        sub_dimension=parsed.get("sub_dimension", "UNKNOWN"),
        evidence=parsed.get("evidence", "LLM 判定"),
        source="llm",
        remediation_hint=parsed.get("remediation_hint"),
        reasoning=parsed.get("reasoning", ""),
        search_queries=search_queries,
    )

    logger.debug(
        "[llm_annotator] failure_cause event=%s dim=%s sub=%s",
        ann_event.event_id, dim.value, ann_event.failure_root_cause.sub_dimension,
    )
    return total_calls, 0


# ─────────────────────────────────────────────────────────────────────────────
# 子任务 C：会话整体目标达成判定
# ─────────────────────────────────────────────────────────────────────────────

def _run_session_outcome(
    ann_seq: AnnotatedTurnSequence,
    seq: TurnSequence,
    client: LLMClient,
) -> tuple[Optional[SessionOutcome], int, int]:
    """执行会话整体目标达成判定。返回 (SessionOutcome|None, call_count, error_count)。"""
    # 构建事件摘要（只取关键字段，避免 prompt 过长）
    events_summary = []
    for ann_ev in ann_seq.annotated_events:
        stdout_hint = ""
        key_signals: list[str] = []
        if ann_ev.base.result:
            stdout_raw = ann_ev.base.result.stdout_raw or ""
            raw_text = (ann_ev.base.result.raw_result or {}).get("_raw_text", "") or ""
            full_output = stdout_raw or raw_text
            stdout_hint = full_output[:250]  # 截断250字符供prompt展示
            # 从完整输出中提取强成功信号（仅命令回显类，不受截断影响）
            # 注意：whoami/'# ' 可能出现在 exploit 代码文本中，不作为信号
            _STRONG_SIGNALS = ["uid=0", "root@", "flag{"]
            for sig in _STRONG_SIGNALS:
                if sig in full_output:
                    key_signals.append(sig)
        # 失败根因维度（用于 session_outcome 判断：多个 DEF/PATCHED → failure）
        frc_dim = ""
        if ann_ev.failure_root_cause:
            frc_dim = ann_ev.failure_root_cause.dimension.value if ann_ev.failure_root_cause.dimension else ""
        events_summary.append({
            "tool_name": ann_ev.base.call.tool_name,
            "attack_phase": ann_ev.attack_phase or "?",
            "outcome_label": ann_ev.outcome_label or "?",
            "stdout_hint": stdout_hint,
            "key_signals": key_signals,  # 强成功信号列表（来自完整输出，不受截断影响）
            "frc_dim": frc_dim,          # 失败根因维度（DEF=目标有防御/已打补丁）
        })

    user_prompt = build_session_outcome_prompt(
        target_info=seq.metadata.target_raw,
        session_end_type=seq.metadata.session_end_type,
        total_events=ann_seq.total_events,
        events_summary=events_summary,
        deterministic_hits=ann_seq.deterministic_hits,
    )

    llm_result = client.chat_json(
        [{"role": "user", "content": user_prompt}],
        system=SESSION_OUTCOME_SYSTEM,
    )

    if not llm_result.success or llm_result.parsed is None:
        logger.warning(
            "[llm_annotator] session_outcome FAILED session=%s: %s",
            seq.metadata.session_id, llm_result.error,
        )
        return None, 1, 1

    parsed = llm_result.parsed
    # P2修复：聚合所有事件的 key_signals（去重保序）
    all_key_signals: list[str] = []
    seen_signals: set[str] = set()
    for ev in events_summary:
        for sig in ev.get("key_signals", []):
            if sig not in seen_signals:
                seen_signals.add(sig)
                all_key_signals.append(sig)
    outcome = SessionOutcome(
        is_success=bool(parsed.get("is_success", False)),
        outcome_label=parsed.get("outcome_label", "failure"),
        session_goal_achieved=bool(parsed.get("session_goal_achieved", False)),
        achieved_goals=parsed.get("achieved_goals", []),
        failed_goals=parsed.get("failed_goals", []),
        reasoning=parsed.get("reasoning", ""),
        key_signals=all_key_signals,
    )

    logger.info(
        "[llm_annotator] session_outcome session=%s is_success=%s label=%s",
        seq.metadata.session_id, outcome.is_success, outcome.outcome_label,
    )
    return outcome, 1, 0
