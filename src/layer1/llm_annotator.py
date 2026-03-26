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
import re
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
from .. import prompts as prompt_lib
from ..utils.log_utils import get_logger

logger = get_logger(__name__)

ATTACK_PHASE_SYSTEM = getattr(prompt_lib, "ATTACK_PHASE_SYSTEM", "")
FAILURE_CAUSE_SYSTEM = getattr(prompt_lib, "FAILURE_CAUSE_SYSTEM", "")
SESSION_OUTCOME_SYSTEM = getattr(prompt_lib, "SESSION_OUTCOME_SYSTEM", "")
build_attack_phase_prompt = getattr(prompt_lib, "build_attack_phase_prompt")
build_failure_cause_prompt = getattr(prompt_lib, "build_failure_cause_prompt")
build_session_outcome_prompt = getattr(prompt_lib, "build_session_outcome_prompt")

# 有效的 attack_phase 标签集合（用于校验 LLM 输出）
_VALID_ATTACK_PHASES = {e.value for e in AttackPhase}
# 有效的 outcome_label
_VALID_OUTCOMES = {"success", "partial_success", "failure", "timeout", "uncertain", "unknown"}

_HARD_SUCCESS_PATTERNS = (
    re.compile(r"uid\s*=\s*0", re.IGNORECASE),
    re.compile(r"root@", re.IGNORECASE),
    re.compile(r"flag\s*\{", re.IGNORECASE),
    re.compile(r"successfully\s+read\s+/etc/passwd", re.IGNORECASE),
    re.compile(r"access\s+granted", re.IGNORECASE),
    re.compile(r"authentication\s+successful", re.IGNORECASE),
)

_TIMEOUT_PATTERNS = (
    re.compile(r"\btime(?:d)?\s*out\b", re.IGNORECASE),
    re.compile(r"read\s+timeout", re.IGNORECASE),
    re.compile(r"connection\s+timeout", re.IGNORECASE),
    re.compile(r"deadline\s+exceeded", re.IGNORECASE),
)

_HARD_FAILURE_TOKENS = (
    "connection refused",
    "permission denied",
    "access denied",
    "command not found",
    "no such file",
    "not found",
    "authentication failed",
    "401 unauthorized",
    "403 forbidden",
    "status code: 500",
    "status code: 403",
    "status code: 401",
    "http/1.1 500",
    "http/1.1 403",
    "traceback",
    "exception",
    "not vulnerable",
    "already patched",
    "errors occurred",
)

_HARD_FAILURE_PATTERNS = tuple(
    re.compile(re.escape(token), re.IGNORECASE)
    for token in _HARD_FAILURE_TOKENS
) + (
    re.compile(r"\bstatus\s+code\s*[:=]?\s*(?:401|403|404|500)\b", re.IGNORECASE),
    re.compile(r"\bhttp/\d(?:\.\d)?\s+(?:401|403|404|500)\b", re.IGNORECASE),
    re.compile(r"\b(?:401|403|404|500)\b", re.IGNORECASE),
    re.compile(r"(?<!no\s)\b(?:error|errors|failed|failure)\b", re.IGNORECASE),
)

_RECON_PROGRAM_HINTS = {
    "nmap", "whatweb", "nikto", "gobuster", "dirb", "ffuf", "wfuzz", "masscan",
    "enum4linux", "netdiscover", "curl", "wget",
}

_EXPLOIT_PROGRAM_HINTS = {
    "sqlmap", "msfconsole", "hydra", "john", "hashcat", "python", "python3", "perl",
}


def _collect_result_text(ann_event: AnnotatedEvent) -> str:
    """聚合结果文本，用于 outcome 的证据判定。"""
    result = ann_event.base.result
    if result is None:
        return ""
    raw_text = ""
    if result.raw_result:
        raw_text = (result.raw_result or {}).get("_raw_text", "") or ""
    return "\n".join(
        part for part in [result.stdout_raw or "", result.stderr_raw or "", raw_text] if part
    )


def _has_hard_success_signal(text: str) -> bool:
    return any(p.search(text) for p in _HARD_SUCCESS_PATTERNS)


def _has_timeout_signal(text: str) -> bool:
    return any(p.search(text) for p in _TIMEOUT_PATTERNS)


def _has_hard_failure_signal(text: str) -> bool:
    return any(p.search(text) for p in _HARD_FAILURE_PATTERNS)


def _judge_outcome(ann_event: AnnotatedEvent) -> str:
    """基于确定性证据判定 outcome，优先避免 success=None 场景被误标失败。"""
    result = ann_event.base.result
    if result is None:
        return "uncertain"

    result_text = _collect_result_text(ann_event)

    if result.timed_out or _has_timeout_signal(result_text):
        return "timeout"

    has_success_signal = _has_hard_success_signal(result_text)
    has_failure_signal = _has_hard_failure_signal(result_text)

    if has_success_signal and not has_failure_signal:
        return "partial_success"

    if has_failure_signal and not has_success_signal:
        return "failure"

    if has_success_signal and has_failure_signal:
        return "partial_success"

    if (result.success is True or result.return_code == 0) and not has_failure_signal:
        return "success"

    if result.success is False or (result.return_code is not None and result.return_code != 0):
        return "failure"

    if has_failure_signal:
        return "failure"

    return "uncertain"


def _fallback_attack_phase(ann_event: AnnotatedEvent) -> str:
    """当 LLM 不可用时，根据结构信号给出保守 phase 兜底。"""
    call = ann_event.base.call

    if call.action_category == ActionCategory.RAG_QUERY:
        return AttackPhase.RECON_WEAPONIZATION.value

    if call.action_category == ActionCategory.CODE_WRITE:
        code_text = (call.call_args or {}).get("code", "") or ""
        if re.search(r"\b(cve-\d{4}-\d+|exploit|payload|reverse\s*shell|rce)\b", code_text, re.IGNORECASE):
            return AttackPhase.EXPLOITATION.value
        return AttackPhase.RECON_WEAPONIZATION.value

    if call.action_category == ActionCategory.GENERIC_COMMAND_CALL:
        prog = (call.program_name or "").lower()
        if prog in _RECON_PROGRAM_HINTS:
            return AttackPhase.RECON_WEAPONIZATION.value
        if prog in _EXPLOIT_PROGRAM_HINTS:
            return AttackPhase.EXPLOITATION.value
        return AttackPhase.ENV_PREPARATION.value

    # STRUCTURED_TOOL_CALL 缺少语义细节时，保守归类为环境准备
    return AttackPhase.ENV_PREPARATION.value


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

    raw_text = _collect_result_text(ann_event)

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
        fallback_phase = _fallback_attack_phase(ann_event)
        fallback_outcome = _judge_outcome(ann_event)
        ann_event.attack_phase = fallback_phase
        ann_event.outcome_label = fallback_outcome
        ann_event.attack_phase_reasoning = "LLM 调用失败，使用确定性回退策略。"
        ann_event.llm_error = f"attack_phase: {llm_result.error}"
        logger.warning(
            "[llm_annotator] attack_phase FAILED event=%s: %s; fallback=(%s,%s)",
            ann_event.event_id, llm_result.error, fallback_phase, fallback_outcome,
        )
        return 1, 1

    parsed = llm_result.parsed
    phase = parsed.get("attack_phase", "")
    llm_outcome = parsed.get("outcome_label", "unknown")
    if llm_outcome not in _VALID_OUTCOMES:
        llm_outcome = "unknown"

    # 采用“确定性优先 + uncertain 回退 LLM”策略：
    # - 有硬证据时以规则判定为准
    # - 规则无法判定（uncertain/unknown）时，允许采用 LLM 语义结果
    deterministic_outcome = _judge_outcome(ann_event)
    final_outcome = deterministic_outcome
    if (
        deterministic_outcome in {"uncertain", "unknown"}
        and llm_outcome in {"success", "partial_success", "failure", "timeout"}
    ):
        final_outcome = llm_outcome

    # 校验并回填
    ann_event.attack_phase = phase if phase in _VALID_ATTACK_PHASES else "ENV_PREPARATION"
    ann_event.outcome_label = final_outcome
    ann_event.attack_phase_reasoning = parsed.get("reasoning", "")

    logger.debug(
        "[llm_annotator] attack_phase event=%s phase=%s outcome=%s (det=%s llm=%s)",
        ann_event.event_id, ann_event.attack_phase, ann_event.outcome_label,
        deterministic_outcome, llm_outcome,
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


def _fallback_failure_root_cause(ann_event: AnnotatedEvent) -> Optional[FailureRootCause]:
    """LLM 不可用时，基于确定性信号回退失败根因。"""
    result = ann_event.base.result
    if result is None:
        return None

    txt = _collect_result_text(ann_event)
    txt_lower = txt.lower()

    if result.timed_out or _has_timeout_signal(txt):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.ENV,
            sub_dimension="TIMEOUT",
            evidence="timed_out=true 或输出出现 timeout 信号",
            source="rule_fallback",
            remediation_hint="增大 timeout 或拆分任务后重试",
            reasoning="LLM 不可用，依据超时信号采用 ENV/TIMEOUT 回退。",
        )

    if (
        "401 unauthorized" in txt_lower
        or "authentication failed" in txt_lower
        or "login failed" in txt_lower
        or re.search(r"\bstatus\s+code\s*[:=]?\s*401\b", txt_lower)
        or re.search(r"\bhttp/\d(?:\.\d)?\s+401\b", txt_lower)
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.DEF,
            sub_dimension="AUTHENTICATION",
            evidence="输出含 401/认证失败信号",
            source="rule_fallback",
            remediation_hint="先验证凭据/认证绕过条件，再继续利用",
            reasoning="LLM 不可用，依据认证失败信号采用 DEF/AUTHENTICATION 回退。",
        )

    if (
        "403 forbidden" in txt_lower
        or "authorization" in txt_lower
        or "access denied" in txt_lower
        or re.search(r"\bstatus\s+code\s*[:=]?\s*403\b", txt_lower)
        or re.search(r"\bhttp/\d(?:\.\d)?\s+403\b", txt_lower)
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.DEF,
            sub_dimension="AUTHORIZATION",
            evidence="输出含 403/授权拒绝信号",
            source="rule_fallback",
            remediation_hint="检查权限边界并切换可访问路径或提权后重试",
            reasoning="LLM 不可用，依据授权失败信号采用 DEF/AUTHORIZATION 回退。",
        )

    if (
        "404 not found" in txt_lower
        or re.search(r"\bstatus\s+code\s*[:=]?\s*404\b", txt_lower)
        or re.search(r"\bhttp/\d(?:\.\d)?\s+404\b", txt_lower)
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.INT,
            sub_dimension="TARGET_NOT_FOUND",
            evidence="输出含 404/Not Found 信号",
            source="rule_fallback",
            remediation_hint="先确认路径/端点存在性，再调整漏洞入口",
            reasoning="LLM 不可用，依据 404 信号采用 INT/TARGET_NOT_FOUND 回退。",
        )

    if (
        "500 internal server error" in txt_lower
        or re.search(r"\bstatus\s+code\s*[:=]?\s*500\b", txt_lower)
        or re.search(r"\bhttp/\d(?:\.\d)?\s+500\b", txt_lower)
        or "not vulnerable" in txt_lower
        or "already patched" in txt_lower
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.DEF,
            sub_dimension="PATCHED_OR_HARDENED",
            evidence="输出含 500/补丁/不可利用信号",
            source="rule_fallback",
            remediation_hint="切换同类 CVE 或调整利用链（鉴别已补丁目标）",
            reasoning="LLM 不可用，依据服务端防护/补丁信号采用 DEF/PATCHED_OR_HARDENED 回退。",
        )

    if "permission denied" in txt_lower:
        return FailureRootCause(
            dimension=FailureRootCauseDimension.ENV,
            sub_dimension="PERMISSION",
            evidence="输出含 permission denied",
            source="rule_fallback",
            remediation_hint="检查执行权限、用户权限或沙箱限制",
            reasoning="LLM 不可用，依据权限拒绝信号采用 ENV/PERMISSION 回退。",
        )

    if (
        "command not found" in txt_lower
        or "no such file" in txt_lower
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.ENV,
            sub_dimension="BINARY_MISSING",
            evidence="输出含 command not found/no such file",
            source="rule_fallback",
            remediation_hint="确认工具二进制是否存在，并校验 PATH/脚本路径",
            reasoning="LLM 不可用，依据命令缺失信号采用 ENV/BINARY_MISSING 回退。",
        )

    if (
        "traceback" in txt_lower
        or "exception" in txt_lower
        or "errors occurred" in txt_lower
        or re.search(r"(?<!no\s)\b(?:error|errors|failed|failure)\b", txt_lower)
    ):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.INV,
            sub_dimension="EXECUTION_ERROR",
            evidence="输出含 traceback/exception/error/failed 信号",
            source="rule_fallback",
            remediation_hint="复核命令参数、输入格式与依赖前置，再执行重试",
            reasoning="LLM 不可用，依据执行错误信号采用 INV/EXECUTION_ERROR 回退。",
        )

    if result.return_code not in (None, 0):
        return FailureRootCause(
            dimension=FailureRootCauseDimension.INV,
            sub_dimension="WRONG_ARGS",
            evidence=f"return_code={result.return_code}",
            source="rule_fallback",
            remediation_hint="核对命令参数、语法与调用顺序",
            reasoning="LLM 不可用，依据非零返回码采用 INV/WRONG_ARGS 回退。",
        )

    return FailureRootCause(
        dimension=FailureRootCauseDimension.EFF,
        sub_dimension="OUTPUT_LOST",
        evidence="未出现确定成功信号，且结果不可验证",
        source="rule_fallback",
        remediation_hint="补充可验证回显（uid/文件内容）后再判定",
        reasoning="LLM 不可用，依据效果不可验证采用 EFF/OUTPUT_LOST 回退。",
    )


def _run_failure_cause(
    ann_event: AnnotatedEvent,
    client: LLMClient,
    target_info: Optional[str],
) -> tuple[int, int]:
    """为失败事件补充 LLM 兜底的 failure_root_cause。返回 (call_count, error_count)。"""
    call = ann_event.base.call
    result = ann_event.base.result  # 必不为 None（已由 _needs_failure_cause_llm 保证）
    if result is None:
        return 0, 0

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
        fallback_frc = _fallback_failure_root_cause(ann_event)
        if fallback_frc is not None:
            ann_event.failure_root_cause = fallback_frc
        ann_event.llm_error = (ann_event.llm_error or "") + f" | failure_cause: {llm_result.error}"
        logger.warning(
            "[llm_annotator] failure_cause FAILED event=%s: %s; fallback=%s/%s",
            ann_event.event_id,
            llm_result.error,
            ann_event.failure_root_cause.dimension.value if ann_event.failure_root_cause else "N/A",
            ann_event.failure_root_cause.sub_dimension if ann_event.failure_root_cause else "N/A",
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
        fallback = _fallback_session_outcome(seq.metadata.session_id, events_summary)
        logger.warning(
            "[llm_annotator] session_outcome FAILED session=%s: %s; fallback=%s",
            seq.metadata.session_id, llm_result.error, fallback.outcome_label,
        )
        return fallback, 1, 1

    parsed = llm_result.parsed
    # P2修复：聚合所有事件的 key_signals（去重保序）
    all_key_signals: list[str] = []
    seen_signals: set[str] = set()
    for ev in events_summary:
        for sig in ev.get("key_signals", []):
            if sig not in seen_signals:
                seen_signals.add(sig)
                all_key_signals.append(sig)
    outcome_label = parsed.get("outcome_label", "failure")
    if outcome_label not in {"success", "partial_success", "failure"}:
        outcome_label = "failure"

    parsed_is_success = bool(parsed.get("is_success", False))
    parsed_goal_achieved = bool(parsed.get("session_goal_achieved", False))

    # 字段一致性校正：避免出现 partial_success 但 goal_achieved=False 的矛盾状态。
    if outcome_label == "success":
        normalized_is_success = True
        normalized_goal_achieved = True
    elif outcome_label == "partial_success":
        normalized_is_success = False
        normalized_goal_achieved = True
    else:
        normalized_is_success = False
        normalized_goal_achieved = False

    # 保留 LLM 自身偏好：仅在与 outcome_label 不冲突时接受。
    if outcome_label == "success" and parsed_is_success is False:
        normalized_is_success = True
    if outcome_label == "failure" and parsed_goal_achieved is True:
        normalized_goal_achieved = False

    outcome = SessionOutcome(
        is_success=normalized_is_success,
        outcome_label=outcome_label,
        session_goal_achieved=normalized_goal_achieved,
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


def _fallback_session_outcome(session_id: str, events_summary: List[Dict[str, Any]]) -> SessionOutcome:
    """LLM 不可用时的会话结果兜底。"""
    strong_signals: List[str] = []
    for ev in events_summary:
        for sig in ev.get("key_signals", []):
            if sig not in strong_signals:
                strong_signals.append(sig)

    labels = [str(ev.get("outcome_label", "unknown")) for ev in events_summary]

    if any(sig in {"uid=0", "root@", "flag{"} for sig in strong_signals):
        return SessionOutcome(
            is_success=True,
            outcome_label="success",
            session_goal_achieved=True,
            achieved_goals=["获取高权限或敏感信号"],
            failed_goals=[],
            reasoning="检测到 uid=0/root@/flag{ 强信号，按成功判定。",
            key_signals=strong_signals,
        )

    if any(lb in {"success", "partial_success"} for lb in labels):
        return SessionOutcome(
            is_success=False,
            outcome_label="partial_success",
            session_goal_achieved=True,
            achieved_goals=["出现部分成功事件"],
            failed_goals=["未检测到强成功信号"],
            reasoning="存在 success/partial_success 事件，但无强成功信号，保守判定为部分成功。",
            key_signals=strong_signals,
        )

    return SessionOutcome(
        is_success=False,
        outcome_label="failure",
        session_goal_achieved=False,
        achieved_goals=[],
        failed_goals=["未观察到有效成功信号"],
        reasoning=f"LLM 不可用，基于规则层与事件结果保守判定为失败（session={session_id[:8]}）。",
        key_signals=strong_signals,
    )
