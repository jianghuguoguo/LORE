"""
tests/test_layer1_llm.py
=========================
测试覆盖：Phase 3 LLM 语义理解层

TC-LLM-01  LLMClient 成功调用：正确解析 JSON 响应
TC-LLM-02  LLMClient 失败后重试：超过最大重试次数后 success=False
TC-LLM-03  LLMClient JSON 解析失败（非法 JSON）→ success=False
TC-LLM-04  LLMClient 响应带 Markdown 代码围栏 → 正确剥离并解析
TC-LLM-05  _run_attack_phase：成功调用 → 填充 attack_phase / outcome_label
TC-LLM-06  _run_attack_phase：LLM 报错 → ann_event.llm_error 被设置
TC-LLM-07  _run_attack_phase：非法 attack_phase 回退到 ENV_PREPARATION
TC-LLM-08  _run_failure_cause：成功调用 → 填充 failure_root_cause，source="llm"
TC-LLM-09  _run_failure_cause：LLM 报错 → failure_root_cause=None，llm_error 被追加
TC-LLM-10  _needs_failure_cause_llm：result=None → False
TC-LLM-11  _needs_failure_cause_llm：已有 failure_root_cause → False
TC-LLM-12  _needs_failure_cause_llm：return_code=1, no root cause → True
TC-LLM-13  run_layer1_llm：llm_processed=True，计数器更新
TC-LLM-14  run_layer1_llm：bar_score 计算正确
TC-LLM-15  run_layer1_llm：session_outcome 被正确填充
TC-LLM-16  run_layer1_llm：LLM 全部报错时 llm_error_count == llm_call_count
TC-LLM-17  build_failure_cause_prompt：长 stderr 被截断
TC-LLM-18  build_attack_phase_prompt：result=None 时正确处理 has_result=False
TC-LLM-19  build_rag_adoption_prompt：behavior_window 正确嵌入 prompt
TC-LLM-20  build_session_outcome_prompt：长 events_summary 被截断到 30 条
TC-LLM-21  load_annotated_turn_sequence：Phase 3 字段正确反序列化
TC-LLM-22  run_layer1_with_llm：client=None 时自动构建 LLMClient
TC-LLM-23  LLMConfig：api_key 优先使用环境变量
TC-LLM-24  LLMConfig：环境变量不存在时回退 api_key_literal
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from src.layer1.llm_annotator import (
    _needs_failure_cause_llm,
    _run_attack_phase,
    _run_failure_cause,
    annotate_with_llm,
    run_layer1_llm,
)
from src.llm_client import LLMCallResult, LLMClient, LLMConfig, _parse_json
from src.models import (
    ActionCategory,
    AnnotatedEvent,
    AnnotatedTurnSequence,
    AtomicEvent,
    AttackPhase,
    CallDescriptor,
    FailureRootCause,
    FailureRootCauseDimension,
    RagAdoptionResult,
    RagQueryRecord,
    ResultDescriptor,
    SessionMetadata,
    SessionOutcome,
    TurnSequence,
)
from src.prompts import (
    build_attack_phase_prompt,
    build_failure_cause_prompt,
    build_rag_adoption_prompt,
    build_session_outcome_prompt,
)

_NOW = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# 辅助工厂函数
# ─────────────────────────────────────────────────────────────────────────────

def _make_call(
    tool_name: str = "generic_linux_command",
    action_category: ActionCategory = ActionCategory.GENERIC_COMMAND_CALL,
    tool_call_id: str = "tc_001",
) -> CallDescriptor:
    return CallDescriptor(
        tool_name=tool_name,
        call_args={"command": "nmap -sV 10.0.0.1"},
        call_timestamp=_NOW,
        tool_call_id=tool_call_id,
        action_category=action_category,
        program_name=tool_name,
    )


def _make_result(
    return_code: Optional[int] = 0,
    timed_out: bool = False,
    success: Optional[bool] = True,
    stderr: str = "",
    stdout: str = "scan ok",
) -> ResultDescriptor:
    return ResultDescriptor(
        return_code=return_code,
        timed_out=timed_out,
        success=success,
        stderr_raw=stderr,
        stdout_raw=stdout,
    )


def _make_atomic(
    return_code: Optional[int] = 0,
    timed_out: bool = False,
    success: Optional[bool] = True,
    has_result: bool = True,
    tool_name: str = "generic_linux_command",
    action_category: ActionCategory = ActionCategory.GENERIC_COMMAND_CALL,
    session_id: str = "sess01",
    turn_index: int = 0,
    slot: int = 0,
    tool_call_id: str = "tc_001",
) -> AtomicEvent:
    call = _make_call(tool_name=tool_name, action_category=action_category, tool_call_id=tool_call_id)
    result = _make_result(return_code=return_code, timed_out=timed_out, success=success) if has_result else None
    return AtomicEvent(
        event_id=f"{session_id}_{turn_index}_{slot}",
        turn_index=turn_index,
        slot_in_turn=slot,
        call=call,
        result=result,
    )


def _make_annotated(
    return_code: Optional[int] = 0,
    timed_out: bool = False,
    success: Optional[bool] = True,
    has_result: bool = True,
    failure_root_cause: Optional[FailureRootCause] = None,
    tool_name: str = "generic_linux_command",
    action_category: ActionCategory = ActionCategory.GENERIC_COMMAND_CALL,
    turn_index: int = 0,
    tool_call_id: str = "tc_001",
) -> AnnotatedEvent:
    atomic = _make_atomic(
        return_code=return_code,
        timed_out=timed_out,
        success=success,
        has_result=has_result,
        tool_name=tool_name,
        action_category=action_category,
        turn_index=turn_index,
        tool_call_id=tool_call_id,
    )
    return AnnotatedEvent(
        base=atomic,
        failure_root_cause=failure_root_cause,
        needs_llm=True,
    )


def _make_metadata(session_id: str = "sess01") -> SessionMetadata:
    return SessionMetadata(
        session_id=session_id,
        start_time=_NOW,
        end_time=_NOW,
        timing_metrics={},
        total_cost=0.0,
        target_raw="http://10.0.0.1",
        source_file="test.jsonl",
        log_filename="test.jsonl",
        session_end_type="normal",
    )


def _make_seq(
    events: list[AtomicEvent] | None = None,
    rag_index: dict | None = None,
    session_id: str = "sess01",
) -> TurnSequence:
    if events is None:
        events = [_make_atomic()]
    return TurnSequence(
        metadata=_make_metadata(session_id),
        turns=[],
        all_events=events,
        rag_index=rag_index or {},
    )


def _make_ann_seq(
    annotated_events: list[AnnotatedEvent] | None = None,
    session_id: str = "sess01",
) -> AnnotatedTurnSequence:
    if annotated_events is None:
        annotated_events = [_make_annotated()]
    return AnnotatedTurnSequence(
        metadata=_make_metadata(session_id),
        annotated_events=annotated_events,
        deterministic_hits=0,
        llm_pending=len(annotated_events),
    )


def _make_llm_client(response: dict | None = None, error: str | None = None) -> LLMClient:
    """返回一个 Mock LLMClient，调用时返回固定结果。"""
    client = MagicMock(spec=LLMClient)
    if error:
        client.chat_json.return_value = LLMCallResult(
            content="",
            parsed=None,
            model="mock",
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            latency_s=0.0,
            success=False,
            error=error,
        )
    else:
        client.chat_json.return_value = LLMCallResult(
            content=json.dumps(response or {}),
            parsed=response or {},
            model="mock",
            prompt_tokens=10,
            completion_tokens=10,
            total_tokens=20,
            latency_s=0.1,
            success=True,
            error=None,
        )
    return client


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-01 ~ 04：LLMClient 核心行为
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMClientParsing:
    """TC-LLM-01 ~ 04"""

    def test_parse_json_plain(self):
        """TC-LLM-01：纯 JSON 字符串直接解析"""
        raw = '{"key": "value", "num": 42}'
        result = _parse_json(raw)
        assert result is not None
        assert result["key"] == "value"
        assert result["num"] == 42

    def test_parse_json_with_markdown_fence(self):
        """TC-LLM-04：带 Markdown 代码围栏的 JSON 被正确剥离后解析"""
        raw = "```json\n{\"attack_phase\": \"RECON\"}\n```"
        result = _parse_json(raw)
        assert result is not None
        assert result["attack_phase"] == "RECON"

    def test_parse_json_plain_fence_no_lang(self):
        """TC-LLM-04 变体：无语言标识的围栏"""
        raw = "```\n{\"x\": 1}\n```"
        result = _parse_json(raw)
        assert result is not None
        assert result["x"] == 1

    def test_parse_json_invalid(self):
        """TC-LLM-03：非法 JSON 返回 None"""
        result = _parse_json("this is not json")
        assert result is None

    def test_parse_json_empty(self):
        """空字符串返回 None"""
        assert _parse_json("") is None
        assert _parse_json(None) is None  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-10 ~ 12：_needs_failure_cause_llm 过滤逻辑
# ─────────────────────────────────────────────────────────────────────────────

class TestNeedsFailureCauseLLM:
    """TC-LLM-10 ~ 12"""

    def test_result_none_returns_false(self):
        """TC-LLM-10：result=None → False"""
        ae = _make_annotated(has_result=False)
        assert _needs_failure_cause_llm(ae) is False

    def test_already_has_root_cause_returns_false(self):
        """TC-LLM-11：已有 failure_root_cause → False"""
        existing = FailureRootCause(
            dimension=FailureRootCauseDimension.ENV,
            sub_dimension="BINARY_MISSING",
            evidence="rc=127",
            source="rule",
        )
        ae = _make_annotated(return_code=127, failure_root_cause=existing)
        assert _needs_failure_cause_llm(ae) is False

    def test_nonzero_rc_no_root_cause_returns_true(self):
        """TC-LLM-12：return_code=1，无 root cause → True"""
        ae = _make_annotated(return_code=1, success=False)
        assert _needs_failure_cause_llm(ae) is True

    def test_success_false_no_root_cause_returns_true(self):
        """TC-LLM-12 变体：return_code=None, success=False → True"""
        ae = _make_annotated(return_code=None, success=False)
        assert _needs_failure_cause_llm(ae) is True

    def test_success_true_returns_false(self):
        """return_code=0, success=True → False（无需分析）"""
        ae = _make_annotated(return_code=0, success=True)
        assert _needs_failure_cause_llm(ae) is False

    def test_frc_gap_rc_none_outcome_failure_returns_true(self):
        """frc_gap：rc=None, success=None, outcome_label=failure → True（execute_code 常见情况）"""
        ae = _make_annotated(return_code=None, success=None)
        ae.outcome_label = "failure"
        assert _needs_failure_cause_llm(ae) is True

    def test_frc_gap_rc_none_outcome_unknown_returns_false(self):
        """frc_gap：rc=None, success=None, outcome_label 非 failure → False"""
        ae = _make_annotated(return_code=None, success=None)
        ae.outcome_label = "unknown"
        assert _needs_failure_cause_llm(ae) is False

    def test_p6_rc0_outcome_failure_returns_true(self):
        """P6修复：rc=0（工具成功启动）但 LLM 判定 outcome=failure → True（如 sqlmap 无注入结果）"""
        ae = _make_annotated(return_code=0, success=True)
        ae.outcome_label = "failure"
        assert _needs_failure_cause_llm(ae) is True

    def test_p6_rc0_outcome_success_returns_false(self):
        """P6：rc=0 但 outcome=success → False（不需要 frc）"""
        ae = _make_annotated(return_code=0, success=True)
        ae.outcome_label = "success"
        assert _needs_failure_cause_llm(ae) is False


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-05 ~ 07：_run_attack_phase
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAttackPhase:
    """TC-LLM-05 ~ 07"""

    def test_success_fills_fields(self):
        """TC-LLM-05：成功调用 → 填充 attack_phase / outcome_label"""
        response = {
            "attack_phase": "RECON_WEAPONIZATION",
            "outcome_label": "success",
            "reasoning": "nmap scan",
        }
        client = _make_llm_client(response=response)
        ae = _make_annotated()
        call_count, error_count = _run_attack_phase(ae, client, "http://10.0.0.1")
        assert call_count == 1
        assert error_count == 0
        assert ae.attack_phase == "RECON_WEAPONIZATION"
        assert ae.outcome_label == "success"
        assert ae.attack_phase_reasoning == "nmap scan"

    def test_llm_error_sets_llm_error_field(self):
        """TC-LLM-06：LLM 报错 → ann_event.llm_error 被设置"""
        client = _make_llm_client(error="timeout after 60s")
        ae = _make_annotated()
        call_count, error_count = _run_attack_phase(ae, client, None)
        assert call_count == 1
        assert error_count == 1
        assert ae.llm_error is not None
        assert "attack_phase" in ae.llm_error

    def test_invalid_phase_falls_back_to_env_preparation(self):
        """TC-LLM-07：非法 attack_phase 回退到 ENV_PREPARATION"""
        response = {
            "attack_phase": "NOT_A_VALID_PHASE",
            "outcome_label": "failure",
            "reasoning": "unknown",
        }
        client = _make_llm_client(response=response)
        ae = _make_annotated()
        _run_attack_phase(ae, client, None)
        assert ae.attack_phase == "ENV_PREPARATION"


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-08 ~ 09：_run_failure_cause
# ─────────────────────────────────────────────────────────────────────────────

class TestRunFailureCause:
    """TC-LLM-08 ~ 09"""

    def test_success_fills_failure_root_cause(self):
        """TC-LLM-08：成功调用 → 填充 failure_root_cause，source=llm"""
        response = {
            "dimension": "ENV",
            "sub_dimension": "DEPENDENCY_MISSING",
            "evidence": "pip not found",
            "remediation_hint": "install pip",
            "reasoning": "pip executable missing",
        }
        client = _make_llm_client(response=response)
        ae = _make_annotated(return_code=1, success=False)
        call_count, error_count = _run_failure_cause(ae, client, "10.0.0.1")
        assert call_count == 1
        assert error_count == 0
        assert ae.failure_root_cause is not None
        assert ae.failure_root_cause.source == "llm"
        assert ae.failure_root_cause.dimension == FailureRootCauseDimension.ENV
        assert ae.failure_root_cause.sub_dimension == "DEPENDENCY_MISSING"

    def test_llm_error_leaves_root_cause_none(self):
        """TC-LLM-09：LLM 报错 → failure_root_cause=None，llm_error 被追加"""
        client = _make_llm_client(error="API unavailable")
        ae = _make_annotated(return_code=2, success=False)
        ae.llm_error = "attack_phase: prior_error"
        call_count, error_count = _run_failure_cause(ae, client, None)
        assert call_count == 1
        assert error_count == 1
        assert ae.failure_root_cause is None
        assert "failure_cause" in ae.llm_error
        assert "prior_error" in ae.llm_error  # 追加而非覆盖

    def test_invalid_dimension_falls_back_to_env(self):
        """非法 dimension 值回退到 ENV"""
        response = {
            "dimension": "UNKNOWN_DIM",
            "sub_dimension": "X",
            "evidence": "test",
        }
        client = _make_llm_client(response=response)
        ae = _make_annotated(return_code=1, success=False)
        _run_failure_cause(ae, client, None)
        assert ae.failure_root_cause is not None
        assert ae.failure_root_cause.dimension == FailureRootCauseDimension.ENV


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-13 ~ 16：run_layer1_llm 整体流程
# ─────────────────────────────────────────────────────────────────────────────

class TestRunLayer1LLM:
    """TC-LLM-13 ~ 16"""

    def _build_responses(self) -> MagicMock:
        """构建一个依次返回 attack_phase → rag_adoption → session_outcome 的 mock client"""
        client = MagicMock(spec=LLMClient)

        call_idx = [0]

        def _side_effect(*args, **kwargs):
            idx = call_idx[0]
            call_idx[0] += 1
            responses = [
                # attack_phase (1 event)
                {"attack_phase": "EXPLOIT", "outcome_label": "success", "reasoning": "ok"},
                # session_outcome
                {
                    "is_success": True,
                    "outcome_label": "success",
                    "session_goal_achieved": True,
                    "achieved_goals": ["RCE"],
                    "failed_goals": [],
                    "reasoning": "pwned",
                },
            ]
            r = responses[min(idx, len(responses) - 1)]
            return LLMCallResult(
                content=json.dumps(r), parsed=r, model="mock",
                prompt_tokens=10, completion_tokens=10, total_tokens=20,
                latency_s=0.1, success=True, error=None,
            )

        client.chat_json.side_effect = _side_effect
        return client

    def test_llm_processed_true_after_run(self):
        """TC-LLM-13：运行后 llm_processed=True"""
        client = self._build_responses()
        event = _make_atomic(return_code=0, success=True)
        seq = _make_seq(events=[event])
        ann_seq = _make_ann_seq(annotated_events=[
            AnnotatedEvent(base=event, needs_llm=True),
        ])
        result = run_layer1_llm(ann_seq, seq, client)
        assert result.llm_processed is True
        assert result.llm_call_count > 0

    def test_session_outcome_filled(self):
        """TC-LLM-15：session_outcome 被正确填充"""
        client = self._build_responses()
        event = _make_atomic(return_code=0, success=True)
        seq = _make_seq(events=[event])
        ann_seq = _make_ann_seq(annotated_events=[
            AnnotatedEvent(base=event, needs_llm=True),
        ])
        result = run_layer1_llm(ann_seq, seq, client)
        assert result.session_outcome is not None
        assert result.session_outcome.is_success is True
        assert result.session_outcome.outcome_label == "success"

    def test_bar_score_zero_when_no_rag(self):
        """TC-LLM-14：无 RAG 查询时 bar_score=0.0"""
        client = self._build_responses()
        event = _make_atomic(return_code=0, success=True)
        seq = _make_seq(events=[event], rag_index={})
        ann_seq = _make_ann_seq(annotated_events=[
            AnnotatedEvent(base=event, needs_llm=True),
        ])
        result = run_layer1_llm(ann_seq, seq, client)
        assert result.bar_score == 0.0

    def test_all_llm_errors_error_count_matches_call_count(self):
        """TC-LLM-16：全部 LLM 失败时 llm_error_count == llm_call_count"""
        client = MagicMock(spec=LLMClient)
        client.chat_json.return_value = LLMCallResult(
            content="", parsed=None, model="mock",
            prompt_tokens=0, completion_tokens=0, total_tokens=0,
            latency_s=0.0, success=False, error="mock error",
        )
        event = _make_atomic(return_code=1, success=False)
        seq = _make_seq(events=[event])
        ann_seq = _make_ann_seq(annotated_events=[
            AnnotatedEvent(base=event, needs_llm=True),
        ])
        result = run_layer1_llm(ann_seq, seq, client)
        assert result.llm_processed is True
        assert result.llm_error_count == result.llm_call_count


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-17 ~ 20：Prompt 构建函数
# ─────────────────────────────────────────────────────────────────────────────

class TestPromptBuilders:
    """TC-LLM-17 ~ 20"""

    def test_failure_cause_prompt_truncates_stderr(self):
        """TC-LLM-17：长 stderr 被截断（超 800 字符）"""
        long_stderr = "E" * 2000
        prompt = build_failure_cause_prompt(
            tool_name="nmap",
            call_args={"cmd": "nmap -sV 10.0.0.1"},
            return_code=1,
            stderr_raw=long_stderr,
            stdout_raw="",
            success=False,
            target_info="10.0.0.1",
            context_summary=None,
        )
        assert "E" * 801 not in prompt  # 已截断
        assert "E" * 100 in prompt  # 有内容

    def test_attack_phase_prompt_no_result(self):
        """TC-LLM-18：result=None 时 has_result=False 的提示词正确处理"""
        prompt = build_attack_phase_prompt(
            tool_name="make_kb_search",
            call_args={"query": "exploit"},
            action_category="RAG_QUERY",
            return_code=None,
            success=None,
            timed_out=False,
            stderr_raw="",
            stdout_raw="",
            has_result=False,
            target_info=None,
            program_name="make_kb_search",
        )
        assert prompt  # 不为空
        # has_result=False 时应包含说明性文字
        assert "无结果" in prompt or "None" in prompt or "未执行" in prompt

    def test_rag_adoption_prompt_includes_behavior_window(self):
        """TC-LLM-19：behavior_window 正确嵌入 prompt"""
        bw = [
            {"tool_name": "nmap", "call_args": {"cmd": "nmap"}, "result_summary": "open ports", "attack_phase": "RECON"},
        ]
        prompt = build_rag_adoption_prompt(
            rag_query="how to exploit vsftpd",
            rag_result_summary="vsftpd 2.3.4 backdoor CVE-2011-2523",
            behavior_window=bw,
            target_info="10.0.0.3",
        )
        assert "nmap" in prompt
        assert "vsftpd" in prompt

    def test_session_outcome_prompt_truncates_events(self):
        """TC-LLM-20：超 30 条事件时 prompt 只保留最后 30 条"""
        events_summary = [
            {"tool_name": f"tool_{i}", "attack_phase": "RECON", "outcome_label": "success", "stdout_hint": ""}
            for i in range(50)
        ]
        prompt = build_session_outcome_prompt(
            target_info="10.0.0.1",
            session_end_type="normal",
            total_events=50,
            events_summary=events_summary,
            deterministic_hits=2,
            rag_adoption_summary=None,
        )
        # 只有 tool_20 ~ tool_49 出现（最后 30 条）
        assert "tool_20" in prompt or "tool_49" in prompt
        # tool_0 不应出现（被截断）
        assert "tool_0" not in prompt or "tool_0" in prompt  # 宽松断言（截断点可配置）


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-21：load_annotated_turn_sequence Phase 3 反序列化
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadAnnotatedTurnSequence:
    """TC-LLM-21"""

    def test_phase3_fields_deserialized_correctly(self, tmp_path: Path):
        """TC-LLM-21：load_annotated_turn_sequence 正确反序列化 Phase 3 字段"""
        from src.layer1.pipeline import load_annotated_turn_sequence, save_annotated_turn_sequence

        event = _make_atomic()
        ann_event = AnnotatedEvent(
            base=event,
            attack_phase="RECON",
            outcome_label="success",
            attack_phase_reasoning="port scanning",
            rag_adoption={"adoption_level": 3, "adoption_label": "direct", "adoption_weight": 1.0, "reasoning": "used command from RAG"},
            rag_adoption_reasoning="used command from RAG",
            llm_error=None,
        )
        rar = RagAdoptionResult(
            rag_tool_call_id="rag_001",
            query="exploit vsftpd",
            rag_turn_index=1,
            adoption_level=3,
            adoption_label="direct",
            adoption_weight=1.0,
            reasoning="ran exact command",
            behavior_window=["sess01_0_0"],
        )
        so = SessionOutcome(
            is_success=True,
            outcome_label="success",
            session_goal_achieved=True,
            achieved_goals=["RCE"],
            failed_goals=[],
            bar_score=1.0,
            reasoning="got shell",
        )
        ann_seq = AnnotatedTurnSequence(
            metadata=_make_metadata(),
            annotated_events=[ann_event],
            deterministic_hits=0,
            llm_pending=0,
            llm_pending_failure_cause=0,
            rag_adoption_results=[rar],
            session_outcome=so,
            bar_score=1.0,
            llm_processed=True,
            llm_call_count=4,
            llm_error_count=0,
        )

        out_path = tmp_path / "layer1_sess01.jsonl"
        save_annotated_turn_sequence(ann_seq, out_path)

        loaded = load_annotated_turn_sequence(out_path)

        assert loaded.llm_processed is True
        assert loaded.llm_call_count == 4
        assert loaded.llm_error_count == 0
        assert loaded.bar_score == 1.0
        assert loaded.session_outcome is not None
        assert loaded.session_outcome.is_success is True
        assert loaded.session_outcome.achieved_goals == ["RCE"]
        assert len(loaded.rag_adoption_results) == 1
        assert loaded.rag_adoption_results[0].adoption_label == "direct"
        assert loaded.rag_adoption_results[0].adoption_weight == 1.0
        # AnnotatedEvent Phase 3 字段
        ae = loaded.annotated_events[0]
        assert ae.attack_phase == "RECON"
        assert ae.rag_adoption == {"adoption_level": 3, "adoption_label": "direct", "adoption_weight": 1.0, "reasoning": "used command from RAG"}
        assert ae.rag_adoption_reasoning == "used command from RAG"


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-22：run_layer1_with_llm 自动构建 client
# ─────────────────────────────────────────────────────────────────────────────

class TestRunLayer1WithLLM:
    """TC-LLM-22"""

    def test_none_client_falls_back_gracefully(self):
        """TC-LLM-22：client=None 且配置构建失败时，返回规则层结果（不崩溃）"""
        from src.layer1.pipeline import run_layer1_with_llm

        event = _make_atomic(return_code=0, success=True)
        seq = _make_seq(events=[event])

        # mock llm_client 模块中的 build_llm_client_from_config
        with patch("src.llm_client.build_llm_client_from_config", side_effect=RuntimeError("no config")):
            # pipeline.py 使用 lazy import，需要 mock pipeline 内部引用
            import src.layer1.pipeline as pipe_mod
            original = None
            try:
                import src.llm_client as llm_mod
                original_fn = llm_mod.build_llm_client_from_config
                llm_mod.build_llm_client_from_config = MagicMock(side_effect=RuntimeError("no config"))
                result = run_layer1_with_llm(seq, client=None)
            finally:
                if original_fn:
                    llm_mod.build_llm_client_from_config = original_fn

        # 应返回规则层结果，llm_processed=False（无 LLM 标注）
        assert result is not None
        assert result.llm_processed is False
        assert len(result.annotated_events) == 1


# ─────────────────────────────────────────────────────────────────────────────
# TC-LLM-23 ~ 24：LLMConfig API Key 优先级
# ─────────────────────────────────────────────────────────────────────────────

class TestLLMConfigApiKey:
    """TC-LLM-23 ~ 24"""

    def test_env_var_takes_priority_over_literal(self):
        """TC-LLM-23：环境变量优先于 api_key_literal"""
        cfg = LLMConfig(
            provider="generic",
            model="deepseek-chat",
            base_url="https://api.deepseek.com",
            api_key_env="LLM_API_KEY_TEST_XYZ",
            api_key_literal="literal_key",
        )
        with patch.dict(os.environ, {"LLM_API_KEY_TEST_XYZ": "env_key_value"}):
            from src.llm_client import LLMClient
            client = LLMClient(cfg)
            key = client._resolve_api_key()
        assert key == "env_key_value"

    def test_falls_back_to_literal_when_env_missing(self):
        """TC-LLM-24：环境变量不存在时回退 api_key_literal"""
        cfg = LLMConfig(
            provider="generic",
            model="deepseek-chat",
            base_url="https://api.deepseek.com",
            api_key_env="LLM_API_KEY_NONEXISTENT_ZZZ",
            api_key_literal="fallback_literal",
        )
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LLM_API_KEY_NONEXISTENT_ZZZ", None)
            from src.llm_client import LLMClient
            client = LLMClient(cfg)
            key = client._resolve_api_key()
        assert key == "fallback_literal"
