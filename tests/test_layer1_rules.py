"""
tests/test_layer1_rules.py
===========================
测试覆盖：Layer 1 确定性规则引擎（Phase 2：失败根因规则部分）

TC-L01  return_code=127 → ENV-BINARY_MISSING，source="rule"
TC-L02  return_code=126 → ENV-EXECUTE_PERMISSION_DENIED
TC-L03  timed_out=True  → ENV-TIMEOUT
TC-L04  return_code=0   → 不触发任何规则（failure_root_cause=None）
TC-L05  result=None     → 不触发任何规则（无结果的事件）
TC-L06  return_code=1（通用失败）→ 规则不命中，needs_llm=True
TC-L07  timed_out=True + return_code=127 → RC-127 优先（return_code 检查在前）
TC-L08  success=False, return_code=None  → 规则不命中，needs_llm=True
TC-L09  return_code=127 的 FailureRootCause 含正确字段值
TC-L10  timed_out=True 的 FailureRootCause 含正确字段值
TC-L11  run_layer1 流水线：输出事件数 == 输入事件数
TC-L12  run_layer1 流水线：deterministic_hits 计数正确
TC-L13  run_layer1 流水线：llm_pending 计数正确
TC-L14  result=None 的事件 → needs_llm=False
TC-L15  return_code=0 的事件 → needs_llm=True（attack_phase 分类需要 LLM）
TC-L16  所有确定性规则命中的 source 均为 "rule"
TC-L17  annotate_event 不修改原始 AtomicEvent（base 字段不变）
TC-L18  AnnotatedEvent 代理属性（event_id, turn_index, call, result, has_rag_context）
TC-L19  run_layer1 metadata 透传：metadata 与 TurnSequence 相同
TC-L20  run_layer1 空事件序列：deterministic_hits=0, llm_pending=0
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import pytest

from src.layer1.deterministic_rules import (
    DETERMINISTIC_RULES,
    annotate_event,
    apply_deterministic_rules,
    should_flag_for_llm,
)
from src.layer1.pipeline import run_layer1
from src.models import (
    ActionCategory,
    AnnotatedEvent,
    AnnotatedTurnSequence,
    AtomicEvent,
    CallDescriptor,
    FailureRootCauseDimension,
    ResultDescriptor,
    SessionMetadata,
    TurnSequence,
)


# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数：构建最小测试对象
# ─────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)


def _make_call(tool_name: str = "generic_linux_command") -> CallDescriptor:
    return CallDescriptor(
        tool_name=tool_name,
        call_args={"command": "ls -la"},
        call_timestamp=_NOW,
        tool_call_id="tc_test_001",
        action_category=ActionCategory.GENERIC_COMMAND_CALL,
        program_name="ls",
    )


def _make_result(
    return_code: Optional[int] = 0,
    timed_out: bool = False,
    success: Optional[bool] = True,
    stderr: str = "",
    stdout: str = "",
) -> ResultDescriptor:
    return ResultDescriptor(
        return_code=return_code,
        timed_out=timed_out,
        success=success,
        stderr_raw=stderr,
        stdout_raw=stdout,
    )


def _make_event(
    event_id: str = "sess_0_0",
    result: Optional[ResultDescriptor] = None,
    turn_index: int = 0,
) -> AtomicEvent:
    return AtomicEvent(
        event_id=event_id,
        turn_index=turn_index,
        slot_in_turn=0,
        call=_make_call(),
        result=result,
    )


def _make_turn_sequence(events: list[AtomicEvent]) -> TurnSequence:
    """构建含指定事件列表的最小 TurnSequence。"""
    meta = SessionMetadata(
        session_id="test-session-layer1",
        start_time=_NOW,
        end_time=_NOW,
    )
    return TurnSequence(
        metadata=meta,
        all_events=events,
    )


# ─────────────────────────────────────────────────────────────────────────────
# TC-L01 ~ TC-L05  基础规则触发与不触发
# ─────────────────────────────────────────────────────────────────────────────

class TestDeterministicRulesTrigger:

    def test_L01_rc127_binary_missing(self):
        """TC-L01: return_code=127 → ENV-BINARY_MISSING"""
        event = _make_event(result=_make_result(return_code=127))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is not None, "应命中 RC-127 规则"
        assert frc.dimension == FailureRootCauseDimension.ENV
        assert frc.sub_dimension == "BINARY_MISSING"
        assert rule_name == "RC-127"

    def test_L02_rc126_permission_denied(self):
        """TC-L02: return_code=126 → ENV-EXECUTE_PERMISSION_DENIED"""
        event = _make_event(result=_make_result(return_code=126))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is not None, "应命中 RC-126 规则"
        assert frc.dimension == FailureRootCauseDimension.ENV
        assert frc.sub_dimension == "EXECUTE_PERMISSION_DENIED"
        assert rule_name == "RC-126"

    def test_L03_timed_out_timeout(self):
        """TC-L03: timed_out=True → ENV-TIMEOUT"""
        event = _make_event(result=_make_result(return_code=None, timed_out=True))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is not None, "应命中 TOUT 规则"
        assert frc.dimension == FailureRootCauseDimension.ENV
        assert frc.sub_dimension == "TIMEOUT"
        assert rule_name == "TOUT"

    def test_L04_rc0_no_rule(self):
        """TC-L04: return_code=0 → 不触发任何规则"""
        event = _make_event(result=_make_result(return_code=0))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is None
        assert rule_name is None

    def test_L05_result_none_no_rule(self):
        """TC-L05: result=None → 不触发任何规则"""
        event = _make_event(result=None)
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is None
        assert rule_name is None


# ─────────────────────────────────────────────────────────────────────────────
# TC-L06 ~ TC-L08  needs_llm 逻辑
# ─────────────────────────────────────────────────────────────────────────────

class TestNeedsLlmLogic:

    def test_L06_rc1_generic_failure_needs_llm(self):
        """TC-L06: return_code=1（通用失败）→ 规则不命中，needs_llm=True"""
        event = _make_event(result=_make_result(return_code=1, success=False))
        frc, _ = apply_deterministic_rules(event)
        needs = should_flag_for_llm(event, frc)

        assert frc is None, "RC=1 不在确定性规则集内"
        assert needs is True

    def test_L08_success_false_rc_none_needs_llm(self):
        """TC-L08: success=False, return_code=None → needs_llm=True"""
        event = _make_event(
            result=_make_result(return_code=None, timed_out=False, success=False)
        )
        frc, _ = apply_deterministic_rules(event)
        needs = should_flag_for_llm(event, frc)

        assert frc is None
        assert needs is True

    def test_L14_result_none_needs_llm(self):
        """TC-L14（修订）: result=None 的事件 → needs_llm=True（行为分类仍需 LLM）"""
        event = _make_event(result=None)
        frc, _ = apply_deterministic_rules(event)
        needs = should_flag_for_llm(event, frc)

        assert needs is True, "result=None 的事件也需要 LLM 做 attack_phase 分类"

    def test_L15_rc0_still_needs_llm(self):
        """TC-L15: return_code=0 的事件 → needs_llm=True（attack_phase 需要 LLM）"""
        event = _make_event(result=_make_result(return_code=0, success=True))
        frc, _ = apply_deterministic_rules(event)
        needs = should_flag_for_llm(event, frc)

        assert frc is None
        assert needs is True, "成功事件也需要 LLM 进行 attack_phase 标注"


# ─────────────────────────────────────────────────────────────────────────────
# TC-L07  规则优先级（return_code 在 timed_out 之前检查）
# ─────────────────────────────────────────────────────────────────────────────

class TestRulePriority:

    def test_L07_rc127_wins_over_timed_out(self):
        """TC-L07: timed_out=True + return_code=127 → RC-127 优先"""
        event = _make_event(result=_make_result(return_code=127, timed_out=True))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is not None
        assert frc.sub_dimension == "BINARY_MISSING", "return_code=127 应优先于 timed_out"
        assert rule_name == "RC-127"

    def test_rc126_wins_over_timed_out(self):
        """return_code=126 + timed_out=True → RC-126 优先"""
        event = _make_event(result=_make_result(return_code=126, timed_out=True))
        frc, rule_name = apply_deterministic_rules(event)

        assert frc is not None
        assert frc.sub_dimension == "EXECUTE_PERMISSION_DENIED"
        assert rule_name == "RC-126"


# ─────────────────────────────────────────────────────────────────────────────
# TC-L09 ~ TC-L10  FailureRootCause 字段完整性
# ─────────────────────────────────────────────────────────────────────────────

class TestFailureRootCauseFields:

    def test_L09_rc127_frc_fields(self):
        """TC-L09: return_code=127 的 FailureRootCause 含正确字段值，含工具名"""
        event = _make_event(result=_make_result(return_code=127))
        frc, _ = apply_deterministic_rules(event)

        assert frc.dimension == FailureRootCauseDimension.ENV
        assert frc.sub_dimension == "BINARY_MISSING"
        # evidence 格式：return_code=127 (tool=<tool_name>)
        assert "return_code=127" in frc.evidence
        assert frc.source == "rule"
        assert frc.remediation_hint is not None and len(frc.remediation_hint) > 0

    def test_L10_timed_out_frc_fields(self):
        """TC-L10: timed_out=True 的 FailureRootCause 含正确字段值"""
        event = _make_event(result=_make_result(return_code=None, timed_out=True))
        frc, _ = apply_deterministic_rules(event)

        assert frc.dimension == FailureRootCauseDimension.ENV
        assert frc.sub_dimension == "TIMEOUT"
        assert frc.evidence == "timed_out=true"
        assert frc.source == "rule"
        assert frc.remediation_hint is not None

    def test_L16_all_rule_sources_are_rule(self):
        """TC-L16: 所有确定性规则命中的 source 均为 "rule"（非 "llm"）"""
        cases = [
            _make_result(return_code=127),
            _make_result(return_code=126),
            _make_result(return_code=None, timed_out=True),
        ]
        for res in cases:
            event = _make_event(result=res)
            frc, _ = apply_deterministic_rules(event)
            assert frc is not None
            assert frc.source == "rule", f"规则层 source 应为 'rule'，得到 {frc.source!r}"


# ─────────────────────────────────────────────────────────────────────────────
# TC-L11 ~ TC-L13, TC-L19, TC-L20  run_layer1 流水线
# ─────────────────────────────────────────────────────────────────────────────

class TestRunLayer1Pipeline:

    def _make_seq_with_events(self) -> TurnSequence:
        """构造含 4 个事件的 TurnSequence：
        - event 0: return_code=127 (det hit)
        - event 1: return_code=126 (det hit)
        - event 2: timed_out=True  (det hit)
        - event 3: return_code=0   (no det hit, needs_llm)
        """
        return _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=127), 0),
            _make_event("s0_1", _make_result(return_code=126), 1),
            _make_event("s0_2", _make_result(return_code=None, timed_out=True), 2),
            _make_event("s0_3", _make_result(return_code=0), 3),
        ])

    def test_L11_output_event_count_matches(self):
        """TC-L11: 输出事件数 == 输入事件数"""
        seq = self._make_seq_with_events()
        ann = run_layer1(seq)
        assert ann.total_events == len(seq.all_events) == 4

    def test_L12_deterministic_hits_count(self):
        """TC-L12: deterministic_hits 正确（127/126/timed_out 各1 = 3）"""
        seq = self._make_seq_with_events()
        ann = run_layer1(seq)
        assert ann.deterministic_hits == 3

    def test_L13_llm_pending_count(self):
        """TC-L13（修订）: llm_pending = 全量事件（含 result=None 的事件）"""
        seq = self._make_seq_with_events()
        ann = run_layer1(seq)
        # 全部 4 个事件 needs_llm=True（含 result=None 情况时也为 True）
        assert ann.llm_pending == 4

    def test_L19_metadata_passthrough(self):
        """TC-L19: metadata 透传，与原始 TurnSequence 相同"""
        seq = self._make_seq_with_events()
        ann = run_layer1(seq)
        assert ann.metadata.session_id == seq.metadata.session_id
        assert ann.metadata.start_time == seq.metadata.start_time

    def test_L20_empty_events(self):
        """TC-L20: 空事件序列 → deterministic_hits=0, llm_pending=0"""
        seq = _make_turn_sequence([])
        ann = run_layer1(seq)
        assert ann.total_events == 0
        assert ann.deterministic_hits == 0
        assert ann.llm_pending == 0

    def test_no_result_events_also_need_llm(self):
        """result=None 的事件也计入 llm_pending（行为分类需要 LLM）"""
        seq = _make_turn_sequence([
            _make_event("s0_0", result=None),          # no result → needs_llm=True
            _make_event("s0_1", _make_result(return_code=0)),  # has result
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending == 2, "result=None 事件也应计入 llm_pending"
        assert ann.deterministic_hits == 0


# ─────────────────────────────────────────────────────────────────────────────
# TC-L17 ~ TC-L18  AnnotatedEvent 结构完整性
# ─────────────────────────────────────────────────────────────────────────────

class TestAnnotatedEventStructure:

    def test_L17_annotate_does_not_modify_base(self):
        """TC-L17: annotate_event 不修改原始 AtomicEvent"""
        event = _make_event(result=_make_result(return_code=127))
        original_id = event.event_id
        original_rc = event.result.return_code

        ann = annotate_event(event)

        # base 指向原始对象（不可变，未被替换）
        assert ann.base is event
        assert ann.base.event_id == original_id
        assert ann.base.result.return_code == original_rc

    def test_L18_proxy_properties(self):
        """TC-L18: AnnotatedEvent 代理属性与 base 一致"""
        event = _make_event("proxy_test_001", _make_result(return_code=0), turn_index=5)
        ann = annotate_event(event)

        assert ann.event_id == event.event_id
        assert ann.turn_index == event.turn_index
        assert ann.call is event.call
        assert ann.result is event.result
        assert ann.has_rag_context == event.has_rag_context

    def test_rule_applied_filled_on_hit(self):
        """确定性规则命中时 rule_applied 有值"""
        event = _make_event(result=_make_result(return_code=127))
        ann = annotate_event(event)
        assert ann.rule_applied == "RC-127"

    def test_rule_applied_none_on_miss(self):
        """规则未命中时 rule_applied=None"""
        event = _make_event(result=_make_result(return_code=0))
        ann = annotate_event(event)
        assert ann.rule_applied is None

    def test_phase3_fields_empty_after_phase2(self):
        """Phase 2 完成后，Phase 3 字段（attack_phase, outcome_label）均为 None"""
        event = _make_event(result=_make_result(return_code=127))
        ann = annotate_event(event)
        assert ann.attack_phase is None
        assert ann.outcome_label is None


# ─────────────────────────────────────────────────────────────────────────────
# 规则集完整性检查
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleTableCompleteness:

    def test_rule_names_unique(self):
        """规则表中每个规则名称唯一"""
        names = [r.name for r in DETERMINISTIC_RULES]
        assert len(names) == len(set(names)), f"规则名称重复: {names}"

    def test_required_rules_present(self):
        """必须包含 RC-127 / RC-126 / TOUT 三条核心规则"""
        names = {r.name for r in DETERMINISTIC_RULES}
        required = {"RC-127", "RC-126", "TOUT"}
        missing = required - names
        assert not missing, f"缺少规则: {missing}"

    def test_all_rules_produce_env_dimension(self):
        """Phase 2 所有确定性规则均属于 ENV 维度（技术方案 R-02）"""
        for rule in DETERMINISTIC_RULES:
            frc = rule.build()
            assert frc.dimension == FailureRootCauseDimension.ENV, (
                f"规则 {rule.name} 生成了非 ENV 根因: {frc.dimension}"
            )

    def test_all_rules_have_evidence(self):
        """每条规则生成的 FailureRootCause.evidence 非空"""
        for rule in DETERMINISTIC_RULES:
            frc = rule.build()
            assert frc.evidence, f"规则 {rule.name} 缺少 evidence"


# ─────────────────────────────────────────────────────────────────────────────
# 新增：evidence 含工具名、llm_pending_failure_cause 计数
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceWithToolName:

    def test_rc127_evidence_contains_tool_name(self):
        """RC-127 命中时，evidence 包含实际工具名"""
        event = _make_event(result=_make_result(return_code=127))
        # _make_call() 默认 tool_name="generic_linux_command"
        frc, _ = apply_deterministic_rules(event)
        assert "tool=generic_linux_command" in frc.evidence

    def test_rc127_evidence_with_custom_tool_name(self):
        """RC-127 命中时，evidence 包含自定义工具名（如 dirb_scan）"""
        call = CallDescriptor(
            tool_name="dirb_scan",
            call_args={},
            call_timestamp=_NOW,
            tool_call_id="tc_test_dirb",
            action_category=ActionCategory.STRUCTURED_TOOL_CALL,
        )
        event = AtomicEvent(
            event_id="dirb_test",
            turn_index=9,
            slot_in_turn=0,
            call=call,
            result=_make_result(return_code=127),
        )
        frc, _ = apply_deterministic_rules(event)
        assert "tool=dirb_scan" in frc.evidence
        assert "dirb_scan" in frc.remediation_hint

    def test_rc126_evidence_contains_tool_name(self):
        """RC-126 命中时，evidence 包含工具名"""
        event = _make_event(result=_make_result(return_code=126))
        frc, _ = apply_deterministic_rules(event)
        assert "tool=generic_linux_command" in frc.evidence

    def test_tout_evidence_no_tool_name(self):
        """TOUT 规则的 evidence 固定为 timed_out=true（不含工具名）"""
        event = _make_event(result=_make_result(return_code=None, timed_out=True))
        frc, _ = apply_deterministic_rules(event)
        assert frc.evidence == "timed_out=true"

    def test_different_tools_different_evidence(self):
        """不同工具触发同一规则时，evidence 应不同（区分 Layer 2 经验提取）"""
        def make_event_with_tool(tool_name: str) -> AtomicEvent:
            call = CallDescriptor(
                tool_name=tool_name,
                call_args={},
                call_timestamp=_NOW,
                tool_call_id=f"tc_{tool_name}",
                action_category=ActionCategory.STRUCTURED_TOOL_CALL,
            )
            return AtomicEvent(
                event_id=f"ev_{tool_name}",
                turn_index=0,
                slot_in_turn=0,
                call=call,
                result=_make_result(return_code=127),
            )

        frc_dirb, _ = apply_deterministic_rules(make_event_with_tool("dirb_scan"))
        frc_fscan, _ = apply_deterministic_rules(make_event_with_tool("fscan_scan"))
        frc_nuclei, _ = apply_deterministic_rules(make_event_with_tool("nuclei_scan"))

        evidence_set = {frc_dirb.evidence, frc_fscan.evidence, frc_nuclei.evidence}
        assert len(evidence_set) == 3, (
            f"不同工具的 evidence 应各不相同，实际: {evidence_set}"
        )

    def test_rc127_binary_extracted_from_stderr(self):
        """RC-127 且 stderr 含 '...binary: not found' 时，evidence 包含真实二进制名"""
        call = CallDescriptor(
            tool_name="dirb_scan",
            call_args={},
            call_timestamp=_NOW,
            tool_call_id="tc_binary_extract",
            action_category=ActionCategory.STRUCTURED_TOOL_CALL,
        )
        event = AtomicEvent(
            event_id="ev_binary_extract",
            turn_index=0,
            slot_in_turn=0,
            call=call,
            result=_make_result(
                return_code=127,
                stderr="/bin/sh: 1: dirb: not found",
            ),
        )
        frc, _ = apply_deterministic_rules(event)
        # evidence 使用真实二进制名
        assert "binary=dirb" in frc.evidence
        assert "tool=dirb_scan" in frc.evidence
        # remediation_hint 基于真实二进制，不是 tool_name
        assert "dirb" in frc.remediation_hint
        assert "apt install dirb" in frc.remediation_hint

    def test_rc127_msfconsole_extracted_from_stderr(self):
        """metasploit_run 的 stderr 应提取出 msfconsole，
        remediation_hint 应使用正确的 apt 包名 metasploit-framework"""
        call = CallDescriptor(
            tool_name="metasploit_run",
            call_args={},
            call_timestamp=_NOW,
            tool_call_id="tc_msf",
            action_category=ActionCategory.STRUCTURED_TOOL_CALL,
        )
        event = AtomicEvent(
            event_id="ev_msf",
            turn_index=0,
            slot_in_turn=0,
            call=call,
            result=_make_result(
                return_code=127,
                stderr="/bin/sh: 1: msfconsole: not found",
            ),
        )
        frc, _ = apply_deterministic_rules(event)
        # evidence 包含真实二进制名和工具名
        assert "binary=msfconsole" in frc.evidence
        assert "tool=metasploit_run" in frc.evidence
        # remediation_hint 应使用正确的 apt 包名（metasploit-framework）
        assert "apt install metasploit-framework" in frc.remediation_hint
        # 不得出现二进制名 / tool_name 直接拼接的错误包名
        assert "apt install msfconsole" not in frc.remediation_hint
        assert "apt install metasploit_run" not in frc.remediation_hint

    def test_rc127_fscan_manual_download(self):
        """fscan 是 Go 单体二进制，remediation_hint 应提示手动下载而非 apt install"""
        call = CallDescriptor(
            tool_name="fscan_scan",
            call_args={},
            call_timestamp=_NOW,
            tool_call_id="tc_fscan",
            action_category=ActionCategory.STRUCTURED_TOOL_CALL,
        )
        event = AtomicEvent(
            event_id="ev_fscan",
            turn_index=0,
            slot_in_turn=0,
            call=call,
            result=_make_result(
                return_code=127,
                stderr="/bin/sh: 1: fscan: not found",
            ),
        )
        frc, _ = apply_deterministic_rules(event)
        assert "binary=fscan" in frc.evidence
        # 应提示手动下载，不应给出错误的 apt 命令
        assert "apt install fscan" not in frc.remediation_hint
        assert "github.com" in frc.remediation_hint

    def test_rc127_nuclei_manual_download(self):
        """nuclei 是 Go 单体二进制，remediation_hint 应提示手动下载而非 apt install"""
        call = CallDescriptor(
            tool_name="nuclei_scan",
            call_args={},
            call_timestamp=_NOW,
            tool_call_id="tc_nuclei",
            action_category=ActionCategory.STRUCTURED_TOOL_CALL,
        )
        event = AtomicEvent(
            event_id="ev_nuclei",
            turn_index=0,
            slot_in_turn=0,
            call=call,
            result=_make_result(
                return_code=127,
                stderr="/bin/sh: 1: nuclei: not found",
            ),
        )
        frc, _ = apply_deterministic_rules(event)
        assert "binary=nuclei" in frc.evidence
        assert "apt install nuclei" not in frc.remediation_hint
        assert "github.com" in frc.remediation_hint

    def test_rc127_no_stderr_fallback_to_tool_name(self):
        """stderr 为空时，evidence 退回 tool_name 格式，不含 binary="""
        event = _make_event(result=_make_result(return_code=127, stderr=""))
        frc, _ = apply_deterministic_rules(event)
        assert "binary=" not in frc.evidence
        assert "tool=generic_linux_command" in frc.evidence


class TestLlmPendingFailureCause:

    def test_llm_pfc_counted_for_rc1(self):
        """return_code=1（规则未覆盖）→ 计入 llm_pending_failure_cause"""
        seq = _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=1, success=False)),
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending_failure_cause == 1

    def test_llm_pfc_not_counted_for_rc127(self):
        """return_code=127（规则已覆盖）→ 不计入 llm_pending_failure_cause"""
        seq = _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=127)),
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending_failure_cause == 0, "det-hit 事件不应进入 pfc 统计"

    def test_llm_pfc_not_counted_for_rc0(self):
        """return_code=0（成功）→ 不计入 llm_pending_failure_cause"""
        seq = _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=0, success=True)),
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending_failure_cause == 0

    def test_llm_pfc_not_counted_for_result_none(self):
        """result=None → 不计入 llm_pending_failure_cause（无法判断是否失败）"""
        seq = _make_turn_sequence([
            _make_event("s0_0", result=None),
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending_failure_cause == 0

    def test_llm_pfc_success_false_counted(self):
        """success=False, return_code=None → 计入 llm_pending_failure_cause"""
        seq = _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=None, success=False)),
        ])
        ann = run_layer1(seq)
        assert ann.llm_pending_failure_cause == 1

    def test_llm_pfc_mixed(self):
        """混合场景：det(127) + llm_failure(rc=1) + success(rc=0) + no_result"""
        seq = _make_turn_sequence([
            _make_event("s0_0", _make_result(return_code=127)),       # det hit → pfc=0
            _make_event("s0_1", _make_result(return_code=1)),         # pfc hit → pfc=1
            _make_event("s0_2", _make_result(return_code=0)),         # success → pfc=0
            _make_event("s0_3", result=None),                          # no result → pfc=0
        ])
        ann = run_layer1(seq)
        assert ann.deterministic_hits == 1
        assert ann.llm_pending == 4        # 全量（含 result=None）
        assert ann.llm_pending_failure_cause == 1
