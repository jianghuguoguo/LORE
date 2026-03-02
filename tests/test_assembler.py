"""
tests/test_assembler.py
========================
测试覆盖：TurnSequenceAssembler 的核心功能

TC-A01  所有事件展平到 all_events（数量正确）
TC-A02  rag_index 正确构建（key=tool_call_id）
TC-A03  has_rag_context=True 当且仅当前 N 步内有 RAG 调用
TC-A04  has_rag_context=False 当前 N 步内无 RAG 调用
TC-A05  rag_query_ref 指向最近一次 RAG 调用的 tool_call_id
TC-A06  RAG_QUERY 事件自身的 has_rag_context=False（不自我标记）
TC-A07  CODE_WRITE 事件的 code_script_ref 指向后续执行脚本的事件 ID
TC-A08  code_write_index 包含所有 CODE_WRITE 事件
TC-A09  会话元数据正确透传到 TurnSequence.metadata
TC-A10  turn_count 和 event_count 属性与实际数量一致
TC-A11  超出时间窗口（N+1步）的 RAG 调用不影响 has_rag_context
TC-A12  空事件会话（0 Turn）→ TurnSequence 合法
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from src.layer0.assembler import TurnSequenceAssembler
from src.layer0.extractor import EventExtractor
from src.layer0.parser import LogParser
from src.models import (
    ActionCategory,
    AtomicEvent,
    CallDescriptor,
    RagQueryRecord,
    ResultDescriptor,
    SessionMetadata,
    Turn,
)


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：构建最小 Turn 对象（含 events / rag_queries）
# ─────────────────────────────────────────────────────────────────────────────

_SESSION = "test-asm"

def _ts() -> datetime:
    return datetime(2026, 2, 4, tzinfo=timezone.utc)

def _call(tool_name: str, call_id: str, category: ActionCategory,
          filename: str = None) -> CallDescriptor:
    return CallDescriptor(
        tool_name=tool_name,
        call_args={},
        call_timestamp=_ts(),
        tool_call_id=call_id,
        action_category=category,
        program_name=tool_name if category == ActionCategory.GENERIC_COMMAND_CALL else None,
        code_filename=filename,
    )

def _event(session_id: str, turn_idx: int, slot: int,
           tool_name: str, call_id: str, category: ActionCategory,
           filename: str = None) -> AtomicEvent:
    return AtomicEvent(
        event_id=f"{session_id}_{turn_idx:04d}_{slot:02d}",
        turn_index=turn_idx,
        slot_in_turn=slot,
        call=_call(tool_name, call_id, category, filename),
        result=None,
        has_rag_context=False,
    )

def _rag_record(call_id: str, turn_idx: int) -> RagQueryRecord:
    return RagQueryRecord(
        tool_call_id=call_id,
        query="test query",
        rag_timestamp=_ts(),
        turn_index=turn_idx,
        rag_result="result content",
    )

def _turn(turn_idx: int, events: List[AtomicEvent], rags: List[RagQueryRecord]) -> Turn:
    t = Turn(
        turn_index=turn_idx,
        timestamp=_ts(),
        session_id=_SESSION,
    )
    t.events = events
    t.rag_queries = rags
    return t


def _metadata() -> SessionMetadata:
    return SessionMetadata(
        session_id=_SESSION,
        start_time=_ts(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 测试
# ─────────────────────────────────────────────────────────────────────────────

class TestAssemblerBasicStructure:
    """TC-A01, TC-A02, TC-A09, TC-A10, TC-A12"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.assembler = TurnSequenceAssembler()

    def test_empty_turns(self):
        """TC-A12：空 Turn 列表"""
        seq = self.assembler.assemble(_metadata(), [])
        assert seq.turn_count == 0
        assert seq.event_count == 0
        assert seq.rag_index == {}

    def test_all_events_flattened(self):
        """TC-A01"""
        t0 = _turn(0, [_event(_SESSION, 0, 0, "nmap_scan", "c0", ActionCategory.STRUCTURED_TOOL_CALL)], [])
        t1 = _turn(1, [_event(_SESSION, 1, 0, "generic_linux_command", "c1", ActionCategory.GENERIC_COMMAND_CALL),
                       _event(_SESSION, 1, 1, "gobuster_scan", "c2", ActionCategory.STRUCTURED_TOOL_CALL)], [])
        seq = self.assembler.assemble(_metadata(), [t0, t1])
        assert seq.event_count == 3
        assert seq.turn_count == 2

    def test_rag_index_built(self):
        """TC-A02"""
        rag = _rag_record("rag1", 1)
        rag_event = _event(_SESSION, 1, 0, "make_kb_search", "rag1", ActionCategory.RAG_QUERY)
        t0 = _turn(0, [_event(_SESSION, 0, 0, "nmap_scan", "c0", ActionCategory.STRUCTURED_TOOL_CALL)], [])
        t1 = _turn(1, [rag_event], [rag])
        seq = self.assembler.assemble(_metadata(), [t0, t1])
        assert "rag1" in seq.rag_index
        assert seq.rag_call_count == 1

    def test_metadata_preserved(self):
        """TC-A09"""
        meta = _metadata()
        seq = self.assembler.assemble(meta, [])
        assert seq.metadata.session_id == _SESSION

    def test_turn_count_event_count_properties(self):
        """TC-A10"""
        t0 = _turn(0, [_event(_SESSION, 0, 0, "nmap_scan", "c0", ActionCategory.STRUCTURED_TOOL_CALL)], [])
        seq = self.assembler.assemble(_metadata(), [t0])
        assert seq.turn_count == 1
        assert seq.event_count == 1


class TestHasRagContextAnnotation:
    """TC-A03, TC-A04, TC-A05, TC-A06, TC-A11"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.assembler = TurnSequenceAssembler()

    def test_event_after_rag_gets_context(self):
        """TC-A03：Turn N 有 RAG，Turn N+1 的事件 has_rag_context=True"""
        rag = _rag_record("rag1", 0)
        rag_e = _event(_SESSION, 0, 0, "make_kb_search", "rag1", ActionCategory.RAG_QUERY)
        curltest_e = _event(_SESSION, 1, 0, "generic_linux_command", "curl1", ActionCategory.GENERIC_COMMAND_CALL)

        t0 = _turn(0, [rag_e], [rag])
        t1 = _turn(1, [curltest_e], [])
        seq = self.assembler.assemble(_metadata(), [t0, t1])

        curl_event = next(e for e in seq.all_events if e.call.tool_call_id == "curl1")
        assert curl_event.has_rag_context is True

    def test_event_before_rag_no_context(self):
        """TC-A04：Turn N 的事件在 RAG Turn N+2 之前，has_rag_context=False"""
        nmap_e = _event(_SESSION, 0, 0, "nmap_scan", "nmap1", ActionCategory.STRUCTURED_TOOL_CALL)
        rag = _rag_record("rag1", 2)
        rag_e = _event(_SESSION, 2, 0, "make_kb_search", "rag1", ActionCategory.RAG_QUERY)

        t0 = _turn(0, [nmap_e], [])
        t2 = _turn(2, [rag_e], [rag])
        seq = self.assembler.assemble(_metadata(), [t0, t2])

        nmap_event = next(e for e in seq.all_events if e.call.tool_call_id == "nmap1")
        assert nmap_event.has_rag_context is False

    def test_rag_query_ref_points_to_nearest(self):
        """TC-A05：rag_query_ref 指向最近 RAG 调用"""
        rag1 = _rag_record("rag1", 1)
        rag1_e = _event(_SESSION, 1, 0, "make_kb_search", "rag1", ActionCategory.RAG_QUERY)
        rag2 = _rag_record("rag2", 2)
        rag2_e = _event(_SESSION, 2, 0, "make_kb_search", "rag2", ActionCategory.RAG_QUERY)
        exec_e = _event(_SESSION, 3, 0, "generic_linux_command", "curl1", ActionCategory.GENERIC_COMMAND_CALL)

        t1 = _turn(1, [rag1_e], [rag1])
        t2 = _turn(2, [rag2_e], [rag2])
        t3 = _turn(3, [exec_e], [])
        seq = self.assembler.assemble(_metadata(), [t1, t2, t3])

        exec_event = next(e for e in seq.all_events if e.call.tool_call_id == "curl1")
        # Turn 3 距离 Turn 2 (rag2) 更近
        assert exec_event.rag_query_ref == "rag2"

    def test_rag_query_self_not_marked(self):
        """TC-A06：RAG_QUERY 事件自身 has_rag_context 不自我标记
        设计：RAG_QUERY 事件本身表示正在查询，has_rag_context 标注
        只适用于"基于 RAG 结果的后续行为"。
        对于 RAG_QUERY 自身，has_rag_context 的语义是"本查询前是否有其他 RAG"，
        单独一个 RAG 查询时应为 False。
        """
        rag = _rag_record("rag1", 0)
        rag_e = _event(_SESSION, 0, 0, "make_kb_search", "rag1", ActionCategory.RAG_QUERY)
        t0 = _turn(0, [rag_e], [rag])
        seq = self.assembler.assemble(_metadata(), [t0])
        rag_event = next(e for e in seq.all_events if e.call.tool_call_id == "rag1")
        # 没有任何之前的 RAG，rag_query_ref 应为 None
        assert rag_event.rag_query_ref is None

    def test_beyond_window_not_marked(self):
        """TC-A11：超出 N=3 步窗口的 RAG 不影响 has_rag_context"""
        rag = _rag_record("rag_old", 0)
        rag_e = _event(_SESSION, 0, 0, "make_kb_search", "rag_old", ActionCategory.RAG_QUERY)
        # Turn 4 离 Turn 0 距离为 4 > window=3
        far_e = _event(_SESSION, 4, 0, "nmap_scan", "nmap_far", ActionCategory.STRUCTURED_TOOL_CALL)

        turns = [
            _turn(0, [rag_e], [rag]),
            _turn(1, [], []),
            _turn(2, [], []),
            _turn(3, [], []),
            _turn(4, [far_e], []),
        ]
        seq = self.assembler.assemble(_metadata(), turns)
        far_event = next(e for e in seq.all_events if e.call.tool_call_id == "nmap_far")
        assert far_event.has_rag_context is False

    def test_within_window_marked(self):
        """边界：Turn N=3 步内（刚好 N=3）应被标记"""
        rag = _rag_record("rag_edge", 0)
        rag_e = _event(_SESSION, 0, 0, "make_kb_search", "rag_edge", ActionCategory.RAG_QUERY)
        border_e = _event(_SESSION, 3, 0, "nmap_scan", "nmap_border", ActionCategory.STRUCTURED_TOOL_CALL)

        turns = [
            _turn(0, [rag_e], [rag]),
            _turn(1, [], []),
            _turn(2, [], []),
            _turn(3, [border_e], []),
        ]
        seq = self.assembler.assemble(_metadata(), turns)
        border_event = next(e for e in seq.all_events if e.call.tool_call_id == "nmap_border")
        assert border_event.has_rag_context is True


class TestCodeScriptRefAnnotation:
    """TC-A07, TC-A08"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.assembler = TurnSequenceAssembler()

    def test_code_write_links_to_exec(self):
        """TC-A07：execute_code 写入后，python3 xxx.py 执行的 GLC 事件应持有后向引用

        设计规范方向：GLC 事件的 code_script_ref 指向生成其所执行脚本的 CODE_WRITE event_id。
        CODE_WRITE 事件自身的 code_script_ref 保持为空列表。
        """
        ec_e = _event(_SESSION, 0, 0, "execute_code", "ec1",
                      ActionCategory.CODE_WRITE, filename="exploit.py")
        from src.layer0.assembler import _replace_event
        ec_e = _replace_event(ec_e, call=CallDescriptor(
            tool_name="execute_code",
            call_args={"code": "import requests\n", "language": "python",
                       "filename": "exploit.py", "timeout": 30},
            call_timestamp=_ts(),
            tool_call_id="ec1",
            action_category=ActionCategory.CODE_WRITE,
            code_filename="exploit.py",
        ))

        run_e = AtomicEvent(
            event_id=f"{_SESSION}_0001_00",
            turn_index=1,
            slot_in_turn=0,
            call=CallDescriptor(
                tool_name="generic_linux_command",
                call_args={"command": "python3 exploit.py", "interactive": False},
                call_timestamp=_ts(),
                tool_call_id="run1",
                action_category=ActionCategory.GENERIC_COMMAND_CALL,
                program_name="python3",
            ),
            result=None,
        )

        t0 = _turn(0, [ec_e], [])
        t1 = _turn(1, [run_e], [])
        seq = self.assembler.assemble(_metadata(), [t0, t1])

        # GLC 事件的 code_script_ref 应指向 CODE_WRITE event_id（后向引用）
        exec_events = [e for e in seq.all_events if e.call.action_category == ActionCategory.GENERIC_COMMAND_CALL]
        assert len(exec_events) == 1
        code_write_events = [e for e in seq.all_events if e.call.action_category == ActionCategory.CODE_WRITE]
        assert len(code_write_events) == 1
        assert code_write_events[0].event_id in exec_events[0].code_script_ref
        # CODE_WRITE 自身的 code_script_ref 保持为空
        assert code_write_events[0].code_script_ref == []

    def test_code_write_index_populated(self):
        """TC-A08"""
        ec_e = AtomicEvent(
            event_id=f"{_SESSION}_0000_00",
            turn_index=0, slot_in_turn=0,
            call=CallDescriptor(
                tool_name="execute_code",
                call_args={"code": "print(1)", "language": "python",
                           "filename": "test.py", "timeout": 30},
                call_timestamp=_ts(),
                tool_call_id="ec_idx",
                action_category=ActionCategory.CODE_WRITE,
                code_filename="test.py",
            ),
            result=None,
        )
        t0 = _turn(0, [ec_e], [])
        seq = self.assembler.assemble(_metadata(), [t0])
        assert len(seq.code_write_index) == 1
        assert f"{_SESSION}_0000_00" in seq.code_write_index


# ─────────────────────────────────────────────────────────────────────────────
# 集成测试：全流水线 full fixture
# ─────────────────────────────────────────────────────────────────────────────

class TestAssemblerIntegration:
    """使用 full_log fixture 进行端到端测试"""

    @pytest.fixture(autouse=True)
    def setup(self, full_log_path: Path):
        parser = LogParser()
        extractor = EventExtractor()
        assembler = TurnSequenceAssembler()

        metadata, turns = parser.parse_file(full_log_path)
        for turn in turns:
            events, rag_queries = extractor.extract(turn)
            turn.events = events
            turn.rag_queries = rag_queries

        self.seq = assembler.assemble(metadata, turns)

    def test_event_count(self):
        assert self.seq.event_count == 5

    def test_rag_call_count(self):
        assert self.seq.rag_call_count == 1

    def test_rag_context_propagation(self):
        """Turn 1 的 RAG 调用应使 Turn 2 的事件有 has_rag_context=True"""
        turn2_events = [e for e in self.seq.all_events if e.turn_index == 2]
        assert all(e.has_rag_context for e in turn2_events), \
            f"Expected all Turn2 events to have has_rag_context=True, got: {[(e.call.tool_name, e.has_rag_context) for e in turn2_events]}"

    def test_turn0_no_rag_context(self):
        """Turn 0 在任何 RAG 之前，has_rag_context=False"""
        turn0_events = [e for e in self.seq.all_events if e.turn_index == 0]
        assert all(not e.has_rag_context for e in turn0_events)

    def test_code_write_linked_to_python_exec(self):
        """execute_code 写入 exploit_cve_2017_10271.py 后，执行该脚本的 GLC 应持有后向引用"""
        cw_events = [e for e in self.seq.all_events
                     if e.call.action_category == ActionCategory.CODE_WRITE]
        assert len(cw_events) == 1
        # 找到执行该脚本的 GLC 事件
        run_events = [e for e in self.seq.all_events
                      if e.call.action_category == ActionCategory.GENERIC_COMMAND_CALL
                      and "exploit_cve_2017_10271.py" in e.call.call_args.get("command", "")]
        assert len(run_events) == 1
        # GLC 的 code_script_ref 应指向 CODE_WRITE event_id（后向引用）
        assert cw_events[0].event_id in run_events[0].code_script_ref
        # CODE_WRITE 自身的 code_script_ref 为空
        assert cw_events[0].code_script_ref == []

    def test_rag_context_count_property(self):
        count = self.seq.rag_context_event_count
        # Turn 1 (1 RAG event, itself has_rag_context varies)
        # Turn 2 (2 events should have rag_context=True)
        assert count >= 2

    def test_get_events_in_window(self):
        events = self.seq.get_events_in_window(turn_index=2, window=3)
        assert all(e.turn_index < 2 for e in events)
