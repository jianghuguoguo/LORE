"""
tests/test_extractor.py
========================
测试覆盖：EventExtractor 的核心功能

TC-E01  STRUCTURED_TOOL_CALL 正确识别（nmap_scan）
TC-E02  RAG_QUERY 正确识别（make_kb_search）+ RagQueryRecord 生成
TC-E03  GENERIC_COMMAND_CALL 正确识别（generic_linux_command）
TC-E04  program_name 正确提取（首个可执行程序名）
TC-E05  CODE_WRITE 正确识别（execute_code）+ code_filename/language 提取
TC-E06  ResultDescriptor 正确构建（return_code, timed_out, success, stderr/stdout 映射）
TC-E07  工具结果缺失时 result=None（不抛异常）
TC-E08  多 tool_call 的 Turn 生成对应数量的 AtomicEvent
TC-E09  event_id 唯一性
TC-E10  call_args 原样保留（不做解析或截断）
TC-E11  program_name 跳过 sudo 等包装命令
TC-E12  no tool_calls → 空列表
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.layer0.extractor import EventExtractor, _extract_program_name
from src.layer0.parser import LogParser
from src.models import ActionCategory, AtomicEvent, Turn


# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数：构建最小 Turn 对象
# ─────────────────────────────────────────────────────────────────────────────

def _make_turn(session_id: str, turn_index: int,
               tool_calls: list, tool_results: dict) -> Turn:
    """构造带有 _tool_results 注入的最小 Turn 对象。"""
    return Turn(
        turn_index=turn_index,
        timestamp=datetime(2026, 2, 4, tzinfo=timezone.utc),
        session_id=session_id,
        assistant_message={"event": "assistant_message", "content": "",
                           "tool_calls": tool_calls},
        api_request={"messages": [], "_tool_results": tool_results},
        completion={"choices": []},
    )


def _tc(call_id: str, name: str, args: dict) -> dict:
    """构造 tool_call dict。"""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def _result(return_code: int = 0, timed_out: bool = False,
            success: bool = True, stderr: str = "", stdout: str = "") -> dict:
    return {
        "return_code": return_code,
        "timed_out": timed_out,
        "success": success,
        "stderr": stderr,
        "stdout": stdout,
        "partial_results": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 测试：program_name 提取（独立单元）
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractProgramName:
    def test_simple_command(self):
        """TC-E04a"""
        assert _extract_program_name("nmap -sV 127.0.0.1") == "nmap"

    def test_full_path(self):
        assert _extract_program_name("/usr/bin/nmap -sV") == "nmap"

    def test_sudo_wrapper(self):
        """TC-E11：sudo 之后的命令才是真正程序名"""
        assert _extract_program_name("sudo nmap -sV 127.0.0.1") == "nmap"

    def test_multi_wrapper(self):
        assert _extract_program_name("sudo timeout 30 hydra ...") == "hydra"

    def test_python_script(self):
        assert _extract_program_name("python3 exploit.py") == "python3"

    def test_bash_script(self):
        assert _extract_program_name("bash /tmp/reverse_shell.sh") == "bash"

    def test_empty_command(self):
        assert _extract_program_name("") is None

    def test_none_command(self):
        assert _extract_program_name(None) is None

    def test_env_var_prefix(self):
        """环境变量赋值前缀不影响程序名提取"""
        # FOO=bar nmap → nmap
        assert _extract_program_name("TERM=xterm nmap -sV") == "nmap"


# ─────────────────────────────────────────────────────────────────────────────
# 测试：EventExtractor 核心逻辑
# ─────────────────────────────────────────────────────────────────────────────

class TestEventExtractor:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.extractor = EventExtractor()

    # ── TC-E12：空 tool_calls ─────────────────────────────────────────

    def test_no_tool_calls_returns_empty(self):
        """TC-E12"""
        turn = _make_turn("s1", 0, [], {})
        events, rag_queries = self.extractor.extract(turn)
        assert events == []
        assert rag_queries == []

    def test_no_assistant_message_returns_empty(self):
        turn = Turn(
            turn_index=0,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            session_id="s1",
        )
        events, rag_queries = self.extractor.extract(turn)
        assert events == []

    # ── TC-E01：STRUCTURED_TOOL_CALL ─────────────────────────────────

    def test_nmap_is_structured(self):
        """TC-E01"""
        tc = _tc("id1", "nmap_scan", {"target": "127.0.0.1", "ports": "80"})
        turn = _make_turn("s1", 0, [tc], {"id1": _result(stdout="port 80 open")})
        events, _ = self.extractor.extract(turn)
        assert len(events) == 1
        assert events[0].call.action_category == ActionCategory.STRUCTURED_TOOL_CALL
        assert events[0].call.tool_name == "nmap_scan"
        assert events[0].call.program_name is None   # 仅 GENERIC_COMMAND 填充

    # ── TC-E10：call_args 原样保留 ────────────────────────────────────

    def test_call_args_preserved(self):
        """TC-E10"""
        args = {"target": "127.0.0.1", "ports": "7001", "scan_type": "sV",
                "additional_args": "-O --script vuln"}
        tc = _tc("id_args", "nmap_scan", args)
        turn = _make_turn("s1", 0, [tc], {})
        events, _ = self.extractor.extract(turn)
        assert events[0].call.call_args == args

    # ── TC-E02：RAG_QUERY ─────────────────────────────────────────────

    def test_make_kb_search_is_rag(self):
        """TC-E02a"""
        tc = _tc("rag1", "make_kb_search", {"query": "WebLogic CVE exploit", "limit": 10})
        turn = _make_turn("s1", 1, [tc], {
            "rag1": _result(stdout="# CVE-2017-10271\npayload: ...")
        })
        events, rag_queries = self.extractor.extract(turn)
        assert len(events) == 1
        assert events[0].call.action_category == ActionCategory.RAG_QUERY

    def test_rag_query_record_created(self):
        """TC-E02b：RagQueryRecord 正确生成"""
        tc = _tc("rag1", "make_kb_search", {"query": "WebLogic CVE exploit", "limit": 10})
        turn = _make_turn("s1", 1, [tc], {
            "rag1": _result(stdout="# CVE-2017-10271\npayload: ...")
        })
        _, rag_queries = self.extractor.extract(turn)
        assert len(rag_queries) == 1
        rq = rag_queries[0]
        assert rq.query == "WebLogic CVE exploit"
        assert rq.tool_call_id == "rag1"
        assert "CVE-2017-10271" in rq.rag_result

    def test_non_rag_tool_no_rag_query(self):
        """RAG_QUERY 以外的工具不产生 RagQueryRecord"""
        tc = _tc("id1", "nmap_scan", {"target": "127.0.0.1"})
        turn = _make_turn("s1", 0, [tc], {})
        _, rag_queries = self.extractor.extract(turn)
        assert rag_queries == []

    # ── TC-E03 / TC-E04：GENERIC_COMMAND_CALL + program_name ─────────

    def test_curl_is_generic(self):
        """TC-E03"""
        tc = _tc("curl1", "generic_linux_command",
                 {"command": "curl -s http://127.0.0.1:7001/console", "interactive": False})
        turn = _make_turn("s1", 0, [tc], {"curl1": _result(return_code=200)})
        events, _ = self.extractor.extract(turn)
        assert events[0].call.action_category == ActionCategory.GENERIC_COMMAND_CALL

    def test_program_name_extracted(self):
        """TC-E04"""
        tc = _tc("curl1", "generic_linux_command",
                 {"command": "curl -s http://127.0.0.1:7001", "interactive": False})
        turn = _make_turn("s1", 0, [tc], {})
        events, _ = self.extractor.extract(turn)
        assert events[0].call.program_name == "curl"

    # ── TC-E05：CODE_WRITE ─────────────────────────────────────────────

    def test_execute_code_is_code_write(self):
        """TC-E05a"""
        tc = _tc("ec1", "execute_code", {
            "code": "print('hello')", "language": "python",
            "filename": "test.py", "timeout": 30,
        })
        turn = _make_turn("s1", 0, [tc], {"ec1": _result(stdout="Script written.")})
        events, _ = self.extractor.extract(turn)
        assert events[0].call.action_category == ActionCategory.CODE_WRITE

    def test_code_write_extracts_filename_language(self):
        """TC-E05b"""
        tc = _tc("ec1", "execute_code", {
            "code": "import socket", "language": "python3",
            "filename": "reverse_shell.py", "timeout": 60,
        })
        turn = _make_turn("s1", 0, [tc], {})
        events, _ = self.extractor.extract(turn)
        assert events[0].call.code_filename == "reverse_shell.py"
        assert events[0].call.code_language == "python3"

    # ── TC-E06：ResultDescriptor 字段映射 ─────────────────────────────

    def test_result_return_code(self):
        """TC-E06a"""
        tc = _tc("id1", "nmap_scan", {"target": "127.0.0.1"})
        turn = _make_turn("s1", 0, [tc], {"id1": _result(return_code=1, success=False, stderr="error")})
        events, _ = self.extractor.extract(turn)
        r = events[0].result
        assert r is not None
        assert r.return_code == 1
        assert r.success is False
        assert r.stderr_raw == "error"
        assert r.timed_out is False

    def test_result_timed_out(self):
        """TC-E06b"""
        tc = _tc("id1", "generic_linux_command", {"command": "sleep 9999"})
        turn = _make_turn("s1", 0, [tc],
                          {"id1": _result(return_code=-1, timed_out=True, success=False)})
        events, _ = self.extractor.extract(turn)
        assert events[0].result.timed_out is True

    def test_result_stdout_preserved(self):
        """TC-E06c：stdout 原样保留"""
        stdout_str = "port 80/tcp open  http\nport 443/tcp open  https"
        tc = _tc("id1", "nmap_scan", {"target": "127.0.0.1"})
        turn = _make_turn("s1", 0, [tc], {"id1": _result(stdout=stdout_str)})
        events, _ = self.extractor.extract(turn)
        assert events[0].result.stdout_raw == stdout_str

    # ── TC-E07：工具结果缺失时 result=None ─────────────────────────────

    def test_no_result_when_missing(self):
        """TC-E07"""
        tc = _tc("id_missing", "nmap_scan", {"target": "127.0.0.1"})
        turn = _make_turn("s1", 0, [tc], {})  # _tool_results 中无对应 ID
        events, _ = self.extractor.extract(turn)
        assert events[0].result is None

    # ── TC-E08：多 tool_call ────────────────────────────────────────────

    def test_multiple_tool_calls_all_extracted(self):
        """TC-E08"""
        tc1 = _tc("id1", "nmap_scan", {"target": "127.0.0.1"})
        tc2 = _tc("id2", "make_kb_search", {"query": "WebLogic CVE"})
        tc3 = _tc("id3", "generic_linux_command", {"command": "curl -I http://127.0.0.1"})
        turn = _make_turn("s1", 0, [tc1, tc2, tc3], {
            "id1": _result(return_code=0),
            "id2": _result(stdout="# knowledge"),
            "id3": _result(return_code=200),
        })
        events, rag_queries = self.extractor.extract(turn)
        assert len(events) == 3
        assert len(rag_queries) == 1
        assert events[0].slot_in_turn == 0
        assert events[1].slot_in_turn == 1
        assert events[2].slot_in_turn == 2

    # ── TC-E09：event_id 唯一性 ────────────────────────────────────────

    def test_event_id_unique_across_two_turns(self):
        """TC-E09"""
        tc1 = _tc("a1", "nmap_scan", {"target": "127.0.0.1"})
        tc2 = _tc("b1", "nmap_scan", {"target": "10.0.0.1"})
        turn0 = _make_turn("s1", 0, [tc1], {})
        turn1 = _make_turn("s1", 1, [tc2], {})
        e0, _ = self.extractor.extract(turn0)
        e1, _ = self.extractor.extract(turn1)
        ids = [e.event_id for e in e0 + e1]
        assert len(set(ids)) == len(ids), f"Duplicate event IDs: {ids}"


# ─────────────────────────────────────────────────────────────────────────────
# 集成测试：Parser + Extractor 联动（使用 fixture 文件）
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractorWithRealFixture:
    """使用 make_full_session_jsonl() 的完整 3-Turn fixture"""

    @pytest.fixture(autouse=True)
    def setup(self, full_log_path: Path):
        parser = LogParser()
        _, self.turns = parser.parse_file(full_log_path)
        extractor = EventExtractor()
        for turn in self.turns:
            events, rag_queries = extractor.extract(turn)
            turn.events = events
            turn.rag_queries = rag_queries

    def test_total_events_count(self):
        """Turn0=1事件, Turn1=2事件, Turn2=2事件 → 共5个"""
        total = sum(len(t.events) for t in self.turns)
        assert total == 5

    def test_turn0_nmap_structured(self):
        assert self.turns[0].events[0].call.action_category == ActionCategory.STRUCTURED_TOOL_CALL
        assert self.turns[0].events[0].call.tool_name == "nmap_scan"

    def test_turn1_rag_query(self):
        events = self.turns[1].events
        rag_events = [e for e in events if e.call.action_category == ActionCategory.RAG_QUERY]
        assert len(rag_events) == 1
        assert len(self.turns[1].rag_queries) == 1

    def test_turn1_curl_generic(self):
        events = self.turns[1].events
        generic = [e for e in events if e.call.action_category == ActionCategory.GENERIC_COMMAND_CALL]
        assert len(generic) == 1
        assert generic[0].call.program_name == "curl"

    def test_turn2_execute_code(self):
        events = self.turns[2].events
        ec = [e for e in events if e.call.action_category == ActionCategory.CODE_WRITE]
        assert len(ec) == 1
        assert ec[0].call.code_filename == "exploit_cve_2017_10271.py"

    def test_turn2_python_generic(self):
        events = self.turns[2].events
        generic = [e for e in events if e.call.action_category == ActionCategory.GENERIC_COMMAND_CALL]
        assert len(generic) == 1
        assert generic[0].call.program_name == "python3"
