"""
tests/test_parser.py
=====================
测试覆盖：LogParser 的核心功能

TC-P01  session_start / session_end 元数据正确提取
TC-P02  Turn 数量大于零（3 Turn fixture）
TC-P03  每个 Turn 包含三段式完整结构（assistant_message / api_request / completion）
TC-P04  Turn.api_request["_tool_results"] 正确注入工具结果
TC-P05  target_raw 从 user_message 正确提取（含中文关键词）
TC-P06  空会话（仅 session_start/end，无 assistant_message）→ turns=[]
TC-P07  return_code=127 的工具结果被正确解析
TC-P08  timed_out=True 的工具结果被正确解析
TC-P09  双层 JSON 格式的工具结果内容正确解析
TC-P10  不存在的文件抛出 FileNotFoundError
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.layer0.parser import (
    LogParser,
    _classify_line,
    _LineType,
    _parse_tool_result_content,
)
from src.models import Turn


class TestClassifyLine:
    """TC-P 前置：行类型识别单元测试"""

    def test_session_start(self):
        assert _classify_line({"event": "session_start", "session_id": "x"}) == _LineType.SESSION_START

    def test_session_end(self):
        assert _classify_line({"event": "session_end"}) == _LineType.SESSION_END

    def test_user_message(self):
        assert _classify_line({"event": "user_message", "content": "tgt"}) == _LineType.USER_MESSAGE

    def test_assistant_message(self):
        assert _classify_line({"event": "assistant_message", "tool_calls": []}) == _LineType.ASSISTANT_MSG

    def test_api_request(self):
        assert _classify_line({"event": "UNKNOWN", "object": "", "messages": []}) == _LineType.API_REQUEST

    def test_completion(self):
        assert _classify_line({"event": "UNKNOWN", "object": "chat.completion", "choices": []}) == _LineType.COMPLETION

    def test_fallback_by_messages_key(self):
        """兼容：event 字段缺失但有 messages 键"""
        assert _classify_line({"messages": []}) == _LineType.API_REQUEST

    def test_fallback_by_choices_key(self):
        """兼容：event 字段缺失但有 choices 键"""
        assert _classify_line({"choices": []}) == _LineType.COMPLETION


class TestParseToolResultContent:
    """TC-P09：双层 JSON 工具结果解析"""

    def test_double_wrapped(self):
        import json
        inner = json.dumps({"return_code": 0, "timed_out": False, "success": True,
                            "stderr": "", "stdout": "port open"})
        outer = json.dumps({"type": "text", "text": inner, "annotations": None})
        result = _parse_tool_result_content(outer)
        assert result["return_code"] == 0
        assert result["stdout"] == "port open"
        assert result["timed_out"] is False

    def test_return_code_127(self):
        import json
        inner = json.dumps({"return_code": 127, "success": False,
                            "stderr": "bash: dirb: command not found", "stdout": "",
                            "timed_out": False})
        outer = json.dumps({"type": "text", "text": inner})
        result = _parse_tool_result_content(outer)
        assert result["return_code"] == 127

    def test_timed_out_true(self):
        import json
        inner = json.dumps({"return_code": -1, "timed_out": True, "success": False,
                            "stderr": "", "stdout": ""})
        outer = json.dumps({"type": "text", "text": inner})
        result = _parse_tool_result_content(outer)
        assert result["timed_out"] is True

    def test_already_dict(self):
        result = _parse_tool_result_content({"return_code": 0})
        assert result["return_code"] == 0

    def test_malformed_falls_back(self):
        result = _parse_tool_result_content("not json at all")
        assert "_raw_text" in result


class TestLogParserFullSession:
    """TC-P01 ~ TC-P05 使用 full fixture"""

    @pytest.fixture(autouse=True)
    def setup(self, full_log_path: Path):
        parser = LogParser()
        self.metadata, self.turns = parser.parse_file(full_log_path)

    def test_session_id_extracted(self):
        """TC-P01a"""
        assert self.metadata.session_id == "test-session-full-0001"

    def test_start_time_parsed(self):
        """TC-P01b"""
        assert self.metadata.start_time is not None

    def test_end_time_parsed(self):
        """TC-P01c"""
        assert self.metadata.end_time is not None

    def test_total_cost_parsed(self):
        """TC-P01d"""
        assert abs(self.metadata.total_cost - 0.0523) < 1e-6

    def test_target_raw_extracted(self):
        """TC-P05：渗透目标包含中文关键词"""
        assert self.metadata.target_raw is not None
        assert "127.0.0.1" in self.metadata.target_raw or "渗透测试目标" in self.metadata.target_raw

    def test_three_turns(self):
        """TC-P02：fixture 有 3 个 assistant_message with tool_calls"""
        assert len(self.turns) == 3

    def test_turn_order(self):
        """Turn 按顺序排列"""
        indices = [t.turn_index for t in self.turns]
        assert indices == sorted(indices)

    def test_turn_has_assistant_message(self):
        """TC-P03a"""
        for turn in self.turns:
            assert turn.assistant_message is not None

    def test_turn_has_api_request(self):
        """TC-P03b"""
        for turn in self.turns:
            assert turn.api_request is not None

    def test_turn_has_completion(self):
        """TC-P03c"""
        for turn in self.turns:
            assert turn.completion is not None

    def test_tool_results_injected(self):
        """TC-P04：_tool_results 字典注入正确"""
        turn0 = self.turns[0]
        tr = turn0.api_request.get("_tool_results", {})
        assert "call_turn0_nmap" in tr
        nmap_res = tr["call_turn0_nmap"]
        assert nmap_res["return_code"] == 0
        assert "WebLogic" in nmap_res["stdout"]

    def test_turn1_both_tool_results_injected(self):
        """Turn 1 有两个工具调用，均有结果"""
        turn1 = self.turns[1]
        tr = turn1.api_request.get("_tool_results", {})
        assert "call_turn1_rag" in tr
        assert "call_turn1_curl" in tr

    def test_turn2_execute_code_result(self):
        """Turn 2 execute_code 结果正确"""
        turn2 = self.turns[2]
        tr = turn2.api_request.get("_tool_results", {})
        assert "call_turn2_execute" in tr
        assert tr["call_turn2_execute"]["return_code"] == 0


class TestLogParserEmptySession:
    """TC-P06：空会话"""

    def test_no_turns(self, empty_log_path: Path):
        parser = LogParser()
        metadata, turns = parser.parse_file(empty_log_path)
        assert turns == []
        assert metadata.session_id == "test-session-empty-0002"


class TestLogParserFailureSession:
    """TC-P07 / TC-P08：失败工具结果"""

    @pytest.fixture(autouse=True)
    def setup(self, failure_log_path: Path):
        parser = LogParser()
        self.metadata, self.turns = parser.parse_file(failure_log_path)

    def test_three_failure_turns(self):
        assert len(self.turns) == 3

    def test_return_code_1_injected(self):
        """TC-P07a：gobuster return_code=1"""
        tr = self.turns[0].api_request.get("_tool_results", {})
        assert tr["call_f0_gobuster"]["return_code"] == 1
        assert tr["call_f0_gobuster"]["success"] is False

    def test_return_code_127_injected(self):
        """TC-P07b：dirb return_code=127"""
        tr = self.turns[1].api_request.get("_tool_results", {})
        assert tr["call_f1_dirb"]["return_code"] == 127

    def test_timed_out_injected(self):
        """TC-P08：sleep timed_out=True"""
        tr = self.turns[2].api_request.get("_tool_results", {})
        assert tr["call_f2_sleep"]["timed_out"] is True


class TestLogParserFileNotFound:
    """TC-P10"""

    def test_raises_file_not_found(self):
        parser = LogParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file(Path("/nonexistent/path/to/log.jsonl"))
