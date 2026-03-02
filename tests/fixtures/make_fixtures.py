"""
测试用 JSONL fixture 生成器
============================
生成严格模拟真实日志格式的最小化测试数据，覆盖：
- session_start / session_end
- user_message（含渗透目标）
- assistant_message（含 tool_calls）
- UNKNOWN API request（含 role=tool 工具结果）
- UNKNOWN chat.completion
- RAG 查询事件
- execute_code 事件
- generic_linux_command 事件
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

# 基准时间戳（ISO 8601 with timezone，匹配真实日志格式）
_T0 = datetime(2026, 2, 4, 13, 37, 14, tzinfo=timezone.utc)

def _ts(offset_seconds: float = 0) -> str:
    from datetime import timedelta
    return (_T0 + timedelta(seconds=offset_seconds)).isoformat()


def _tool_result_content(
    return_code: int = 0,
    timed_out: bool = False,
    success: bool = True,
    stderr: str = "",
    stdout: str = "",
    partial_results: bool = False,
) -> str:
    """生成真实日志格式的双层 JSON 工具结果内容。"""
    inner = json.dumps({
        "return_code": return_code,
        "timed_out": timed_out,
        "success": success,
        "stderr": stderr,
        "stdout": stdout,
        "partial_results": partial_results,
    })
    outer = json.dumps({"type": "text", "text": inner, "annotations": None, "meta": None})
    return outer


# ─────────────────────────────────────────────────────────────────────────────
# Fixture 1：最小化正常会话（3 个 Turn，逐步包含更多工具类型）
# ─────────────────────────────────────────────────────────────────────────────

SESSION_ID_FULL = "test-session-full-0001"
SESSION_ID_EMPTY = "test-session-empty-0002"
SESSION_ID_MULTI_TOOL = "test-session-multi-0003"


def make_full_session_jsonl() -> List[str]:
    """3 Turn 会话 fixture：
    Turn 0: nmap_scan（STRUCTURED_TOOL_CALL）
    Turn 1: make_kb_search（RAG_QUERY）+ generic_linux_command（GENERIC_COMMAND_CALL）
    Turn 2: execute_code（CODE_WRITE）+ generic_linux_command 执行脚本
    """
    sid = SESSION_ID_FULL
    lines: List[str] = []

    # session_start
    lines.append(json.dumps({
        "event": "session_start",
        "timestamp": _ts(0),
        "session_id": sid,
    }))

    # user_message（渗透目标）
    lines.append(json.dumps({
        "event": "user_message",
        "timestamp": _ts(1),
        "content": "渗透测试目标：http://127.0.0.1:7001",
    }))

    # ── Turn 0：nmap_scan ────────────────────────────────────────────────
    nmap_call_id = "call_turn0_nmap"
    lines.append(json.dumps({
        "event": "assistant_message",
        "timestamp": _ts(2),
        "content": "",
        "tool_calls": [{
            "id": nmap_call_id,
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "arguments": json.dumps({
                    "target": "127.0.0.1",
                    "ports": "7001",
                    "scan_type": "sV",
                    "additional_args": "-sC",
                }),
            },
        }],
    }))

    nmap_result_content = _tool_result_content(
        return_code=0,
        stdout="7001/tcp open  http  Oracle WebLogic Server 10.3.6.0",
    )

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "",
        "timestamp": _ts(5),
        "messages": [
            {"role": "system", "content": "You are a penetration testing assistant."},
            {"role": "user", "content": "渗透测试目标：http://127.0.0.1:7001"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": nmap_call_id, "type": "function",
                "function": {"name": "nmap_scan",
                             "arguments": json.dumps({"target": "127.0.0.1", "ports": "7001",
                                                       "scan_type": "sV", "additional_args": "-sC"})}
            }]},
            {"role": "tool", "tool_call_id": nmap_call_id, "content": nmap_result_content},
        ],
    }))

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "chat.completion",
        "timestamp": _ts(6),
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_turn1_rag",
                    "type": "function",
                    "function": {
                        "name": "make_kb_search",
                        "arguments": json.dumps({"query": "WebLogic 10.3.6 CVE exploit", "limit": 10}),
                    },
                }],
            },
        }],
    }))

    # ── Turn 1：make_kb_search + curl ────────────────────────────────────
    rag_call_id = "call_turn1_rag"
    curl_call_id = "call_turn1_curl"

    lines.append(json.dumps({
        "event": "assistant_message",
        "timestamp": _ts(7),
        "content": "",
        "tool_calls": [
            {
                "id": rag_call_id,
                "type": "function",
                "function": {
                    "name": "make_kb_search",
                    "arguments": json.dumps({"query": "WebLogic 10.3.6 CVE exploit", "limit": 10}),
                },
            },
            {
                "id": curl_call_id,
                "type": "function",
                "function": {
                    "name": "generic_linux_command",
                    "arguments": json.dumps({
                        "command": "curl -s -I http://127.0.0.1:7001/console",
                        "interactive": False,
                    }),
                },
            },
        ],
    }))

    rag_result_content = _tool_result_content(
        return_code=0,
        stdout="# CVE-2017-10271\n## WebLogic XMLDecoder RCE\nPayload: POST /wls-wsat/...",
    )
    curl_result_content = _tool_result_content(
        return_code=0,
        stdout="HTTP/1.1 200 OK\nServer: WebLogic Server 10.3.6",
    )

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "",
        "timestamp": _ts(12),
        "messages": [
            {"role": "system", "content": "You are a penetration testing assistant."},
            {"role": "user", "content": "渗透测试目标：http://127.0.0.1:7001"},
            {"role": "tool", "tool_call_id": nmap_call_id, "content": nmap_result_content},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": rag_call_id, "type": "function",
                 "function": {"name": "make_kb_search",
                              "arguments": json.dumps({"query": "WebLogic 10.3.6 CVE exploit", "limit": 10})}},
                {"id": curl_call_id, "type": "function",
                 "function": {"name": "generic_linux_command",
                              "arguments": json.dumps({"command": "curl -s -I http://127.0.0.1:7001/console",
                                                        "interactive": False})}},
            ]},
            {"role": "tool", "tool_call_id": rag_call_id, "content": rag_result_content},
            {"role": "tool", "tool_call_id": curl_call_id, "content": curl_result_content},
        ],
    }))

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "chat.completion",
        "timestamp": _ts(13),
        "choices": [{"message": {
            "role": "assistant", "content": "",
            "tool_calls": [{"id": "call_turn2_execute", "type": "function",
                            "function": {"name": "execute_code",
                                         "arguments": json.dumps({"code": "import requests\nprint('probe')",
                                                                   "language": "python",
                                                                   "filename": "exploit_cve_2017_10271.py",
                                                                   "timeout": 30})}}]
        }}],
    }))

    # ── Turn 2：execute_code + python 执行脚本 ───────────────────────────
    ec_call_id = "call_turn2_execute"
    run_call_id = "call_turn2_run_script"

    lines.append(json.dumps({
        "event": "assistant_message",
        "timestamp": _ts(14),
        "content": "",
        "tool_calls": [
            {
                "id": ec_call_id,
                "type": "function",
                "function": {
                    "name": "execute_code",
                    "arguments": json.dumps({
                        "code": "import requests\nresp = requests.post('http://127.0.0.1:7001/wls-wsat/')\nprint(resp.status_code)",
                        "language": "python",
                        "filename": "exploit_cve_2017_10271.py",
                        "timeout": 30,
                    }),
                },
            },
            {
                "id": run_call_id,
                "type": "function",
                "function": {
                    "name": "generic_linux_command",
                    "arguments": json.dumps({
                        "command": "python3 exploit_cve_2017_10271.py",
                        "interactive": False,
                    }),
                },
            },
        ],
    }))

    ec_result_content = _tool_result_content(
        return_code=0, success=True,
        stdout="Script written to exploit_cve_2017_10271.py",
    )
    run_result_content = _tool_result_content(
        return_code=0, success=True,
        stdout="200",
    )

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "",
        "timestamp": _ts(20),
        "messages": [
            {"role": "tool", "tool_call_id": nmap_call_id, "content": nmap_result_content},
            {"role": "tool", "tool_call_id": rag_call_id, "content": rag_result_content},
            {"role": "tool", "tool_call_id": curl_call_id, "content": curl_result_content},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": ec_call_id, "type": "function",
                 "function": {"name": "execute_code",
                              "arguments": json.dumps({"code": "import requests\n...",
                                                        "language": "python",
                                                        "filename": "exploit_cve_2017_10271.py",
                                                        "timeout": 30})}},
                {"id": run_call_id, "type": "function",
                 "function": {"name": "generic_linux_command",
                              "arguments": json.dumps({"command": "python3 exploit_cve_2017_10271.py",
                                                        "interactive": False})}},
            ]},
            {"role": "tool", "tool_call_id": ec_call_id, "content": ec_result_content},
            {"role": "tool", "tool_call_id": run_call_id, "content": run_result_content},
        ],
    }))

    lines.append(json.dumps({
        "event": "UNKNOWN",
        "object": "chat.completion",
        "timestamp": _ts(21),
        "choices": [{"message": {"role": "assistant", "content": "Attack complete.", "tool_calls": []}}],
    }))

    # session_end
    lines.append(json.dumps({
        "event": "session_end",
        "timestamp": _ts(25),
        "session_id": sid,
        "timing_metrics": {
            "active_time_seconds": 20.0,
            "idle_time_seconds": 5.0,
            "total_time_seconds": 25.0,
            "active_percentage": 80.0,
        },
        "cost": {"total_cost": 0.0523},
    }))

    return lines


def make_minimal_session_jsonl() -> List[str]:
    """最小化 2 行 fixture：仅含 session_start 和 session_end，无任何 Turn。"""
    sid = SESSION_ID_EMPTY
    return [
        json.dumps({"event": "session_start", "timestamp": _ts(0), "session_id": sid}),
        json.dumps({
            "event": "session_end", "timestamp": _ts(1), "session_id": sid,
            "timing_metrics": {}, "cost": {"total_cost": 0.0},
        }),
    ]


def make_failure_session_jsonl() -> List[str]:
    """包含失败工具调用的 fixture：
    Turn 0: gobuster_scan（STRUCTURED_TOOL_CALL，失败 return_code=1）
    Turn 1: generic_linux_command dirb（GENERIC_COMMAND_CALL，127=命令不存在）
    Turn 2: generic_linux_command sleep（timed_out=True）
    """
    sid = "test-session-failure-0004"
    lines: List[str] = []
    lines.append(json.dumps({"event": "session_start", "timestamp": _ts(0), "session_id": sid}))
    lines.append(json.dumps({"event": "user_message", "timestamp": _ts(1),
                              "content": "目标：http://127.0.0.1:7001"}))

    # Turn 0: gobuster失败
    gob_id = "call_f0_gobuster"
    lines.append(json.dumps({
        "event": "assistant_message", "timestamp": _ts(2), "content": "",
        "tool_calls": [{"id": gob_id, "type": "function", "function": {
            "name": "gobuster_scan",
            "arguments": json.dumps({"url": "http://127.0.0.1:7001", "mode": "dir"}),
        }}],
    }))
    gob_result = _tool_result_content(
        return_code=1, success=False,
        stderr="WordList (-w): Must be specified\nUrl/Domain (-u): Must be specified",
    )
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "", "timestamp": _ts(5),
        "messages": [
            {"role": "tool", "tool_call_id": gob_id, "content": gob_result},
        ],
    }))
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "chat.completion", "timestamp": _ts(6),
        "choices": [{"message": {"role": "assistant", "content": "", "tool_calls": []}}],
    }))

    # Turn 1: dirb not found (return_code=127)
    dirb_id = "call_f1_dirb"
    lines.append(json.dumps({
        "event": "assistant_message", "timestamp": _ts(7), "content": "",
        "tool_calls": [{"id": dirb_id, "type": "function", "function": {
            "name": "generic_linux_command",
            "arguments": json.dumps({"command": "dirb http://127.0.0.1:7001", "interactive": False}),
        }}],
    }))
    dirb_result = _tool_result_content(
        return_code=127, success=False,
        stderr="bash: dirb: command not found",
    )
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "", "timestamp": _ts(10),
        "messages": [
            {"role": "tool", "tool_call_id": gob_id, "content": gob_result},
            {"role": "tool", "tool_call_id": dirb_id, "content": dirb_result},
        ],
    }))
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "chat.completion", "timestamp": _ts(11),
        "choices": [{"message": {"role": "assistant", "content": "", "tool_calls": []}}],
    }))

    # Turn 2: timed_out
    sleep_id = "call_f2_sleep"
    lines.append(json.dumps({
        "event": "assistant_message", "timestamp": _ts(12), "content": "",
        "tool_calls": [{"id": sleep_id, "type": "function", "function": {
            "name": "generic_linux_command",
            "arguments": json.dumps({"command": "sleep 9999", "interactive": False}),
        }}],
    }))
    sleep_result = _tool_result_content(
        return_code=-1, timed_out=True, success=False,
        stderr="", stdout="",
    )
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "", "timestamp": _ts(18),
        "messages": [
            {"role": "tool", "tool_call_id": dirb_id, "content": dirb_result},
            {"role": "tool", "tool_call_id": sleep_id, "content": sleep_result},
        ],
    }))
    lines.append(json.dumps({
        "event": "UNKNOWN", "object": "chat.completion", "timestamp": _ts(19),
        "choices": [{"message": {"role": "assistant", "content": "", "tool_calls": []}}],
    }))

    lines.append(json.dumps({
        "event": "session_end", "timestamp": _ts(20), "session_id": sid,
        "timing_metrics": {}, "cost": {"total_cost": 0.001},
    }))
    return lines


def write_fixtures(output_dir: "Path") -> None:  # type: ignore[name-defined]
    """将所有 fixture 写入 output_dir 目录。"""
    from pathlib import Path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "cai_test-session-full-0001.jsonl": make_full_session_jsonl(),
        "cai_test-session-empty-0002.jsonl": make_minimal_session_jsonl(),
        "cai_test-session-failure-0004.jsonl": make_failure_session_jsonl(),
    }
    for fname, lines in fixtures.items():
        path = output_dir / fname
        with open(path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
