from __future__ import annotations

import json
from pathlib import Path

from src.layer0 import AdapterRegistry
from src.layer0.adapters.generic import GenericJsonlAdapter
from src.layer0.adapters.langchain import LangChainAdapter
from src.layer0.adapters.openai_assistant import OpenAIAssistantAdapter
from src.layer0.parser import LogParser
from src.layer0.pipeline import run_layer0
from src.models import ActionCategory
from src.utils.config_loader import get_config


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _openai_step(*, tc_type: str = "function") -> dict:
    if tc_type == "file_search":
        tool_call = {
            "id": "call_fs_1",
            "type": "file_search",
            "file_search": {
                "results": [
                    {"id": "doc_1", "text": "exploit note"},
                ]
            },
        }
    else:
        tool_call = {
            "id": "call_fn_1",
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "arguments": json.dumps({"target": "127.0.0.1"}),
                "output": json.dumps({"stdout": "ok", "return_code": 0}),
            },
        }

    return {
        "id": "step_1",
        "object": "thread.run.step",
        "type": "tool_calls",
        "created_at": 1710000000,
        "completed_at": 1710000005,
        "run_id": "run_abc",
        "thread_id": "thread_xyz",
        "step_details": {"tool_calls": [tool_call]},
    }


def test_openai_can_handle_large_pretty_json(tmp_path: Path) -> None:
    step = {
        "padding": "x" * 12000,
        **_openai_step(tc_type="function"),
    }
    log_path = tmp_path / "openai_large_pretty.json"
    _write_json(log_path, [step])

    assert OpenAIAssistantAdapter.can_handle(log_path)


def test_run_layer0_auto_detects_openai_array(tmp_path: Path) -> None:
    log_path = tmp_path / "openai_steps.json"
    _write_json(log_path, [_openai_step(tc_type="function")])

    adapter = AdapterRegistry.auto_detect(log_path)
    assert adapter.adapter_name == "openai_assistant"

    seq = run_layer0(log_path, get_config())
    assert seq.turn_count == 1
    assert seq.event_count == 1
    assert seq.metadata.session_id == "thread_xyz"
    assert seq.all_events[0].call.tool_name == "nmap_scan"


def test_run_layer0_preserves_rag_events_from_adapter(tmp_path: Path) -> None:
    log_path = tmp_path / "openai_rag.json"
    _write_json(log_path, [_openai_step(tc_type="file_search")])

    seq = run_layer0(log_path, get_config())
    assert seq.event_count == 1
    assert seq.rag_call_count == 1
    assert seq.all_events[0].call.action_category == ActionCategory.RAG_QUERY


def test_parser_skips_non_object_lines_instead_of_crashing(tmp_path: Path) -> None:
    log_path = tmp_path / "not_jsonl_array.json"
    _write_json(log_path, [_openai_step(tc_type="function")])

    parser = LogParser(get_config())
    metadata, turns = parser.parse_file(log_path)

    assert metadata.session_id
    assert turns == []


def test_langchain_adapter_parse_works_in_stream_mode(tmp_path: Path) -> None:
    log_path = tmp_path / "langchain_v2.jsonl"
    lines = [
        {"type": "on_chain_start", "run_id": "run_lc", "timestamp": "2026-01-01T00:00:00"},
        {"type": "on_tool_start", "run_id": "tool_1", "name": "search", "input": {"query": "cve"}},
        {
            "type": "on_tool_end",
            "run_id": "tool_1",
            "output": "ok",
            "timestamp": "2026-01-01T00:00:02",
            "run_metadata": {"return_code": 0},
        },
        {"type": "on_chain_end", "timestamp": "2026-01-01T00:00:03"},
    ]
    log_path.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in lines), encoding="utf-8")

    meta, turns = LangChainAdapter().parse(log_path)
    parsed = list(turns)

    assert meta.session_id == "run_lc"
    assert len(parsed) == 1
    assert parsed[0].tool_name == "search"


def test_generic_adapter_parse_works_in_stream_mode(tmp_path: Path) -> None:
    log_path = tmp_path / "generic.jsonl"
    lines = [
        {
            "session_id": "sess_x",
            "turn_index": 0,
            "timestamp": "2026-01-01T00:00:00",
            "tool_name": "generic_linux_command",
            "tool_args": {"command": "id"},
            "stdout": "uid=0(root)",
            "return_code": 0,
        },
        {
            "session_id": "sess_x",
            "turn_index": 1,
            "timestamp": "2026-01-01T00:00:01",
            "tool_name": "make_kb_search",
            "tool_args": {"query": "CVE-2021"},
            "stdout": "[]",
        },
    ]
    log_path.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in lines), encoding="utf-8")

    meta, turns = GenericJsonlAdapter().parse(log_path)
    parsed = list(turns)

    assert meta.session_id == "sess_x"
    assert len(parsed) == 2
    assert parsed[0].tool_name == "generic_linux_command"
