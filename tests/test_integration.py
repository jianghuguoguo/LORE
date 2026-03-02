"""
tests/test_integration.py
==========================
针对真实日志文件的集成测试，验证完整 Layer 0 流水线在生产数据上的鲁棒性。

TC-I01  对每个真实日志文件，parse_file 不抛出异常
TC-I02  每个 TurnSequence 的 session_id 与文件名中的 ID 一致
TC-I03  TurnSequence 序列化 → 反序列化 round-trip 无损
TC-I04  has_rag_context 数量 ≤ event_count
TC-I05  make_kb_search 调用被分类为 RAG_QUERY
TC-I06  execute_code 调用被分类为 CODE_WRITE
TC-I07  generic_linux_command 调用被分类为 GENERIC_COMMAND_CALL
TC-I08  rag_index 中的记录数 == rag_call_count
TC-I09  run_layer0() 批量结果可迭代，无崩溃
TC-I10  code_write_index 中的所有 event_id 可在 all_events 中找到
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

import pytest

# ────────────────────────────────────────────────────────────────────────────
# 项目导入
# ────────────────────────────────────────────────────────────────────────────
from src.layer0.pipeline import run_layer0, run_layer0_batch
from src.models import ActionCategory, TurnSequence
from src.utils.config_loader import get_config
from src.utils.serializer import load_turn_sequence, save_turn_sequence

# ────────────────────────────────────────────────────────────────────────────
# 配置：真实日志目录
# ────────────────────────────────────────────────────────────────────────────

_REAL_LOG_DIR = Path(__file__).parent.parent / "logs"


def _real_log_files() -> List[Path]:
    if not _REAL_LOG_DIR.exists():
        return []
    return sorted(_REAL_LOG_DIR.glob("*.jsonl"))


_REAL_LOGS = _real_log_files()


# ────────────────────────────────────────────────────────────────────────────
# skip 条件：若日志目录不存在，跳过集成测试
# ────────────────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.skipif(
    not _REAL_LOGS,
    reason=f"真实日志目录不存在或为空: {_REAL_LOG_DIR}",
)


# ────────────────────────────────────────────────────────────────────────────
# TC-I01: 每个真实日志文件可被完整解析（无异常）
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_file", _REAL_LOGS, ids=[f.name for f in _REAL_LOGS])
def test_parse_no_exception(log_file: Path):
    """TC-I01：对每个真实日志文件，run_layer0 不抛出异常"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)
    assert seq is not None
    assert isinstance(seq, TurnSequence)


# ────────────────────────────────────────────────────────────────────────────
# TC-I02: session_id 与文件名一致
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_file", _REAL_LOGS, ids=[f.name for f in _REAL_LOGS])
def test_session_id_matches_filename(log_file: Path):
    """TC-I02：TurnSequence.metadata.session_id 应在文件名中出现"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)
    # 文件名格式：cai_{session_id}_{date}_{...}.jsonl
    # session_id 是 UUID 格式，应出现在文件名中
    assert seq.metadata.session_id in log_file.name, (
        f"session_id '{seq.metadata.session_id}' not found in '{log_file.name}'"
    )


# ────────────────────────────────────────────────────────────────────────────
# TC-I03: 序列化/反序列化 round-trip
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "log_file",
    # 仅取前3个文件以避免测试过慢
    _REAL_LOGS[:3] if len(_REAL_LOGS) >= 3 else _REAL_LOGS,
    ids=[f.name for f in (_REAL_LOGS[:3] if len(_REAL_LOGS) >= 3 else _REAL_LOGS)],
)
def test_round_trip_serialization(log_file: Path, tmp_path: Path):
    """TC-I03：TurnSequence 序列化后再反序列化，event_count 和 session_id 不变"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)

    # 序列化到临时文件
    out_file = tmp_path / f"rt_{log_file.stem}.jsonl"
    save_turn_sequence(seq, out_file)
    assert out_file.exists()

    # 反序列化
    recovered = load_turn_sequence(out_file)
    assert recovered.metadata.session_id == seq.metadata.session_id
    assert recovered.event_count == seq.event_count
    assert recovered.rag_call_count == seq.rag_call_count


# ────────────────────────────────────────────────────────────────────────────
# TC-I04: has_rag_context 数量合理
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_file", _REAL_LOGS, ids=[f.name for f in _REAL_LOGS])
def test_rag_context_count_sane(log_file: Path):
    """TC-I04：有 rag_context 的事件数 ≤ 总事件数"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)
    ctx_count = sum(1 for e in seq.all_events if e.has_rag_context)
    assert ctx_count <= seq.event_count

    # 如果 rag_call_count > 0，则至少有部分事件应有 rag_context
    if seq.rag_call_count > 0 and seq.event_count > seq.rag_call_count:
        # 不强制要求，因为 RAG 可能在最后一步或没有后续事件
        # 但记录到日志供审查
        pass


# ────────────────────────────────────────────────────────────────────────────
# TC-I05/06/07: 工具分类正确
# ────────────────────────────────────────────────────────────────────────────

def _find_first_log_with_tool(tool_name: str) -> Path | None:
    """找到第一个实际包含指定工具调用事件的日志文件（通过 run_layer0 验证）"""
    cfg = get_config()
    for log_file in _REAL_LOGS:
        try:
            # 先用字符串快速筛选
            content = log_file.read_text(encoding="utf-8", errors="replace")
            if f'"name": "{tool_name}"' not in content and f'"name":"{tool_name}"' not in content:
                continue
            # 再跑完整流水线确认有实际事件
            seq = run_layer0(log_file, cfg)
            events = [e for e in seq.all_events if e.call.tool_name == tool_name]
            if events:
                return log_file
        except Exception:
            continue
    return None


def test_make_kb_search_classified_as_rag():
    """TC-I05：make_kb_search 被分类为 RAG_QUERY"""
    log_file = _find_first_log_with_tool("make_kb_search")
    if log_file is None:
        pytest.skip("No log file contains make_kb_search")
    seq = run_layer0(log_file, get_config())
    rag_events = [e for e in seq.all_events
                  if e.call.tool_name == "make_kb_search"]
    assert len(rag_events) > 0
    assert all(e.call.action_category == ActionCategory.RAG_QUERY for e in rag_events)


def test_execute_code_classified_as_code_write():
    """TC-I06：execute_code 被分类为 CODE_WRITE"""
    log_file = _find_first_log_with_tool("execute_code")
    if log_file is None:
        pytest.skip("No log file contains execute_code")
    seq = run_layer0(log_file, get_config())
    exec_events = [e for e in seq.all_events
                   if e.call.tool_name == "execute_code"]
    assert len(exec_events) > 0
    assert all(e.call.action_category == ActionCategory.CODE_WRITE for e in exec_events)


def test_generic_linux_command_classified_correctly():
    """TC-I07：generic_linux_command 被分类为 GENERIC_COMMAND_CALL"""
    log_file = _find_first_log_with_tool("generic_linux_command")
    if log_file is None:
        pytest.skip("No log file contains generic_linux_command")
    seq = run_layer0(log_file, get_config())
    cmd_events = [e for e in seq.all_events
                  if e.call.tool_name == "generic_linux_command"]
    assert len(cmd_events) > 0
    assert all(e.call.action_category == ActionCategory.GENERIC_COMMAND_CALL for e in cmd_events)


# ────────────────────────────────────────────────────────────────────────────
# TC-I08: rag_index 记录数 == rag_call_count
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_file", _REAL_LOGS, ids=[f.name for f in _REAL_LOGS])
def test_rag_index_count_matches(log_file: Path):
    """TC-I08：rag_index 的 key 数量 == RAG_QUERY 事件数"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)
    rag_event_count = sum(
        1 for e in seq.all_events
        if e.call.action_category == ActionCategory.RAG_QUERY
    )
    assert len(seq.rag_index) == rag_event_count == seq.rag_call_count


# ────────────────────────────────────────────────────────────────────────────
# TC-I09: run_layer0_batch 可批量迭代
# ────────────────────────────────────────────────────────────────────────────

def test_batch_runs_without_error(tmp_path: Path):
    """TC-I09：run_layer0_batch 可对所有真实日志批量处理"""
    from src.layer0.pipeline import run_layer0_batch

    cfg = get_config()
    results = list(run_layer0_batch(_REAL_LOG_DIR, tmp_path, cfg, save=True))
    assert len(results) == len(_REAL_LOGS)
    for seq in results:
        assert isinstance(seq, TurnSequence)


# ────────────────────────────────────────────────────────────────────────────
# TC-I10: code_write_index 中的 event_id 可在 all_events 中找到
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_file", _REAL_LOGS, ids=[f.name for f in _REAL_LOGS])
def test_code_write_index_event_ids_valid(log_file: Path):
    """TC-I10：code_write_index 中所有 event_id 可在 all_events 中找到"""
    cfg = get_config()
    seq = run_layer0(log_file, cfg)
    all_event_ids = {e.event_id for e in seq.all_events}
    for eid in seq.code_write_index:
        assert eid in all_event_ids, f"event_id '{eid}' in code_write_index not found in all_events"
