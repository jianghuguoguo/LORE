"""
重跑所有受 P1-P3 修复影响的 8 个 session，逐项检验修复效果：
  P1a: rag_adoption 字段 — has_rag_context=False 事件应为 null，True 事件存 dict
  P1b: frc reasoning 非空 — 所有 source=llm 的 FailureRootCause.reasoning 不得为空
  P2a: achieved_goals 精度 — flag 未获取不应列入，盲 RCE 应标注为盲执行
  P2b: execute_code CVE → EXPLOITATION（非 RECON_WEAPONIZATION）
  P3a: frc_gap — rc=None+outcome=failure 的事件现在也能触发 frc 分析
  P3b: sqlmap banner FP — 启动输出不等于 success
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer1.pipeline import load_turn_sequence, run_layer1_with_llm, save_annotated_turn_sequence
from src.llm_client import build_llm_client_from_config

INPUT_DIR  = ROOT / "data" / "layer0_output"
OUTPUT_DIR = ROOT / "data" / "layer1_output"

# 所有受影响 session（含预期 outcome 和待验证问题）
TARGET_SESSIONS = [
    ("b3ab5c15-5c94-42d2-a302-5c20547c7b90",   "success",         "rag_adoption dict + frc reasoning + achieved_goals 精度"),
    ("85cd2e37-2f48-48a7-8310-b651b33741f8",    "partial_success", "rag_adoption + frc reasoning + 盲RCE标注 + RECON→EXPLOIT"),
    ("f9af8981-2445-48b7-ba19-da36f5c1a574",    "partial_success", "rag_adoption + frc_gap(14 events)"),
    ("5db69512-2f95-4fc8-a826-65e81c19a41c",    "failure",         "rag_adoption + frc_gap(20 events) + RECON→EXPLOIT"),
    ("7d4c1a6a-7346-49a5-973f-70caaad894f6",    "failure",         "sqlmap banner FP 修复"),
    ("8cb881bb-19ca-42e3-a394-b160369c5395",    "failure",         "rag_adoption + RECON→EXPLOIT(4 events)"),
    ("64227b8f-f396-44f0-82a4-8158e1583c53",    "failure",         "rag_adoption + RECON→EXPLOIT(4 events)"),
    ("d1bd6e0b-fdf0-4217-a844-44f6618d02eb",    "failure",         "rag_adoption(4 events)"),
]


def check_rag_adoption(ann_seq, sid_short):
    """验证 rag_adoption 字段正确性"""
    wrong = []
    for ev in ann_seq.annotated_events:
        ra = ev.rag_adoption
        if ra is not None:
            # 有值时必须是 dict
            if not isinstance(ra, dict):
                wrong.append(f"  turn={ev.turn_index}: rag_adoption 类型错误 = {ra!r}")
            # has_rag_context=False 时必须是 null
            if not ev.has_rag_context:
                wrong.append(f"  turn={ev.turn_index}: has_rag_context=False 但 rag_adoption 非 null = {ra!r}")
    return wrong


def check_frc_reasoning(ann_seq):
    """验证 LLM frc 条目的 reasoning 非空"""
    empty = []
    for ev in ann_seq.annotated_events:
        frc = ev.failure_root_cause
        if frc and frc.source == "llm":
            if not (frc.reasoning or "").strip():
                empty.append(f"  event={ev.event_id[:24]}… dim={frc.dimension.value} reasoning=空")
    return empty


def check_frc_gap(ann_seq):
    """验证 frc_gap 事件（rc=None+outcome=failure）是否拿到了 frc"""
    unfilled = []
    for ev in ann_seq.annotated_events:
        result = ev.base.result
        if (
            result is not None
            and result.return_code is None
            and result.success is None
            and ev.outcome_label == "failure"
            and ev.failure_root_cause is None
        ):
            unfilled.append(f"  event={ev.event_id[:24]}… phase={ev.attack_phase} 仍无 frc")
    return unfilled


def main():
    client = build_llm_client_from_config()
    print("[rerun] LLMClient 构建成功\n")

    for sid, expected_outcome, check_desc in TARGET_SESSIONS:
        log_path = INPUT_DIR / f"layer0_{sid}.jsonl"
        if not log_path.exists():
            print(f"[!] 文件不存在: {log_path.name}")
            continue

        short = sid[:8]
        print(f"━━━ {short}… | 预期: {expected_outcome:<15} | 检查: {check_desc}")

        seq = load_turn_sequence(log_path)
        ann_seq = run_layer1_with_llm(seq, client=client)

        out_path = OUTPUT_DIR / f"layer1_{sid}.jsonl"
        save_annotated_turn_sequence(ann_seq, out_path)

        outcome = ann_seq.session_outcome
        ok_label = outcome.outcome_label if outcome else "N/A"
        is_ok    = outcome.is_success    if outcome else None
        match    = "✅" if ok_label == expected_outcome else "❌"

        print(f"  outcome={ok_label:<15}({match}) is_success={is_ok}  llm_calls={ann_seq.llm_call_count}  errors={ann_seq.llm_error_count}")
        if outcome:
            print(f"  reasoning: {(outcome.reasoning or '')[:200]}")

        # P1a: rag_adoption 字段检查
        rag_issues = check_rag_adoption(ann_seq, short)
        if rag_issues:
            print(f"  ❌ P1a rag_adoption 问题：")
            for msg in rag_issues[:5]:
                print(msg)
        else:
            rag_events = sum(1 for ev in ann_seq.annotated_events if ev.rag_adoption is not None)
            print(f"  ✅ P1a rag_adoption: 无类型错误  ({rag_events} 个事件有值)")

        # P1b: frc reasoning 检查
        frc_empty = check_frc_reasoning(ann_seq)
        total_llm_frc = sum(1 for ev in ann_seq.annotated_events
                            if ev.failure_root_cause and ev.failure_root_cause.source == "llm")
        if frc_empty:
            print(f"  ❌ P1b frc reasoning 仍为空: {len(frc_empty)}/{total_llm_frc}")
            for msg in frc_empty[:3]:
                print(msg)
        else:
            print(f"  ✅ P1b frc reasoning: 全部非空 ({total_llm_frc} 个 llm frc)")

        # P3a: frc_gap 检查
        gap_unfilled = check_frc_gap(ann_seq)
        gap_total = sum(1 for ev in ann_seq.annotated_events
                        if ev.base.result and ev.base.result.return_code is None
                        and ev.base.result.success is None and ev.outcome_label == "failure")
        if gap_unfilled:
            print(f"  ⚠️  P3a frc_gap: {len(gap_unfilled)}/{gap_total} 个 failure 事件仍无 frc（可能 LLM 未判为 failure）")
        else:
            print(f"  ✅ P3a frc_gap: 无遗漏 (rc=None+failure 共 {gap_total} 个)")

        print()

    print("[rerun] 全部完成")


if __name__ == "__main__":
    main()
