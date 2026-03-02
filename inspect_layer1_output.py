"""查看 Phase 3 批量处理结果详情"""
import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "data" / "layer1_output"

# ── 选一个有 RAG 查询的会话（5db69512，44 events，2 RAG queries）
p = OUTPUT_DIR / "layer1_5db69512-2f95-4fc8-a826-65e81c19a41c.jsonl"
d = json.loads(p.read_text(encoding="utf-8"))

print("=== 会话基本信息 ===")
print(f"session_id   : {d['metadata']['session_id']}")
print(f"llm_processed: {d['llm_processed']}")
print(f"llm_calls    : {d['llm_call_count']}")
print(f"llm_errors   : {d['llm_error_count']}")
print(f"bar_score    : {d['bar_score']}")
print(f"det_hits     : {d['deterministic_hits']}")
print(f"total_events : {len(d['annotated_events'])}")

so = d.get("session_outcome")
if so:
    print("\n=== Session Outcome ===")
    print(f"  is_success     : {so['is_success']}")
    print(f"  outcome_label  : {so['outcome_label']}")
    print(f"  session_goal   : {so['session_goal_achieved']}")
    print(f"  achieved_goals : {so['achieved_goals']}")
    print(f"  failed_goals   : {so['failed_goals']}")
    print(f"  reasoning      : {so['reasoning'][:300]}")

print("\n=== 前 10 个事件 attack_phase ===")
for ae in d["annotated_events"][:10]:
    event_id = ae["base"]["event_id"]
    phase = ae.get("attack_phase", "N/A")
    outcome = ae.get("outcome_label", "N/A")
    tool = ae["base"]["call"]["tool_name"]
    print(f"  [{event_id[-6:]}] {tool:<30} phase={phase:<22} outcome={outcome}")

print("\n=== 失败根因 ===")
for ae in d["annotated_events"]:
    frc = ae.get("failure_root_cause")
    if frc:
        source = frc.get("source", "?")
        dim = frc.get("dimension", "?")
        sub = frc.get("sub_dimension", "?")
        evidence = frc.get("evidence", "")[:60]
        print(f"  [{ae['base']['event_id'][-6:]}] {source:<5} {dim}/{sub}  evidence={evidence!r}")

print("\n=== RAG 采纳结果 ===")
for r in d.get("rag_adoption_results", []):
    print(f"  rag_id  = {r['rag_tool_call_id']}")
    print(f"  query   = {r['query'][:80]}")
    print(f"  level   = {r['adoption_level']} ({r['adoption_label']})  weight={r['adoption_weight']}")
    print(f"  reason  = {r['reasoning'][:120]}")
    print()
