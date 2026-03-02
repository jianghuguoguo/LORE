"""快速从 JSONL 读取 8 个 session 的最终标注结果，不重跑 LLM"""
import json, pathlib

out_dir = pathlib.Path(__file__).parent / "data" / "layer1_output"
sessions = [
    ("b3ab5c15-5c94-42d2-a302-5c20547c7b90", "success"),
    ("85cd2e37-2f48-48a7-8310-b651b33741f8",  "partial_success"),
    ("f9af8981-2445-48b7-ba19-da36f5c1a574",  "partial_success"),
    ("5db69512-2f95-4fc8-a826-65e81c19a41c",  "failure"),
    ("7d4c1a6a-7346-49a5-973f-70caaad894f6",  "failure"),
    ("8cb881bb-19ca-42e3-a394-b160369c5395",  "failure"),
    ("64227b8f-f396-44f0-82a4-8158e1583c53",  "failure"),
    ("d1bd6e0b-fdf0-4217-a844-44f6618d02eb",  "failure"),
]

def check_session(sid, expected):
    p = out_dir / f"layer1_{sid}.jsonl"
    if not p.exists():
        return {"sid": sid[:8], "status": "FILE_NOT_FOUND"}

    d = json.loads(p.read_text(encoding="utf-8").strip())
    so = d.get("session_outcome", {})
    outcome = so.get("outcome_label", "N/A")
    outcome_ok = "✅" if outcome == expected else "❌"

    # P1a: rag_adoption check
    rag_issues = 0
    rag_dict_count = 0
    ae_list = d.get("annotated_events", [])
    for ae in ae_list:
        ra = ae.get("rag_adoption")
        has_rag = ae.get("base", {}).get("has_rag_context", False)
        if ra is not None:
            if not isinstance(ra, dict):
                rag_issues += 1
            if not has_rag:
                rag_issues += 1
            else:
                rag_dict_count += 1

    # P1b: frc reasoning
    frc_empty = 0
    frc_total = 0
    for ae in ae_list:
        frc = ae.get("failure_root_cause")
        if frc and frc.get("source") == "llm":
            frc_total += 1
            if not (frc.get("reasoning") or "").strip():
                frc_empty += 1

    # P3a: frc_gap
    gap_total = 0
    gap_unfilled = 0
    for ae in ae_list:
        result = ae.get("base", {}).get("result", {}) or {}
        if (result.get("return_code") is None
                and result.get("success") is None
                and ae.get("outcome_label") == "failure"):
            gap_total += 1
            if ae.get("failure_root_cause") is None:
                gap_unfilled += 1

    # P2b EXPLOIT classification check
    exploit_events = sum(1 for ae in ae_list
                         if ae.get("attack_phase") == "EXPLOITATION")

    return {
        "sid": sid[:8],
        "outcome": outcome,
        "expected": expected,
        "outcome_ok": outcome_ok,
        "rag_issues": rag_issues,
        "rag_dict_count": rag_dict_count,
        "frc_empty": frc_empty,
        "frc_total": frc_total,
        "gap_unfilled": gap_unfilled,
        "gap_total": gap_total,
        "exploit_events": exploit_events,
        "achieved_goals": so.get("achieved_goals", []),
        "reasoning_preview": (so.get("reasoning", "") or "")[:120],
    }

print(f"{'Session':10} {'Outcome':15} {'Exp':15} {'P1a':6} {'P1b':8} {'P3a':8} {'EXPL':5}")
print("─" * 75)
for sid, expected in sessions:
    r = check_session(sid, expected)
    if r.get("status") == "FILE_NOT_FOUND":
        print(f"{r['sid']:10} FILE NOT FOUND")
        continue
    p1a = "✅" if r["rag_issues"] == 0 else f"❌{r['rag_issues']}"
    p1b = f"✅{r['frc_total']}" if r["frc_empty"] == 0 else f"❌{r['frc_empty']}/{r['frc_total']}"
    p3a = f"✅{r['gap_total']}" if r["gap_unfilled"] == 0 else f"❌{r['gap_unfilled']}/{r['gap_total']}"
    print(f"{r['sid']:10} {r['outcome']:15} {r['expected']:15} {p1a:6} {p1b:8} {p3a:8} {r['exploit_events']:3}")
    if r["achieved_goals"]:
        print(f"           achieved_goals: {r['achieved_goals']}")
    print(f"           reasoning: {r['reasoning_preview']}")
    print()
