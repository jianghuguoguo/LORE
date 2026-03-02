"""查看 4 个问题 session 的 layer1 最终标注结果"""
import json, pathlib

out_dir = pathlib.Path(__file__).parent / "data" / "layer1_output"
sessions = [
    "b3ab5c15-5c94-42d2-a302-5c20547c7b90",
    "f9af8981-2445-48b7-ba19-da36f5c1a574",
    "85cd2e37-2f48-48a7-8310-b651b33741f8",
    "5db69512-2f95-4fc8-a826-65e81c19a41c",
]
expected = {
    "b3ab5c15": "success",
    "f9af8981": "success",
    "85cd2e37": "partial_success",
    "5db69512": "partial_success",
}
for sid in sessions:
    p = out_dir / f"layer1_{sid}.jsonl"
    if not p.exists():
        print(f"{sid[:8]}: file not found")
        continue
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    for line in reversed(lines):
        try:
            rec = json.loads(line)
            if rec.get("type") == "session_outcome":
                label = rec.get("outcome_label", "?")
                exp = expected[sid[:8]]
                mark = "PASS" if label == exp else "FAIL"
                reasoning = rec.get("reasoning", "")[:120]
                print(f"[{mark}] {sid[:8]}  outcome={label:<15} expected={exp}")
                print(f"       reasoning: {reasoning}")
                print()
                break
        except Exception:
            pass
