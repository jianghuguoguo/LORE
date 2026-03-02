"""重跑 2 个仍有问题的 session：64227b8f（failure 回退）和 b3ab5c15（success 降级）"""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer1.pipeline import load_turn_sequence, run_layer1_with_llm, save_annotated_turn_sequence
from src.llm_client import build_llm_client_from_config

INPUT_DIR  = ROOT / "data" / "layer0_output"
OUTPUT_DIR = ROOT / "data" / "layer1_output"

TARGETS = [
    ("b3ab5c15-5c94-42d2-a302-5c20547c7b90", "success",  "uid=0 truncation fix — stdout_hint 250"),
    ("64227b8f-f396-44f0-82a4-8158e1583c53", "failure",  "HTTP200≠RCE rule — no partial_success"),
]

def main():
    client = build_llm_client_from_config()
    for sid, expected, desc in TARGETS:
        print(f"{'─'*60}\n  {sid[:8]}  期望: {expected}  检查: {desc}")
        seq = load_turn_sequence(INPUT_DIR / f"layer0_{sid}.jsonl")
        ann_seq = run_layer1_with_llm(seq, client=client)
        save_annotated_turn_sequence(ann_seq, OUTPUT_DIR / f"layer1_{sid}.jsonl")
        outcome = ann_seq.session_outcome
        label = outcome.outcome_label if outcome else "N/A"
        mark = "✅" if label == expected else "❌"
        print(f"  {mark} outcome={label}  llm_calls={ann_seq.llm_call_count}")
        if outcome:
            print(f"  achieved_goals: {outcome.achieved_goals}")
            print(f"  reasoning: {(outcome.reasoning or '')[:300]}")

if __name__ == "__main__":
    main()
