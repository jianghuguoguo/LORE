"""
快速重跑 4 个问题会话的 Layer 1 LLM 标注，验证 _raw_text 修复效果。
目标：
  b3ab5c15 → success
  f9af8981 → success
  85cd2e37 → partial_success
  5db69512 → partial_success
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer1.pipeline import load_turn_sequence, run_layer1_with_llm, save_annotated_turn_sequence
from src.llm_client import build_llm_client_from_config

INPUT_DIR  = ROOT / "data" / "layer0_output"
OUTPUT_DIR = ROOT / "data" / "layer1_output"

TARGET_SESSIONS = [
    "b3ab5c15-5c94-42d2-a302-5c20547c7b90",
    "f9af8981-2445-48b7-ba19-da36f5c1a574",
    "85cd2e37-2f48-48a7-8310-b651b33741f8",
    "5db69512-2f95-4fc8-a826-65e81c19a41c",
]

EXPECTED = {
    "b3ab5c15": "success",
    "f9af8981": "success",
    "85cd2e37": "partial_success",
    "5db69512": "partial_success",
}


def main():
    client = build_llm_client_from_config()
    print(f"[rerun] LLMClient 构建成功\n")

    for sid in TARGET_SESSIONS:
        log_path = INPUT_DIR / f"layer0_{sid}.jsonl"
        if not log_path.exists():
            print(f"  [!] 文件不存在: {log_path}")
            continue

        print(f"[rerun] 处理 {sid[:8]}… ({log_path.name})")
        seq = load_turn_sequence(log_path)
        ann_seq = run_layer1_with_llm(seq, client=client)

        out_path = OUTPUT_DIR / f"layer1_{sid}.jsonl"
        save_annotated_turn_sequence(ann_seq, out_path)

        outcome = ann_seq.session_outcome
        ok_label = outcome.outcome_label if outcome else "N/A"
        is_ok    = outcome.is_success    if outcome else None
        short    = sid[:8]
        expected = EXPECTED.get(short, "?")
        match_icon = "✅" if ok_label == expected else "❌"

        print(
            f"  {match_icon} outcome={ok_label:<15s} (预期: {expected})"
            f"  is_success={is_ok}  llm_calls={ann_seq.llm_call_count}"
            f"  errors={ann_seq.llm_error_count}"
        )
        if outcome:
            print(f"     reasoning: {(outcome.reasoning or '')[:200]}")
        print()

    print("[rerun] 完成")


if __name__ == "__main__":
    main()
