"""
批量执行 Layer 1 完整流水线（规则层 + LLM 语义标注）
运行：python run_layer1_llm_batch.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer1 import run_layer1_llm_batch

INPUT_DIR  = ROOT / "data" / "layer0_output"
OUTPUT_DIR = ROOT / "data" / "layer1_output"


def main():
    # 确保输出目录存在
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[batch] 输入目录 : {INPUT_DIR}")
    print(f"[batch] 输出目录 : {OUTPUT_DIR}")
    print(f"[batch] 待处理文件: {len(list(INPUT_DIR.glob('layer0_*.jsonl')))} 个\n")

    total_calls = 0
    total_errors = 0
    results_summary = []

    for i, ann_seq in enumerate(run_layer1_llm_batch(INPUT_DIR, OUTPUT_DIR, save=True), 1):
        sid = ann_seq.metadata.session_id
        bar  = ann_seq.bar_score
        outcome = ann_seq.session_outcome
        ok_label = outcome.outcome_label if outcome else "N/A"
        is_ok    = outcome.is_success    if outcome else None
        calls    = ann_seq.llm_call_count
        errs     = ann_seq.llm_error_count
        rag_n    = len(ann_seq.rag_adoption_results)
        det_hits = ann_seq.deterministic_hits

        total_calls  += calls
        total_errors += errs

        results_summary.append({
            "session_id"   : sid,
            "is_success"   : is_ok,
            "outcome_label": ok_label,
            "bar_score"    : bar,
            "rag_queries"  : rag_n,
            "det_hits"     : det_hits,
            "llm_calls"    : calls,
            "llm_errors"   : errs,
        })

        status_icon = "✅" if is_ok else ("❌" if is_ok is False else "❓")
        print(
            f"  [{i:2d}] {status_icon} {sid[:8]}…  "
            f"outcome={ok_label:<15s} BAR={bar:.2f}  "
            f"rag={rag_n}  det_hits={det_hits}  "
            f"llm_calls={calls}  errors={errs}"
        )

    print(f"\n[batch] 处理完毕  总 LLM 调用={total_calls}  总失败={total_errors}")

    # 打印摘要统计
    success_sessions = sum(1 for r in results_summary if r["is_success"] is True)
    fail_sessions    = sum(1 for r in results_summary if r["is_success"] is False)
    avg_bar          = (
        sum(r["bar_score"] for r in results_summary) / len(results_summary)
        if results_summary else 0.0
    )
    print(f"[batch] 会话成功率={success_sessions}/{len(results_summary)}  "
          f"平均 BAR={avg_bar:.3f}  失败会话={fail_sessions}")

    # 保存摘要 JSON
    summary_path = OUTPUT_DIR / "batch_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results_summary, f, ensure_ascii=False, indent=2)
    print(f"[batch] 摘要已保存: {summary_path}")


if __name__ == "__main__":
    main()
