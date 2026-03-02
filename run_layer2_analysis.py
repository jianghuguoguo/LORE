"""
run_layer2_analysis.py
=======================
用真实 Layer 1 输出数据运行 Layer 2（规则 + LLM），将结果保存到 data/layer2_output/。

输出结构：
  data/layer2_output/
    {session_id}/
      experiences.jsonl   — 该会话提取的所有经验（每行一条 JSON）
    experience_raw.jsonl  — 全量经验库（追加，供 Layer 3 消费）
    summary.json          — 本次运行的汇总统计

用法：cd RefPenTest && python run_layer2_analysis.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from src.layer1.pipeline import load_annotated_turn_sequence
from src.layer2.pipeline import run_layer2
from src.layer2.experience_models import KnowledgeLayer
from src.layer2.serializer import save_experience_bundle
from src.llm_client import LLMClient, LLMConfig
from src.ragflow_uploader import upload_session_jsonl, RAGFLOW_CONFIG

DATA_DIR     = ROOT / "data" / "layer1_output"
OUTPUT_DIR   = ROOT / "data" / "layer2_output"
LAYER1_FILES = sorted(DATA_DIR.glob("layer1_*.jsonl"))

def _build_client() -> LLMClient:
    """DeepSeek API key 直接造, 失败时返回 None."""
    return LLMClient(LLMConfig(
        provider="deepseek",
        model="deepseek-chat",
        base_url="https://api.deepseek.com",
        api_key_literal="sk-6bd4ea2482004f44bef2a842a4badc06",
        temperature=0.2,
        max_tokens=2000,
        max_retries=2,
        retry_delay=3.0,
        timeout=90,
    ))


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="运行 Layer 2 分析并（可选）上传至 RAGflow 经验库")
    ap.add_argument("--no-ragflow", action="store_true",
                    help="跳过 RAGflow 上传（仅生成本地 JSONL 文件）")
    ap.add_argument("--dry-run-ragflow", action="store_true",
                    help="RAGflow 变换但不实际上传（用于调试）")
    args, _ = ap.parse_known_args()

    upload_enabled = not args.no_ragflow
    ragflow_dry_run = args.dry_run_ragflow

    print(f"[layer2] 输入: {DATA_DIR}  会话数: {len(LAYER1_FILES)}")
    print(f"[layer2] 输出: {OUTPUT_DIR}")
    if upload_enabled:
        mode = "(dry-run)" if ragflow_dry_run else "(实际上传)"
        print(f"[layer2] RAGflow 上传: 已启用 {mode} → {RAGFLOW_CONFIG['base_url']}")
        print(f"[layer2]   经验库 ID: {RAGFLOW_CONFIG['experience_dataset']}")
    else:
        print("[layer2] RAGflow 上传: 已禁用（--no-ragflow）")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # P0 修复: 每次全量运行前先清除旧的全局 raw 文件，彻底消除 append double-write bug
    raw_path = OUTPUT_DIR / "experience_raw.jsonl"
    if raw_path.exists():
        raw_path.unlink()
        print(f"[layer2] 已清除旧的 experience_raw.jsonl（避免重复追加）")
    # 始终预创建空文件，确保 Layer 3 不会因文件缺失而崩溃
    raw_path.touch()

    # 构建 LLM client
    try:
        client = _build_client()
        print("[layer2] LLM client 已就绪（DeepSeek）— METACOGNITIVE/FACTUAL_LLM/NEG_RULE 将开启")
    except Exception as e:
        client = None
        print(f"[layer2] 警告: 无法构建 LLM client，将仅运行规则层: {e}")

    total_exps = 0
    layer_counter: Counter = Counter()
    error_sessions: list = []
    session_summaries: list = []
    fact_key_counter: Counter = Counter()
    fact_val_samples: dict = defaultdict(list)
    neg_dim_counter: Counter = Counter()
    ragflow_stats: dict = {"uploaded": 0, "skipped": 0, "failed": 0, "errors": []}

    # P1 META 跨 session 去重：相同 key_lessons 组合只保留首次出现的 META 经验
    meta_lessons_seen: set = set()

    for path in LAYER1_FILES:
        try:
            seq = load_annotated_turn_sequence(path)
        except Exception as e:
            error_sessions.append({"file": path.name, "error": str(e)})
            print(f"  [ERR] {path.name}: {e}")
            continue

        sid      = seq.metadata.session_id
        n_events = len(seq.annotated_events)
        so       = seq.session_outcome
        outcome  = so.outcome_label if so else "unknown"
        bar      = seq.bar_score

        bundle = run_layer2(seq, client=client)

        # P1: META 跨 session 内容去重 —— 相同 key_lessons 的 META 不写入全局 raw
        for exp in bundle.by_layer(KnowledgeLayer.METACOGNITIVE):
            lessons_key = tuple(sorted(str(x) for x in exp.content.get("key_lessons", [])))
            if lessons_key and lessons_key in meta_lessons_seen:
                exp.merged_into = "deduped_cross_session_meta"
            elif lessons_key:
                meta_lessons_seen.add(lessons_key)

        # ---- 保存到磁盘（session 目录用 "w" 覆写，全局 raw 用 append）----
        save_experience_bundle(bundle, OUTPUT_DIR, append_to_global_raw=True)

        # ---- 推送到 RAGflow 经验库 ----
        if upload_enabled:
            session_jsonl = OUTPUT_DIR / sid / "experiences.jsonl"
            try:
                rf_result = upload_session_jsonl(
                    str(session_jsonl), sid,
                    dry_run=ragflow_dry_run,
                )
                ragflow_stats["uploaded"] += rf_result.get("uploaded", 0)
                ragflow_stats["skipped"]  += rf_result.get("skipped", 0)
                ragflow_stats["failed"]   += rf_result.get("failed", 0)
                if rf_result.get("error"):
                    ragflow_stats["errors"].append(
                        {"session": sid[:8], "error": rf_result["error"]}
                    )
            except Exception as _rf_err:
                ragflow_stats["errors"].append({"session": sid[:8], "error": str(_rf_err)})
                print(f"  [WARN] RAGflow 上传异常: {_rf_err}")

        f_count  = bundle.factual_count
        pp_count = bundle.procedural_pos_count
        pn_count = bundle.procedural_neg_count
        mc_count = bundle.metacognitive_count
        co_count = bundle.conceptual_count
        re_count = bundle.rag_evaluation_count
        total    = bundle.total_count
        total_exps += total

        layer_counter[KnowledgeLayer.FACTUAL]          += f_count
        layer_counter[KnowledgeLayer.PROCEDURAL_POS]   += pp_count
        layer_counter[KnowledgeLayer.PROCEDURAL_NEG]   += pn_count
        layer_counter[KnowledgeLayer.METACOGNITIVE]    += mc_count
        layer_counter[KnowledgeLayer.CONCEPTUAL]       += co_count
        layer_counter[KnowledgeLayer.RAG_EVALUATION]   += re_count

        for exp in bundle.by_layer(KnowledgeLayer.FACTUAL):
            for fact in exp.content.get("discovered_facts", []):
                k = fact.get("key", "")
                v = fact.get("value", "")
                fact_key_counter[k] += 1
                if len(fact_val_samples[k]) < 3:
                    fact_val_samples[k].append(v[:60])

        for exp in bundle.by_layer(KnowledgeLayer.PROCEDURAL_NEG):
            dim = exp.content.get("failure_dimension", "UNKNOWN")
            sub = exp.content.get("failure_sub_dimension", "")
            neg_dim_counter[f"{dim}/{sub}"] += 1

        session_summaries.append({
            "session_id": sid,
            "outcome":    outcome,
            "bar":        bar,
            "n_events":   n_events,
            "factual":    f_count,
            "proc_pos":   pp_count,
            "proc_neg":   pn_count,
            "metacog":    mc_count,
            "conceptual": co_count,
            "rag_eval":   re_count,
            "total":      total,
            "errors":     bundle.extraction_errors,
        })
        print(f"  {sid[:8]}… | {outcome:15s} | BAR={bar:.2f} | ev={n_events:3d} "
              f"| F={f_count:2d} P+={pp_count:2d} P-={pn_count:2d} MC={mc_count:1d} "
              f"CO={co_count:1d} RE={re_count:1d} tot={total:2d}")

    n_sess = len(session_summaries)
    avg    = total_exps / n_sess if n_sess else 0

    # ---- 写 summary.json ----
    summary = {
        "session_count":     n_sess,
        "load_errors":       len(error_sessions),
        "total_experiences": total_exps,
        "avg_per_session":   round(avg, 2),
        "by_layer": {
            "FACTUAL":          layer_counter[KnowledgeLayer.FACTUAL],
            "PROCEDURAL_POS":   layer_counter[KnowledgeLayer.PROCEDURAL_POS],
            "PROCEDURAL_NEG":   layer_counter[KnowledgeLayer.PROCEDURAL_NEG],
            "METACOGNITIVE":    layer_counter[KnowledgeLayer.METACOGNITIVE],
            "CONCEPTUAL":       layer_counter[KnowledgeLayer.CONCEPTUAL],
            "RAG_EVALUATION":   layer_counter[KnowledgeLayer.RAG_EVALUATION],
        },
        "factual_key_distribution": {
            k: {"count": v, "samples": fact_val_samples[k]}
            for k, v in fact_key_counter.most_common()
        },
        "neg_dimension_distribution": dict(neg_dim_counter.most_common()),
        "zero_output_sessions": [s for s in session_summaries if s["total"] == 0],
        "error_sessions":       error_sessions,
        "sessions":             session_summaries,
    }
    summary_path = OUTPUT_DIR / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n[layer2] 完成。共处理 {n_sess} 个会话，提取经验 {total_exps} 条。")
    print(f"[layer2] 结果已保存至: {OUTPUT_DIR}")
    print(f"[layer2]   experience_raw.jsonl — {total_exps} 条")
    print(f"[layer2]   summary.json         — 汇总统计")
    if upload_enabled:
        print(f"[layer2] RAGflow 上传汇总: uploaded={ragflow_stats['uploaded']} "
              f"skipped={ragflow_stats['skipped']} failed={ragflow_stats['failed']}")
        if ragflow_stats["errors"]:
            for err in ragflow_stats["errors"]:
                print(f"  [ERR] session={err['session']}: {err['error']}")


if __name__ == "__main__":
    main()
