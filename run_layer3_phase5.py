"""
run_layer3_phase5.py — XPEC Phase 5: Knowledge Lifecycle Management (KLM)
===========================================================================
接收 Phase 4 BCC 生成的 ConsolidatedExp，执行完整知识生命周期管理：
  1. 回流标记      — consolidated (active) → refluxed=True，源经验 → archived
  2. 冲突标记      — consolidated (conflicted) → 源经验 → conflicted，生成冲突报告
  3. 时效性衰减    — W_effective < 0.10 的 active 经验 → suspended

输入：
  data/layer3_output/phase34_consolidated.jsonl   （Phase 4 ConsolidatedExp）
  data/layer2_output/experience_raw.jsonl          （原始经验映射）

输出：
  data/layer3_output/phase5_klm_registry.jsonl    — 全库统一注册表（原始 + consolidated）
  data/layer3_output/phase5_reflux_ready.jsonl    — 回流就绪的 consolidated 经验
  data/layer3_output/phase5_klm_summary.json      — KLM 统计摘要 + 冲突报告 + 衰减日志

使用方法：
  # 仅执行 Phase 5 KLM（需 Phase 3+4 已完成）
  python run_layer3_phase5.py [--consolidated FILE] [--exp-file FILE] [--output-dir DIR]

  # 全流程串联（Phase 1+2 → 3+4 → 5）
  python run_layer3_phase5.py --full-pipeline [--exp-file FILE] [--output-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── 路径设置
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

from src.layer3.models import ConsolidatedExp
from src.layer3.klm import KlmResult, run_klm, summarize_klm_result


# ─────────────────────────────────────────────────────────────────────────────
# 日志
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 反序列化：从 JSONL 恢复 ConsolidatedExp 列表
# ─────────────────────────────────────────────────────────────────────────────

def _load_consolidated_exps(path: Path) -> List[ConsolidatedExp]:
    """从 phase34_consolidated.jsonl 加载 ConsolidatedExp 列表。

    字段与 ConsolidatedExp dataclass 一一对应，通过 dict 解包还原。
    未知字段被安全忽略（向前兼容）。
    """
    if not path.exists():
        logging.warning(f"ConsolidatedExp 文件不存在，返回空列表: {path}")
        return []

    known_fields = {
        "exp_id", "knowledge_layer", "content", "metadata",
        "maturity", "confidence", "p_fused", "n_independent_sessions",
        "contradiction_score", "minority_opinions",
        "lifecycle_status", "merged_into", "refluxed", "provenance",
    }

    exps: List[ConsolidatedExp] = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                logging.warning(f"跳过第 {lineno} 行（JSON 解析失败）: {e}")
                continue

            # 过滤未知字段，避免 dataclass 构造报错
            filtered = {k: v for k, v in d.items() if k in known_fields}

            # 补全缺失的可选字段默认值
            filtered.setdefault("lifecycle_status", "active")
            filtered.setdefault("merged_into",       None)
            filtered.setdefault("refluxed",          False)
            filtered.setdefault("provenance",        None)
            filtered.setdefault("minority_opinions", [])

            try:
                exps.append(ConsolidatedExp(**filtered))
            except TypeError as e:
                logging.warning(f"跳过第 {lineno} 行（ConsolidatedExp 构造失败）: {e}")

    logging.info(f"加载 ConsolidatedExp: {len(exps)} 条  来源: {path}")
    return exps


def _load_experiences(path: Path) -> Dict[str, Dict[str, Any]]:
    """加载 experience_raw.jsonl，返回 exp_id → dict 映射。"""
    if not path.exists():
        logging.warning(f"经验文件不存在，使用空映射: {path}")
        return {}

    exp_map: Dict[str, Dict[str, Any]] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                exp = json.loads(line)
                exp_id = exp.get("exp_id") or exp.get("id", "")
                if exp_id:
                    exp_map[exp_id] = exp
            except json.JSONDecodeError:
                pass

    logging.info(f"加载原始经验: {len(exp_map)} 条  来源: {path}")
    return exp_map


# ─────────────────────────────────────────────────────────────────────────────
# 序列化：结果写回磁盘
# ─────────────────────────────────────────────────────────────────────────────

def _save_registry(
    updated_raw_list:  List[Dict[str, Any]],
    reflux_ready_list: List[Dict[str, Any]],
    all_consolidated:  List[ConsolidatedExp],
    output_dir:        Path,
) -> None:
    """保存 KLM 全库注册表。

    phase5_klm_registry.jsonl 格式：每行一条经验，包含：
      - 原始经验（带 lifecycle_status / merged_into 更新）
      - consolidated 经验（带 refluxed 标志）
    末尾附加一行 `{"_meta": {...}}` 作为文件元数据。
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(tz=timezone.utc).isoformat()

    # 1) phase5_klm_registry.jsonl — 完整注册表
    # P0 Fix: 仅写入 lifecycle_status != "archived" 的原始经验
    # archived 语义 = 已被 consolidated 经验吸收，原始失效；保留在 Registry 会污染 RAG 检索
    registry_path = output_dir / "phase5_klm_registry.jsonl"
    n_written = 0
    n_archived_skipped = 0
    with registry_path.open("w", encoding="utf-8") as f:
        for exp in updated_raw_list:
            if exp.get("lifecycle_status") == "archived":
                n_archived_skipped += 1
                continue   # 已归档经验不写入检索索引
            f.write(json.dumps(exp, ensure_ascii=False) + "\n")
            n_written += 1
        for ce in all_consolidated:
            ce_dict = asdict(ce)
            ce_dict["_registry_type"] = "consolidated"
            # P0 Fix: 为 consolidated 经验补全结构化 metadata 检索字段
            # 原始经验路径：metadata.target_raw；consolidated 路径：metadata.applicable_constraints
            _meta = ce_dict.get("metadata", {})
            _ac   = _meta.get("applicable_constraints", {})
            _prov = ce_dict.get("provenance") or {}
            # 提取目标服务、CVE 列表、失败子维度
            target_svc  = _ac.get("target_service", "") or ""
            target_ver  = _ac.get("target_version", "") or ""
            cve_list    = _ac.get("cve_ids", []) or []
            fail_sub    = ce_dict.get("content", {}).get("failure_sub_dimension", "") or ""
            # fallback: 从 cluster_id 解析 failure_sub_dimension
            if not fail_sub:
                cluster_id = _prov.get("cluster_id", "")
                # cluster_id 格式：SEC_{LAYER}_{target}_{sub_dim}_...（下划线分隔）
                # 剥离已知前缀后，下一个大写词即为 sub_dim
                _cid_parts = cluster_id.upper().split("_")
                _known_layers = {"PROCEDURAL", "NEG", "POS", "FACTUAL", "RULE", "LLM",
                                  "METACOGNITIVE", "CONCEPTUAL", "RAG", "EVALUATION", "SEC"}
                for _p in _cid_parts:
                    if _p and _p not in _known_layers and not _p.startswith("CVE") and len(_p) > 3:
                        fail_sub = _p
                        break
            # 自动生成 retrieval_triggers（CVE IDs + target_service + failure_type + layer）
            _triggers: List[str] = list(cve_list)
            if target_svc:
                _triggers.append(target_svc.lower().replace(" ", "_"))
            if fail_sub:
                _triggers.append(fail_sub.upper())
            _triggers.append(ce_dict.get("knowledge_layer", ""))
            # 去重保留顺序
            seen_t: set = set()
            retrieval_triggers = [t for t in _triggers if t and not (t in seen_t or seen_t.add(t))]
            # 写入顶层检索字段
            ce_dict["target_service"]         = target_svc
            ce_dict["version_family"]         = target_ver
            ce_dict["cve_ids"]                = cve_list
            ce_dict["failure_sub_dimension"]  = fail_sub
            ce_dict["retrieval_triggers"]     = retrieval_triggers
            f.write(json.dumps(ce_dict, ensure_ascii=False) + "\n")
            n_written += 1
        # 末尾元数据行
        meta = {
            "_meta": {
                "generated_at":    now_iso,
                "source":          "XPEC-Layer3-Phase5-KLM",
                "raw_exp_count":   len(updated_raw_list),
                "archived_skipped": n_archived_skipped,
                "consol_count":    len(all_consolidated),
                "total_entries":   n_written,
            }
        }
        f.write(json.dumps(meta, ensure_ascii=False) + "\n")
    logging.info(
        f"KLM 注册表已保存: {registry_path}  ({n_written} 条经验，"
        f"已过滤 {n_archived_skipped} 条 archived 经验)"
    )

    # 2) phase5_reflux_ready.jsonl — 回流就绪（高优先级 RAG 候选）
    reflux_path = output_dir / "phase5_reflux_ready.jsonl"
    with reflux_path.open("w", encoding="utf-8") as f:
        for ce_dict in reflux_ready_list:
            f.write(json.dumps(ce_dict, ensure_ascii=False) + "\n")
    logging.info(
        f"回流就绪清单已保存: {reflux_path}  ({len(reflux_ready_list)} 条)"
    )


def _save_summary(
    klm_result:        KlmResult,
    updated_raw_list:  List[Dict[str, Any]],
    reflux_ready_list: List[Dict[str, Any]],
    all_consolidated:  List[ConsolidatedExp],
    output_dir:        Path,
) -> None:
    """保存 Phase 5 统计摘要 JSON。"""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 分层统计（lifecycle_status × knowledge_layer 的交叉分布）
    layer_lifecycle: Dict[str, Dict[str, int]] = {}
    for exp in updated_raw_list:
        layer  = exp.get("knowledge_layer", "UNKNOWN")
        status = exp.get("lifecycle_status", "active")
        if layer not in layer_lifecycle:
            layer_lifecycle[layer] = {}
        layer_lifecycle[layer][status] = layer_lifecycle[layer].get(status, 0) + 1

    # 最终状态计数（原始经验）
    status_dist: Dict[str, int] = {}
    for exp in updated_raw_list:
        s = exp.get("lifecycle_status", "active")
        status_dist[s] = status_dist.get(s, 0) + 1

    # consolidated 成熟度分布
    consol_maturity: Dict[str, int] = {}
    for ce in all_consolidated:
        consol_maturity[ce.maturity] = consol_maturity.get(ce.maturity, 0) + 1

    # 知识血缘链（merged_into_map）
    lineage = [
        {"source_exp_id": src, "consolidated_exp_id": dst}
        for src, dst in klm_result.merged_into_map.items()
    ]

    summary = {
        "generated_at":            klm_result.generated_at,
        "pipeline_stage":          "phase5_klm",
        "total_raw_exps":          klm_result.total_raw_exps,
        "consolidated_count":      klm_result.consolidated_count,
        "lifecycle_operations": {
            "refluxed":            klm_result.refluxed_count,
            "archived_source":     klm_result.archived_source_count,
            "suspended":           klm_result.suspended_count,
            "conflicted":          klm_result.conflicted_count,
        },
        "final_state_distribution": {
            "raw_experiences":     status_dist,
            "consolidated":        consol_maturity,
            "reflux_ready_count":  len(reflux_ready_list),
        },
        "by_knowledge_layer":      layer_lifecycle,
        "knowledge_lineage":       lineage,
        "conflict_report":         klm_result.conflict_report,
        "suspension_log":          klm_result.suspension_log,
    }

    summary_path = output_dir / "phase5_klm_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    logging.info(f"Phase 5 摘要已保存: {summary_path}")


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def run(
    consolidated_path: Path,
    exp_file:          Path,
    output_dir:        Path,
    verbose:           bool = False,
) -> KlmResult:
    """执行 Phase 5 KLM 完整管道。

    Args:
        consolidated_path : phase34_consolidated.jsonl 路径
        exp_file          : experience_raw.jsonl 路径
        output_dir        : 输出目录
        verbose           : 是否输出详细摘要

    Returns:
        KlmResult — 生命周期管理统计摘要
    """
    _setup_logging(verbose)
    log = logging.getLogger(__name__)

    log.info("=" * 65)
    log.info("XPEC Layer3  Phase 5 (KLM) — 知识生命周期管理  启动")
    log.info("=" * 65)

    # ── 加载数据
    consolidated_exps = _load_consolidated_exps(consolidated_path)
    exp_map           = _load_experiences(exp_file)

    if not consolidated_exps:
        log.warning("ConsolidatedExp 列表为空，Phase 5 退出。请先运行 Phase 3+4。")
        return KlmResult(
            total_raw_exps=0, consolidated_count=0, refluxed_count=0,
            archived_source_count=0, suspended_count=0, conflicted_count=0,
            active_raw_count=0, active_consol_count=0,
        )

    log.info(
        f"KLM 输入统计: "
        f"consolidated={len(consolidated_exps)}  "
        f"原始经验={len(exp_map)}"
    )

    # 分析输入中的成熟度分布
    maturity_dist: Dict[str, int] = {}
    for ce in consolidated_exps:
        maturity_dist[ce.maturity] = maturity_dist.get(ce.maturity, 0) + 1
    log.info(
        f"  ConsolidatedExp 成熟度分布: "
        + "  ".join(f"{k}={v}" for k, v in sorted(maturity_dist.items()))
    )
    lifecycle_dist: Dict[str, int] = {}
    for ce in consolidated_exps:
        lifecycle_dist[ce.lifecycle_status] = lifecycle_dist.get(ce.lifecycle_status, 0) + 1
    log.info(
        f"  ConsolidatedExp 生命周期分布: "
        + "  ".join(f"{k}={v}" for k, v in sorted(lifecycle_dist.items()))
    )

    # ── Phase 5: KLM
    from datetime import datetime
    t0 = datetime.now()
    klm_result, updated_raw_list, reflux_ready_list = run_klm(
        consolidated_exps, exp_map
    )
    elapsed = (datetime.now() - t0).total_seconds()
    log.info(f"[Phase 5 / KLM] 完成  耗时={elapsed:.2f}s")

    if verbose:
        print(summarize_klm_result(klm_result))

    # ── 保存结果
    _save_registry(updated_raw_list, reflux_ready_list, consolidated_exps, output_dir)
    _save_summary(klm_result, updated_raw_list, reflux_ready_list, consolidated_exps, output_dir)

    # ── 终端输出关键统计
    print(f"\n{'=' * 65}")
    print(f"  Phase 5 KLM 执行完毕")
    print(f"  原始经验总数           : {klm_result.total_raw_exps}")
    print(f"  Consolidated 经验数    : {klm_result.consolidated_count}")
    print(f"  ├── 回流完成           : {klm_result.refluxed_count}")
    print(f"  ├── 归档的源经验        : {klm_result.archived_source_count}")
    print(f"  ├── 衰减挂起           : {klm_result.suspended_count}")
    print(f"  └── 标记冲突           : {klm_result.conflicted_count}")
    print(f"")
    print(f"  最终状态（原始经验）   :")
    print(f"  ├── active             : {klm_result.active_raw_count}")
    if klm_result.suspended_count:
        print(f"  ├── suspended          : {klm_result.suspended_count}")
    if klm_result.archived_source_count:
        print(f"  ├── archived           : {klm_result.archived_source_count}")
    if klm_result.conflicted_count:
        print(f"  └── conflicted         : {klm_result.conflicted_count}")
    print(f"")
    print(f"  回流就绪 (RAG 高优先级): {len(reflux_ready_list)} 条")
    print(f"  输出目录               : {output_dir}")
    print(f"{'=' * 65}\n")

    if klm_result.conflict_report:
        print("⚠  冲突分析报告（需人工确认）：")
        for entry in klm_result.conflict_report:
            print(
                f"   [{entry['knowledge_layer']}]  "
                f"contra={entry['contradiction_score']:.3f}  "
                f"p_fused={entry['p_fused']:.4f}  "
                f"→ {entry['recommendation']}"
            )
        print()

    return klm_result


# ─────────────────────────────────────────────────────────────────────────────
# 全流程串联：Phase 1+2 → 3+4 → 5
# ─────────────────────────────────────────────────────────────────────────────

def run_full_pipeline(
    exp_file:   Path,
    output_dir: Path,
    verbose:    bool = False,
) -> None:
    """串联执行全流水线：Phase 1+2 → Phase 3+4 → Phase 5。"""
    log = logging.getLogger(__name__)

    # Phase 1+2
    log.info("全流程模式：[1/3] 执行 Phase 1+2 (SEC + EWC)...")
    from run_layer3_phase12 import run as run_phase12
    run_phase12(exp_file, output_dir, verbose)

    # Phase 3+4
    log.info("全流程模式：[2/3] 执行 Phase 3+4 (RME + BCC)...")
    phase12_path = output_dir / "phase12_result.jsonl"
    from run_layer3_phase34 import run as run_phase34
    run_phase34(phase12_path, exp_file, output_dir, verbose)

    # Phase 5
    log.info("全流程模式：[3/3] 执行 Phase 5 (KLM)...")
    consolidated_path = output_dir / "phase34_consolidated.jsonl"
    run(consolidated_path, exp_file, output_dir, verbose)

    log.info("=" * 65)
    log.info("XPEC 全流程完成: SEC → EWC → RME → BCC → KLM")
    log.info(f"输出目录: {output_dir}")
    log.info("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="XPEC Layer3 Phase 5: KLM — 知识生命周期管理"
    )
    parser.add_argument(
        "--consolidated",
        type=Path,
        default=_ROOT / "data" / "layer3_output" / "phase34_consolidated.jsonl",
        help="ConsolidatedExp JSONL 文件（默认: data/layer3_output/phase34_consolidated.jsonl）",
    )
    parser.add_argument(
        "--exp-file",
        type=Path,
        default=_ROOT / "data" / "layer2_output" / "experience_raw.jsonl",
        help="原始经验 JSONL 文件（默认: data/layer2_output/experience_raw.jsonl）",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_ROOT / "data" / "layer3_output",
        help="输出目录（默认: data/layer3_output/）",
    )
    parser.add_argument(
        "--full-pipeline",
        action="store_true",
        help="先运行 Phase 1+2+3+4，再运行 Phase 5（完整五阶段流水线）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="输出详细 KLM 摘要",
    )

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if args.full_pipeline:
        run_full_pipeline(args.exp_file, args.output_dir, args.verbose)
    else:
        run(args.consolidated, args.exp_file, args.output_dir, args.verbose)


if __name__ == "__main__":
    main()
