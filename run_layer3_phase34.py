"""
run_layer3_phase34.py — XPEC Phase 3 + Phase 4 运行脚本
=========================================================
输入：data/layer3_output/phase12_result.jsonl（Phase 1+2 等价集 + 权重）
      data/layer2_output/experience_raw.jsonl  （原始经验，用于读取 content）
输出：data/layer3_output/phase34_result.jsonl       （MergeResult + BccResult 摘要）
      data/layer3_output/phase34_consolidated.jsonl （ConsolidatedExp — 可写回知识库）
      data/layer3_output/phase34_summary.json        （统计摘要）

使用方法：
  # 仅处理 Phase 3+4（需 Phase 1+2 已完成）
  python run_layer3_phase34.py [--input DIR] [--exp-file FILE] [--output-dir DIR] [--verbose]

  # 串联运行 Phase 1+2 → Phase 3+4（全流程）
  python run_layer3_phase34.py --full-pipeline [--exp-file FILE] [--output-dir DIR] [--verbose]

输出格式 (phase34_result.jsonl, 每行一个等价集结果)：
  {
    "cluster_id": "...",
    "knowledge_layer": "PROCEDURAL_NEG",
    "merge": {
      "source_exp_count": 5,
      "contradiction_score": 0.12,
      "merge_notes": "...",
      "fused_content": { ... },
      "minority_opinions": [ ... ]
    },
    "bcc": {
      "p_fused": 0.823,
      "n_independent": 4,
      "n_total": 5,
      "old_maturity": "validated",
      "new_maturity": "consolidated",
      "upgraded": true,
      "upgrade_reason": "...",
      "should_reflux": true
    }
  }
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

from src.layer3.models import (
    WeightedEquivalenceSet,
    WeightedExperience,
    EquivalenceSet,
    Provenance,
    MergeResult,
    BccResult,
    ConsolidatedExp,
)
from src.layer3.rme import run_rme, summarize_merge_results
from src.layer3.bcc import run_bcc, summarize_bcc_results


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
# 反序列化：从 phase12_result.jsonl 恢复 WeightedEquivalenceSet
# ─────────────────────────────────────────────────────────────────────────────

def _load_phase12_results(
    phase12_path: Path,
    exp_map: Dict[str, Dict[str, Any]],
) -> List[WeightedEquivalenceSet]:
    """从 Phase 1+2 输出文件恢复 WeightedEquivalenceSet 列表。

    Args:
        phase12_path : phase12_result.jsonl 路径
        exp_map      : exp_id → experience dict（从 experience_raw.jsonl 构建）
    """
    if not phase12_path.exists():
        logging.warning(f"Phase 1+2 结果文件不存在，返回空列表: {phase12_path}")
        return []

    wes_list: List[WeightedEquivalenceSet] = []

    with phase12_path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                logging.warning(f"跳过第 {lineno} 行（JSON 解析失败）: {e}")
                continue

            # 重建 EquivalenceSet
            # EquivalenceSet.__post_init__ 会自动设 meets_fusion_threshold
            cluster = EquivalenceSet(
                cluster_id      = d["cluster_id"],
                knowledge_layer = d["knowledge_layer"],
                target_service  = d.get("target_service", ""),
                failure_sub_dim = d.get("failure_sub_dim", ""),
                version_family  = d.get("version_family", ""),
                cve_ids         = d.get("cve_ids", []),
                exp_ids         = d.get("exp_ids", []),
                experiences     = [],          # 不重建完整列表，节省内存
                trigger_level   = d.get("trigger_level", "L1"),
                has_conflict    = d.get("has_conflict", False),
            )
            # 手动覆盖 meets_fusion_threshold（__post_init__ 基于 len(experiences)=0）
            n_exps = len(d.get("weighted_experiences", []))
            object.__setattr__(cluster, "meets_fusion_threshold",
                               n_exps >= 3) if False else setattr(
                               cluster, "meets_fusion_threshold", n_exps >= 3)

            # 重建 WeightedExperience 列表
            weighted_exps: List[WeightedExperience] = []
            for we_d in d.get("weighted_experiences", []):
                exp_id = we_d["exp_id"]
                exp    = exp_map.get(exp_id, {})
                if not exp:
                    # 构造最小骨架，避免各 merge 函数 KeyError
                    exp = {
                        "exp_id":         exp_id,
                        "knowledge_layer": we_d.get("knowledge_layer", d["knowledge_layer"]),
                        "content":        {},
                        "metadata":       {
                            "source_session_id": we_d.get("session_id", ""),
                            "session_outcome":   we_d.get("session_outcome", ""),
                        },
                        "maturity":   we_d.get("maturity", "raw"),
                        "confidence": we_d.get("confidence", 0.3),
                    }

                weighted_exps.append(WeightedExperience(
                    exp_id          = exp_id,
                    exp             = exp,
                    weight          = we_d.get("weight", 0.3),
                    weight_effective= we_d.get("weight_effective", 0.3),
                    w_quality       = we_d.get("w_quality", 0.0),
                    w_maturity      = we_d.get("w_maturity", 0.0),
                    w_outcome       = we_d.get("w_outcome", 0.0),
                    w_coverage      = we_d.get("w_coverage", 0.0),
                    w_decay         = we_d.get("w_decay", 1.0),
                ))

            # 主导经验 ID
            dominant_exp_id = d.get("dominant_exp_id", "")
            if not dominant_exp_id and weighted_exps:
                dominant_exp_id = max(
                    weighted_exps, key=lambda x: x.weight_effective
                ).exp_id

            wes_list.append(WeightedEquivalenceSet(
                cluster        = cluster,
                weighted_exps  = weighted_exps,
                total_weight   = d.get("total_weight", 0.0),
                dominant_exp_id= dominant_exp_id,
            ))

    logging.info(f"加载 Phase 1+2 结果: {len(wes_list)} 个等价集  来源: {phase12_path}")
    return wes_list


def _load_experiences(exp_path: Path) -> Dict[str, Dict[str, Any]]:
    """加载 experience_raw.jsonl，返回 exp_id → dict 映射。"""
    if not exp_path.exists():
        logging.warning(f"经验文件不存在，将使用骨架数据: {exp_path}")
        return {}

    exp_map: Dict[str, Dict[str, Any]] = {}
    with exp_path.open(encoding="utf-8") as f:
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
    logging.info(f"加载原始经验: {len(exp_map)} 条  来源: {exp_path}")
    return exp_map


# ─────────────────────────────────────────────────────────────────────────────
# 序列化：结果写回磁盘
# ─────────────────────────────────────────────────────────────────────────────

def _merge_result_to_dict(mr: MergeResult) -> Dict[str, Any]:
    """MergeResult 序列化（provenance 使用 asdict）。"""
    prov = None
    try:
        prov = asdict(mr.provenance)
    except Exception:
        prov = {}

    return {
        "cluster_id":         mr.cluster_id,
        "knowledge_layer":    mr.knowledge_layer,
        "target_service":     mr.target_service,
        "version_family":     mr.version_family,
        "cve_ids":            mr.cve_ids,
        "source_exp_count":   mr.source_exp_count,
        "fused_content":      mr.fused_content,
        "provenance":         prov,
        "minority_opinions":  mr.minority_opinions,
        "contradiction_score":mr.contradiction_score,
        "merge_notes":        mr.merge_notes,
    }


def _bcc_result_to_dict(br: BccResult) -> Dict[str, Any]:
    return {
        "cluster_id":     br.cluster_id,
        "p_fused":        br.p_fused,
        "n_independent":  br.n_independent,
        "n_total":        br.n_total,
        "old_maturity":   br.old_maturity,
        "new_maturity":   br.new_maturity,
        "upgraded":       br.upgraded,
        "upgrade_reason": br.upgrade_reason,
        "downgraded":     br.downgraded,
        "should_reflux":  br.should_reflux,
        "lifecycle_status": br.lifecycle_status,
        "new_confidence": br.new_confidence,
    }


def _consolidated_to_dict(ce: ConsolidatedExp) -> Dict[str, Any]:
    return {
        "exp_id":                   ce.exp_id,
        "knowledge_layer":          ce.knowledge_layer,
        "content":                  ce.content,
        "metadata":                 ce.metadata,
        "maturity":                 ce.maturity,
        "confidence":               ce.confidence,
        "p_fused":                  ce.p_fused,
        "n_independent_sessions":   ce.n_independent_sessions,
        "contradiction_score":      ce.contradiction_score,
        "minority_opinions":        ce.minority_opinions,
        "lifecycle_status":         ce.lifecycle_status,
        "merged_into":              ce.merged_into,
        "refluxed":                 ce.refluxed,
        "provenance":               ce.provenance,
    }


def save_results(
    merge_results:     List[MergeResult],
    bcc_results:       List[BccResult],
    consolidated_exps: List[ConsolidatedExp],
    output_dir:        Path,
) -> None:
    """保存 Phase 3+4 结果到 output_dir。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(tz=timezone.utc).isoformat()

    # 1) phase34_result.jsonl — 每行包含 merge + bcc 摘要
    result_path = output_dir / "phase34_result.jsonl"
    mr_map = {mr.cluster_id: mr for mr in merge_results}
    br_map = {br.cluster_id: br for br in bcc_results}

    with result_path.open("w", encoding="utf-8") as f:
        for cluster_id, mr in mr_map.items():
            br = br_map.get(cluster_id)
            row = {
                "cluster_id":      cluster_id,
                "knowledge_layer": mr.knowledge_layer,
                "merge": _merge_result_to_dict(mr),
                "bcc":   _bcc_result_to_dict(br) if br else None,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    logging.info(f"Phase 3+4 结果已保存: {result_path}")

    # 2) phase34_consolidated.jsonl — 可直接追加写入知识库
    consol_path = output_dir / "phase34_consolidated.jsonl"
    with consol_path.open("w", encoding="utf-8") as f:
        for ce in consolidated_exps:
            f.write(json.dumps(_consolidated_to_dict(ce), ensure_ascii=False) + "\n")
    logging.info(f"ConsolidatedExp 已保存: {consol_path}  ({len(consolidated_exps)} 条)")

    # 3) phase34_summary.json — 统计摘要
    n_consol    = sum(1 for br in bcc_results if br.new_maturity == "consolidated")
    n_validated = sum(1 for br in bcc_results if br.new_maturity == "validated")
    n_raw       = sum(1 for br in bcc_results if br.new_maturity == "raw")
    n_upgraded  = sum(1 for br in bcc_results if br.upgraded)
    n_reflux    = sum(1 for br in bcc_results if br.should_reflux)

    by_layer: Dict[str, int] = {}
    for mr in merge_results:
        by_layer[mr.knowledge_layer] = by_layer.get(mr.knowledge_layer, 0) + 1

    summary = {
        "generated_at":   now_iso,
        "pipeline_stage": "phase34_rme_bcc",
        "merge_results_count": len(merge_results),
        "bcc_results_count":   len(bcc_results),
        "consolidated_exps_generated": len(consolidated_exps),
        "maturity_distribution": {
            "consolidated": n_consol,
            "validated":    n_validated,
            "raw":          n_raw,
        },
        "upgrades": n_upgraded,
        "for_reflux": n_reflux,
        "by_knowledge_layer": by_layer,
        "p_fused_stats": _compute_p_stats(bcc_results),
        "detailed_bcc": [
            {
                "cluster_id":    br.cluster_id,
                "p_fused":       br.p_fused,
                "n_independent": br.n_independent,
                "n_total":       br.n_total,
                "maturity":      br.new_maturity,
                "upgraded":      br.upgraded,
                "should_reflux": br.should_reflux,
            }
            for br in sorted(bcc_results, key=lambda x: -x.p_fused)
        ],
    }
    summary_path = output_dir / "phase34_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    logging.info(f"Phase 3+4 摘要已保存: {summary_path}")


def _compute_p_stats(bcc_results: List[BccResult]) -> Dict[str, Any]:
    """计算 p_fused 统计信息。"""
    if not bcc_results:
        return {}
    vals = sorted(br.p_fused for br in bcc_results)
    n = len(vals)
    return {
        "min":    round(vals[0], 4),
        "max":    round(vals[-1], 4),
        "mean":   round(sum(vals) / n, 4),
        "median": round(vals[n // 2], 4),
        "p75":    round(vals[int(n * 0.75)], 4),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def run(
    phase12_path: Path,
    exp_file:     Path,
    output_dir:   Path,
    verbose:      bool = False,
) -> Tuple[List[MergeResult], List[BccResult], List[ConsolidatedExp]]:
    """执行 Phase 3 (RME) + Phase 4 (BCC) 完整管道。

    Args:
        phase12_path : Phase 1+2 输出文件（phase12_result.jsonl）
        exp_file     : 原始经验 JSONL 路径
        output_dir   : 输出目录
        verbose      : 是否输出详细摘要

    Returns:
        (merge_results, bcc_results, consolidated_exps)
    """
    _setup_logging(verbose)
    log = logging.getLogger(__name__)

    log.info("=" * 65)
    log.info("XPEC Layer3  Phase 3 (RME) + Phase 4 (BCC)  启动")
    log.info("=" * 65)

    # ── 加载数据
    exp_map = _load_experiences(exp_file)
    wes_list = _load_phase12_results(phase12_path, exp_map)

    if not wes_list:
        log.warning("无等价集可处理，Phase 3+4 退出。")
        return [], [], []

    # 只对满足融合阈值的等价集执行 RME（≥3 条经验）
    fusion_wes = [w for w in wes_list if w.cluster.meets_fusion_threshold]
    non_fusion  = [w for w in wes_list if not w.cluster.meets_fusion_threshold]
    log.info(
        f"等价集总数={len(wes_list)}  "
        f"可融合(≥3)={len(fusion_wes)}  "
        f"单/双经验集(跳过)={len(non_fusion)}"
    )

    if not fusion_wes:
        log.warning("无满足融合阈值的等价集，Phase 3+4 退出。")
        return [], [], []

    # ── Phase 3: RME 规则融合
    log.info(f"[Phase 3 / RME] 对 {len(fusion_wes)} 个等价集执行规则融合...")
    t0 = datetime.now()
    merge_results = run_rme(fusion_wes)
    elapsed_rme = (datetime.now() - t0).total_seconds()
    log.info(
        f"[Phase 3 / RME] 完成  耗时={elapsed_rme:.2f}s  "
        f"融合结果={len(merge_results)}"
    )

    if verbose:
        print(summarize_merge_results(merge_results))

    # ── Phase 4: BCC 贝叶斯置信度校准
    wes_map = {w.cluster.cluster_id: w for w in fusion_wes}
    log.info(f"[Phase 4 / BCC] 对 {len(merge_results)} 个融合结果执行置信度校准...")
    t1 = datetime.now()
    bcc_results, consolidated_exps = run_bcc(merge_results, wes_map)
    elapsed_bcc = (datetime.now() - t1).total_seconds()
    log.info(
        f"[Phase 4 / BCC] 完成  耗时={elapsed_bcc:.2f}s  "
        f"consolidated={sum(1 for b in bcc_results if b.new_maturity == 'consolidated')}  "
        f"validated={sum(1 for b in bcc_results if b.new_maturity == 'validated')}"
    )

    if verbose:
        print(summarize_bcc_results(bcc_results, consolidated_exps))

    # ── 保存结果
    save_results(merge_results, bcc_results, consolidated_exps, output_dir)

    # ── 终端输出关键统计
    n_consol   = sum(1 for b in bcc_results if b.new_maturity == "consolidated")
    n_validated= sum(1 for b in bcc_results if b.new_maturity == "validated")
    n_upgraded = sum(1 for b in bcc_results if b.upgraded)
    n_reflux   = sum(1 for b in bcc_results if b.should_reflux)

    print(f"\n{'=' * 65}")
    print(f"  Phase 3+4 执行完毕")
    print(f"  融合等价集数     : {len(merge_results)}")
    print(f"  BCC 校准完成     : {len(bcc_results)}")
    print(f"  ├── consolidated : {n_consol}")
    print(f"  ├── validated    : {n_validated}")
    print(f"  ├── 成熟度升级   : {n_upgraded}")
    print(f"  └── 待回流KLM   : {n_reflux}")
    print(f"  输出目录         : {output_dir}")
    print(f"{'=' * 65}\n")

    return merge_results, bcc_results, consolidated_exps


# ─────────────────────────────────────────────────────────────────────────────
# 全流程串联：Phase 1+2 → Phase 3+4
# ─────────────────────────────────────────────────────────────────────────────

def run_full_pipeline(
    exp_file:   Path,
    output_dir: Path,
    verbose:    bool = False,
) -> None:
    """串联执行 Phase 1+2 → Phase 3+4（全流程入口）。"""
    # 延迟导入，避免循环
    from run_layer3_phase12 import run as run_phase12, load_experiences

    # Phase 1+2
    log = logging.getLogger(__name__)
    log.info("全流程模式：先执行 Phase 1+2...")
    wes_list = run_phase12(exp_file, output_dir, verbose)

    # Phase 3+4（直接读取磁盘文件确保一致性）
    phase12_path = output_dir / "phase12_result.jsonl"
    run(phase12_path, exp_file, output_dir, verbose)


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="XPEC Layer3 Phase 3+4: RME 规则融合 + BCC 贝叶斯校准"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=_ROOT / "data" / "layer3_output" / "phase12_result.jsonl",
        help="Phase 1+2 结果 JSONL 文件路径（默认: data/layer3_output/phase12_result.jsonl）",
    )
    parser.add_argument(
        "--exp-file",
        type=Path,
        default=_ROOT / "data" / "layer2_output" / "experience_raw.jsonl",
        help="原始经验 JSONL 文件路径（默认: data/layer2_output/experience_raw.jsonl）",
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
        help="先运行 Phase 1+2，再运行 Phase 3+4（全流程）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="输出详细融合/校准摘要",
    )

    args = parser.parse_args()

    _setup_logging(args.verbose)

    if args.full_pipeline:
        run_full_pipeline(args.exp_file, args.output_dir, args.verbose)
    else:
        run(args.input, args.exp_file, args.output_dir, args.verbose)


if __name__ == "__main__":
    main()
