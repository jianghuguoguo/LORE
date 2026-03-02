"""
run_layer3_phase12.py — XPEC Phase 1 + Phase 2 运行脚本
=========================================================
输入：data/layer2_output/experience_raw.jsonl（Layer2 全量经验）
输出：data/layer3_output/phase12_result.jsonl  （等价集 + 权重）
      data/layer3_output/phase12_summary.json  （摘要统计）

使用方法：
  python run_layer3_phase12.py [--input PATH] [--output-dir DIR] [--verbose]

输出格式（JSONL，每行一个等价集）：
  {
    "cluster_id": "SEC_PROCEDURAL_NEG_oracle_weblogic_server_incomplete_recon_...",
    "knowledge_layer": "PROCEDURAL_NEG",
    "target_service": "Oracle WebLogic Server",
    "failure_sub_dim": "INCOMPLETE_RECON",
    "version_family": "10.3.x",
    "cve_ids": ["CVE-2017-10271"],
    "exp_ids": ["exp_5db69512_0004", "exp_8cb881bb_0007"],
    "trigger_level": "L1+L2",
    "meets_fusion_threshold": false,
    "has_conflict": false,
    "weighted_experiences": [
      {
        "exp_id": "exp_5db69512_0004",
        "weight": 0.65,
        "weight_effective": 0.62,
        "w_quality": 0.432,
        "w_maturity": 0.4,
        "w_outcome": 0.6,
        "w_coverage": 0.76,
        "w_decay": 0.962,
        "is_dominant": true
      },
      ...
    ],
    "total_weight": 0.62,
    "dominant_exp_id": "exp_5db69512_0004"
  }
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# ── 路径设置：让脚本在 RefPenTest/ 下直接运行
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))

from src.layer3.sec import cluster_experiences, summarize_clusters
from src.layer3.ewc import weight_equivalence_sets, summarize_weights
from src.layer3.models import WeightedEquivalenceSet


# ─────────────────────────────────────────────────────────────────────────────
# 配置日志
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


# ─────────────────────────────────────────────────────────────────────────────
# IO 工具
# ─────────────────────────────────────────────────────────────────────────────

def load_experiences(path: Path) -> List[Dict[str, Any]]:
    """加载 Layer2 JSONL 经验文件，返回经验列表。若文件不存在则返回空列表。"""
    if not path.exists():
        logging.warning(f"经验文件不存在，返回空列表: {path}")
        return []
    exps = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                exps.append(json.loads(line))
            except json.JSONDecodeError as e:
                logging.warning(f"跳过第 {lineno} 行（JSON 解析失败）: {e}")
    logging.info(f"加载经验: {len(exps)} 条  来源: {path}")
    return exps


def _wes_to_dict(wes: WeightedEquivalenceSet) -> Dict[str, Any]:
    """将 WeightedEquivalenceSet 序列化为可 JSON 存储的 dict。"""
    c = wes.cluster
    weighted_list = []
    for we in wes.weighted_exps:
        weighted_list.append({
            "exp_id":           we.exp_id,
            "weight":           we.weight,
            "weight_effective": we.weight_effective,
            "w_quality":        we.w_quality,
            "w_maturity":       we.w_maturity,
            "w_outcome":        we.w_outcome,
            "w_coverage":       we.w_coverage,
            "w_decay":          we.w_decay,
            "is_dominant":      (we.exp_id == wes.dominant_exp_id),
            # 冗余关键元信息（方便下游 Phase 3 直接使用，不用再读原始经验）
            "knowledge_layer":  we.exp.get("knowledge_layer", ""),
            "session_id":       we.exp.get("metadata", {}).get("source_session_id", ""),
            "session_outcome":  we.exp.get("metadata", {}).get("session_outcome", ""),
            "maturity":         we.exp.get("maturity", ""),
            "confidence":       we.exp.get("confidence", 0.0),
        })

    return {
        "cluster_id":              c.cluster_id,
        "knowledge_layer":         c.knowledge_layer,
        "target_service":          c.target_service,
        "failure_sub_dim":         c.failure_sub_dim,
        "version_family":          c.version_family,
        "cve_ids":                 c.cve_ids,
        "exp_ids":                 c.exp_ids,
        "trigger_level":           c.trigger_level,
        "meets_fusion_threshold":  c.meets_fusion_threshold,
        "has_conflict":            c.has_conflict,
        "weighted_experiences":    weighted_list,
        "total_weight":            round(wes.total_weight, 4),
        "dominant_exp_id":         wes.dominant_exp_id,
        "exp_count":               len(wes.weighted_exps),
    }


def save_results(
    wes_list: List[WeightedEquivalenceSet],
    output_dir: Path,
) -> None:
    """保存 Phase 1+2 结果到 output_dir。"""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1) 全量 JSONL
    result_path = output_dir / "phase12_result.jsonl"
    with result_path.open("w", encoding="utf-8") as f:
        for wes in wes_list:
            f.write(json.dumps(_wes_to_dict(wes), ensure_ascii=False) + "\n")
    logging.info(f"Phase 1+2 结果已保存: {result_path}")

    # 2) 摘要 JSON
    fusion_candidates = [w for w in wes_list if w.cluster.meets_fusion_threshold]
    by_layer: Dict[str, int] = {}
    for wes in wes_list:
        layer = wes.cluster.knowledge_layer
        by_layer[layer] = by_layer.get(layer, 0) + 1

    summary = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "total_experiences_input": sum(len(w.weighted_exps) for w in wes_list),
        "total_clusters": len(wes_list),
        "fusion_candidates": len(fusion_candidates),
        "single_exp_clusters": len(wes_list) - len(fusion_candidates),
        "clusters_by_layer": by_layer,
        "fusion_candidates_detail": [
            {
                "cluster_id": w.cluster.cluster_id,
                "knowledge_layer": w.cluster.knowledge_layer,
                "exp_count": len(w.weighted_exps),
                "dominant_exp_id": w.dominant_exp_id,
                "total_weight": round(w.total_weight, 4),
                "cve_ids": w.cluster.cve_ids,
            }
            for w in fusion_candidates
        ],
    }
    summary_path = output_dir / "phase12_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    logging.info(f"Phase 1+2 摘要已保存: {summary_path}")


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def run(
    input_path: Path,
    output_dir: Path,
    verbose: bool = False,
) -> List[WeightedEquivalenceSet]:
    """执行 Phase 1（SEC）+ Phase 2（EWC）完整管道。

    Returns:
        WeightedEquivalenceSet 列表（同时序列化到磁盘）
    """
    _setup_logging(verbose)
    log = logging.getLogger(__name__)

    log.info("=" * 60)
    log.info("XPEC Layer3  Phase 1 (SEC) + Phase 2 (EWC)  启动")
    log.info("=" * 60)

    # ── 读取 Layer2 经验
    experiences = load_experiences(input_path)
    if not experiences:
        log.warning("经验库为空，无需执行融合。")
        return []

    # ── Phase 1: SEC 语义等价聚类
    log.info(f"[Phase 1 / SEC] 对 {len(experiences)} 条经验执行聚类...")
    t0 = datetime.now()
    clusters = cluster_experiences(experiences)
    elapsed_sec = (datetime.now() - t0).total_seconds()
    log.info(
        f"[Phase 1 / SEC] 完成  耗时={elapsed_sec:.2f}s  "
        f"等价集={len(clusters)}  "
        f"可融合（≥3）={sum(1 for c in clusters if c.meets_fusion_threshold)}"
    )

    if verbose:
        print(summarize_clusters(clusters))

    # ── Phase 2: EWC 证据权重计算
    log.info(f"[Phase 2 / EWC] 对 {len(clusters)} 个等价集计算权重...")
    t1 = datetime.now()
    wes_list = weight_equivalence_sets(clusters)
    elapsed_ewc = (datetime.now() - t1).total_seconds()
    log.info(f"[Phase 2 / EWC] 完成  耗时={elapsed_ewc:.2f}s")

    if verbose:
        print(summarize_weights(wes_list))

    # ── 保存结果
    save_results(wes_list, output_dir)

    # ── 终端输出关键统计
    fusion_cnt = sum(1 for w in wes_list if w.cluster.meets_fusion_threshold)
    print(f"\n{'=' * 60}")
    print(f"  Phase 1+2 执行完毕")
    print(f"  输入经验数    : {len(experiences)}")
    print(f"  等价集总数    : {len(clusters)}")
    print(f"  可融合集数(≥3): {fusion_cnt}")
    print(f"  输出目录      : {output_dir}")
    print(f"{'=' * 60}\n")

    return wes_list


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="XPEC Layer3 Phase 1+2: SEC 聚类 + EWC 权重计算"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=_ROOT / "data" / "layer2_output" / "experience_raw.jsonl",
        help="Layer2 经验 JSONL 文件路径（默认: data/layer2_output/experience_raw.jsonl）",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_ROOT / "data" / "layer3_output",
        help="输出目录（默认: data/layer3_output/）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="输出详细聚类/权重摘要",
    )
    args = parser.parse_args()
    run(args.input, args.output_dir, args.verbose)


if __name__ == "__main__":
    main()
