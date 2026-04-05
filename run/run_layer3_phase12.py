#!/usr/bin/env python3
"""
run/run_layer3_phase12.py
=========================
Layer 3 Phase 1+2 入口：SEC 聚类 + EWC 权重计算。

输入：
  data/layer2_output/experience_raw.jsonl

输出：
  data/layer3_output/phase12_result.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer3 import cluster_experiences, weight_equivalence_sets
from src.layer3.sec import resolve_target_service


logger = logging.getLogger("run_layer3_phase12")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="执行 Layer3 Phase1+2 (SEC+EWC)")
    parser.add_argument(
        "--input-file",
        type=Path,
        default=ROOT / "data" / "layer2_output" / "experience_raw.jsonl",
        help="Layer2 汇总经验文件（默认 data/layer2_output/experience_raw.jsonl）",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "phase12_result.jsonl",
        help="Phase12 输出文件（默认 data/layer3_output/phase12_result.jsonl）",
    )
    parser.add_argument("--verbose", action="store_true", help="输出详细日志")
    return parser


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _dedupe_by_exp_id(rows: list[dict]) -> tuple[list[dict], int]:
    """按 exp_id 去重（保留首次出现），返回 (去重结果, 丢弃数量)。"""
    seen: set[str] = set()
    deduped: list[dict] = []
    dropped = 0
    for row in rows:
        exp_id = str(row.get("exp_id", "")).strip()
        if exp_id and exp_id in seen:
            dropped += 1
            continue
        if exp_id:
            seen.add(exp_id)
        deduped.append(row)
    return deduped, dropped


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _set_target_service_fields(exp: dict, service_name: str) -> None:
    if not service_name:
        return
    content = exp.get("content") if isinstance(exp.get("content"), dict) else {}
    metadata = exp.get("metadata") if isinstance(exp.get("metadata"), dict) else {}
    constraints = (
        metadata.get("applicable_constraints")
        if isinstance(metadata.get("applicable_constraints"), dict)
        else {}
    )
    content["target_service"] = service_name
    constraints["target_service"] = service_name
    metadata["applicable_constraints"] = constraints
    exp["content"] = content
    exp["metadata"] = metadata


def _backfill_target_service_by_session(exps: list[dict]) -> int:
    """同 session 经验共享服务名：将可识别服务回填到该 session 的空服务条目。"""
    votes: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

    for exp in exps:
        session_id = str(exp.get("metadata", {}).get("source_session_id", "")).strip()
        if not session_id:
            continue
        svc = resolve_target_service(exp)
        if not svc:
            continue
        votes[session_id][svc] += float(exp.get("confidence", 0.5))

    filled = 0
    for exp in exps:
        session_id = str(exp.get("metadata", {}).get("source_session_id", "")).strip()
        if not session_id:
            continue
        if resolve_target_service(exp):
            continue
        session_vote = votes.get(session_id, {})
        if not session_vote:
            continue
        inferred = max(session_vote.items(), key=lambda kv: kv[1])[0]
        if inferred:
            _set_target_service_fields(exp, inferred)
            filled += 1
    return filled


def main() -> int:
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    experiences_raw = _load_jsonl(args.input_file)
    if not experiences_raw:
        logger.warning("未发现可处理经验: %s", args.input_file)
        _write_jsonl(args.output_file, [])
        return 0

    experiences, dropped_dups = _dedupe_by_exp_id(experiences_raw)
    if dropped_dups:
        logger.warning(
            "检测到重复 exp_id=%d 条，已在 Phase12 入口去重（原始=%d，去重后=%d）",
            dropped_dups,
            len(experiences_raw),
            len(experiences),
        )

    filled_count = _backfill_target_service_by_session(experiences)
    if filled_count:
        logger.info("Phase12 入口: 按 session 回填 target_service=%d 条", filled_count)

    t0 = time.perf_counter()

    clusters = cluster_experiences(experiences)
    wes_list = weight_equivalence_sets(clusters)

    rows: list[dict] = []
    for wes in wes_list:
        rows.append(
            {
                "cluster_id": wes.cluster.cluster_id,
                "knowledge_layer": wes.cluster.knowledge_layer,
                "target_service": wes.cluster.target_service,
                "failure_sub_dim": wes.cluster.failure_sub_dim,
                "version_family": wes.cluster.version_family,
                "cve_ids": wes.cluster.cve_ids,
                "exp_ids": wes.cluster.exp_ids,
                "source_count": len(wes.cluster.experiences),
                "meets_fusion_threshold": wes.cluster.meets_fusion_threshold,
                "dominant_exp_id": wes.dominant_exp_id,
                "total_weight": round(wes.total_weight, 6),
                "weights": [
                    {
                        "exp_id": we.exp_id,
                        "weight": we.weight,
                        "weight_effective": we.weight_effective,
                    }
                    for we in wes.weighted_exps
                ],
            }
        )

    _write_jsonl(args.output_file, rows)

    elapsed = time.perf_counter() - t0
    logger.info(
        "Phase1+2 完成: input=%d clusters=%d weighted_sets=%d output=%s elapsed=%.2fs",
        len(experiences),
        len(clusters),
        len(wes_list),
        args.output_file,
        elapsed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
