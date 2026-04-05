#!/usr/bin/env python3
"""
run/run_layer3_phase5.py
========================
Layer 3 Phase 5 入口：KLM 生命周期管理。

输入：
  data/layer3_output/phase34_consolidated.jsonl
  data/layer2_output/experience_raw.jsonl

输出：
  data/layer3_output/phase5_klm_registry.jsonl
  data/layer3_output/phase5_reflux_ready.jsonl
  data/layer3_output/conflict_report.jsonl
  data/layer3_output/conflict_summary.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer3.klm import run_klm
from src.layer3.models import ConsolidatedExp


logger = logging.getLogger("run_layer3_phase5")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="执行 Layer3 Phase5 (KLM)")
    parser.add_argument(
        "--consolidated-file",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "phase34_consolidated.jsonl",
        help="Phase34 输出文件（默认 data/layer3_output/phase34_consolidated.jsonl）",
    )
    parser.add_argument(
        "--raw-file",
        type=Path,
        default=ROOT / "data" / "layer2_output" / "experience_raw.jsonl",
        help="Layer2 汇总经验文件（默认 data/layer2_output/experience_raw.jsonl）",
    )
    parser.add_argument(
        "--klm-file",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "phase5_klm_registry.jsonl",
        help="KLM 输出文件（默认 data/layer3_output/phase5_klm_registry.jsonl）",
    )
    parser.add_argument(
        "--reflux-file",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "phase5_reflux_ready.jsonl",
        help="reflux 就绪输出文件（默认 data/layer3_output/phase5_reflux_ready.jsonl）",
    )
    parser.add_argument(
        "--conflict-report",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "conflict_report.jsonl",
        help="冲突报告输出文件（默认 data/layer3_output/conflict_report.jsonl）",
    )
    parser.add_argument(
        "--conflict-summary",
        type=Path,
        default=ROOT / "data" / "layer3_output" / "conflict_summary.json",
        help="冲突摘要输出文件（默认 data/layer3_output/conflict_summary.json）",
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


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _load_consolidated(path: Path) -> list[ConsolidatedExp]:
    rows = _load_jsonl(path)
    fields = set(ConsolidatedExp.__dataclass_fields__.keys())
    result: list[ConsolidatedExp] = []
    for row in rows:
        payload = {k: v for k, v in row.items() if k in fields}
        try:
            result.append(ConsolidatedExp(**payload))
        except TypeError:
            continue
    return result


def main() -> int:
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    consolidated = _load_consolidated(args.consolidated_file)
    raw_exps = _load_jsonl(args.raw_file)

    if not raw_exps:
        logger.warning("未发现 Layer2 原始经验: %s", args.raw_file)
        _write_jsonl(args.klm_file, [])
        _write_jsonl(args.reflux_file, [])
        _write_jsonl(args.conflict_report, [])
        args.conflict_summary.parent.mkdir(parents=True, exist_ok=True)
        args.conflict_summary.write_text(
            json.dumps({"success": True, "message": "no raw experiences"}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return 0

    exp_map = {exp.get("exp_id", ""): exp for exp in raw_exps if exp.get("exp_id")}

    t0 = time.perf_counter()
    klm_result, updated_raw_list, reflux_ready = run_klm(consolidated, exp_map)

    _write_jsonl(args.klm_file, updated_raw_list)
    _write_jsonl(args.reflux_file, reflux_ready)
    _write_jsonl(args.conflict_report, klm_result.conflict_report)

    summary = {
        "success": True,
        "generated_at": klm_result.generated_at,
        "total_raw_exps": klm_result.total_raw_exps,
        "consolidated_count": klm_result.consolidated_count,
        "refluxed_count": klm_result.refluxed_count,
        "archived_source_count": klm_result.archived_source_count,
        "suspended_count": klm_result.suspended_count,
        "conflicted_count": klm_result.conflicted_count,
        "active_raw_count": klm_result.active_raw_count,
        "active_consol_count": klm_result.active_consol_count,
        "entries_updated": len(klm_result.lifecycle_updates),
    }
    args.conflict_summary.parent.mkdir(parents=True, exist_ok=True)
    args.conflict_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    elapsed = time.perf_counter() - t0
    logger.info(
        "Phase5 完成: consolidated=%d raw=%d updated=%d reflux_ready=%d output=%s elapsed=%.2fs",
        len(consolidated),
        len(raw_exps),
        len(updated_raw_list),
        len(reflux_ready),
        args.klm_file,
        elapsed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
