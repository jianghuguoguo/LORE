#!/usr/bin/env python3
"""
run/run_layer4_gap_dispatch.py
==============================
Layer 4 调度入口：队列恢复 + 可选爬取调度。

默认输出：
  data/layer4_output/gap_dispatch_summary.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer4.gap_queue import GapQueue
from src.layer4.dispatcher import Layer4Dispatcher
from src.utils.config_loader import get_config


logger = logging.getLogger("run_layer4_gap_dispatch")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="执行 Layer4 队列调度")
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "configs" / "config.yaml",
        help="用户配置路径（默认 configs/config.yaml；设计参数自动从 configs/design.yaml 合并）",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=ROOT / "data" / "layer4_output" / "gap_dispatch_summary.json",
        help="摘要输出文件（默认 data/layer4_output/gap_dispatch_summary.json）",
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="仅生成队列摘要，不触发爬取",
    )
    parser.add_argument(
        "--run-daily",
        action="store_true",
        help="触发一次 P1 每日任务（仅在非 --no-crawl 下生效）",
    )
    parser.add_argument(
        "--run-weekly",
        action="store_true",
        help="触发一次 P2 每周任务（仅在非 --no-crawl 下生效）",
    )
    parser.add_argument(
        "--p0-limit",
        type=int,
        default=5,
        help="P0 一次处理上限（默认 5）",
    )
    parser.add_argument("--verbose", action="store_true", help="输出详细日志")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    t0 = time.perf_counter()

    queue = GapQueue()
    reset_count = queue.reset_stale_processing()
    before_stats = queue.stats()

    processed = {"p0": 0, "p1": 0, "p2": 0}

    if not args.no_crawl:
        try:
            layer4_cfg = get_config(args.config).layer4_config
        except Exception as exc:
            logger.warning("加载 Layer4 配置失败，回退默认值: %s", exc)
            layer4_cfg = {}
        dispatcher = Layer4Dispatcher(layer4_cfg)
        processed["p0"] = dispatcher.handle_p0(limit=max(1, args.p0_limit))
        if args.run_daily:
            dispatcher.run_daily_job()
            processed["p1"] = 1
        if args.run_weekly:
            dispatcher.run_weekly_job()
            processed["p2"] = 1

    after_stats = queue.stats()
    elapsed = time.perf_counter() - t0

    summary = {
        "success": True,
        "ran_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "no_crawl": bool(args.no_crawl),
        "reset_stale_processing": reset_count,
        "processed": processed,
        "queue_before": before_stats,
        "queue_after": after_stats,
        "elapsed_s": round(elapsed, 3),
    }

    args.summary_file.parent.mkdir(parents=True, exist_ok=True)
    args.summary_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    logger.info("Layer4 调度完成: no_crawl=%s elapsed=%.2fs summary=%s", args.no_crawl, elapsed, args.summary_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
