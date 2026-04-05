#!/usr/bin/env python3
"""
run/run_layer1_llm_batch.py
===========================
Layer 1 批处理入口：读取 Layer0 输出并执行规则+LLM 标注。

默认路径：
  input  = data/layer0_output
  output = data/layer1_output
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer1.pipeline import run_layer1_llm_batch
from src.llm_client import build_llm_client_from_config, llm_preflight_check


logger = logging.getLogger("run_layer1_llm_batch")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="批量执行 Layer 1（规则+LLM）")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=ROOT / "data" / "layer0_output",
        help="Layer0 输出目录（默认 data/layer0_output）",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "data" / "layer1_output",
        help="Layer1 输出目录（默认 data/layer1_output）",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出详细日志",
    )
    parser.add_argument(
        "--allow-llm-fallback",
        action="store_true",
        help="允许 LLM 不可用时继续运行（默认关闭；默认行为为硬失败）",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    input_dir = args.input_dir
    output_dir = args.output_dir

    if not input_dir.exists():
        logger.error("输入目录不存在: %s", input_dir)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    input_files = sorted(input_dir.glob("layer0_*.jsonl"))

    client = None
    try:
        client = build_llm_client_from_config()
    except Exception as exc:
        if args.allow_llm_fallback:
            logger.warning("LLMClient 初始化失败，按 --allow-llm-fallback 继续: %s", exc)
        else:
            logger.error("LLMClient 初始化失败（严格模式）：%s", exc)
            return 1

    if client is not None:
        ok, err = llm_preflight_check(client)
        if not ok:
            if args.allow_llm_fallback:
                logger.warning("LLM 预检失败，按 --allow-llm-fallback 继续: %s", err)
                client = None
            else:
                logger.error("LLM 预检失败（严格模式）：%s", err)
                return 1

    t0 = time.perf_counter()
    sessions = 0
    total_llm_calls = 0
    total_llm_errors = 0
    total_frc = 0
    total_rule_fallback_frc = 0

    for _ann_seq in run_layer1_llm_batch(
        input_dir=input_dir,
        output_dir=output_dir,
        client=client,
        save=True,
    ):
        sessions += 1
        total_llm_calls += int(getattr(_ann_seq, "llm_call_count", 0) or 0)
        total_llm_errors += int(getattr(_ann_seq, "llm_error_count", 0) or 0)
        for ev in getattr(_ann_seq, "annotated_events", []):
            frc = getattr(ev, "failure_root_cause", None)
            if frc is None:
                continue
            total_frc += 1
            if getattr(frc, "source", "") == "rule_fallback":
                total_rule_fallback_frc += 1

    elapsed = time.perf_counter() - t0
    logger.info(
        "Layer1 完成: sessions=%d elapsed=%.2fs output=%s llm_calls=%d llm_errors=%d rule_fallback_frc=%d/%d",
        sessions,
        elapsed,
        output_dir,
        total_llm_calls,
        total_llm_errors,
        total_rule_fallback_frc,
        total_frc,
    )

    if input_files and sessions == 0:
        logger.error("Layer1 未产生任何有效会话输出（输入文件=%d）", len(input_files))
        return 1

    if client is not None and total_llm_calls > 0 and total_llm_errors >= total_llm_calls:
        msg = (
            "Layer1 检测到所有 LLM 调用均失败，继续运行将退化为规则回退模板，"
            "请检查 API key / base_url / 网络后重试"
        )
        if args.allow_llm_fallback:
            logger.warning(msg)
        else:
            logger.error(msg)
            return 1

    if (
        client is not None
        and total_frc > 0
        and total_rule_fallback_frc >= total_frc
        and not args.allow_llm_fallback
    ):
        logger.error(
            "Layer1 所有 failure_root_cause 均来自 rule_fallback，判定 LLM 根因分析不可用，严格模式终止"
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
