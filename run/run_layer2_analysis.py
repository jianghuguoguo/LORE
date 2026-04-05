#!/usr/bin/env python3
"""
run/run_layer2_analysis.py
==========================
Layer 2 批处理入口：读取 Layer1 输出并执行经验提取。

默认路径：
  input  = data/layer1_output
  output = data/layer2_output

可选：
  --no-ragflow   仅执行 Layer2 提取，不触发上传
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.layer2.pipeline import run_layer2_batch
from src.llm_client import build_llm_client_from_config, llm_preflight_check


logger = logging.getLogger("run_layer2_analysis")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="批量执行 Layer 2 经验提取")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=ROOT / "data" / "layer1_output",
        help="Layer1 输出目录（默认 data/layer1_output）",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "data" / "layer2_output",
        help="Layer2 输出目录（默认 data/layer2_output）",
    )
    parser.add_argument(
        "--no-ragflow",
        action="store_true",
        help="跳过上传到 RAGFlow",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出详细日志",
    )
    parser.add_argument(
        "--no-clean-output",
        action="store_true",
        help="禁用默认清理输出目录（默认会清空 output-dir 后再运行）",
    )
    parser.add_argument(
        "--allow-rule-fallback",
        action="store_true",
        help="允许 LLM 不可用时退化到规则路径（默认关闭；默认行为为硬失败）",
    )
    return parser


def _prepare_output_dir(output_dir: Path, clean_output: bool) -> None:
    """准备 Layer2 输出目录。默认清理，避免复跑叠加历史结果。"""
    if clean_output and output_dir.exists():
        logger.info("清理 Layer2 输出目录: %s", output_dir)
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def _run_ragflow_upload() -> int:
    cmd = [
        sys.executable,
        "-m",
        "src.ragflow.uploader",
        "--source",
        "raw",
    ]
    logger.info("开始上传 RAGFlow: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(ROOT),
        env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"},
    )
    return result.returncode


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

    _prepare_output_dir(output_dir, clean_output=not args.no_clean_output)
    input_files = sorted(input_dir.glob("layer1_*.jsonl"))

    client = None
    try:
        client = build_llm_client_from_config()
    except Exception as exc:
        if args.allow_rule_fallback:
            logger.warning("LLMClient 初始化失败，按 --allow-rule-fallback 降级: %s", exc)
            client = None
        else:
            logger.error("LLMClient 初始化失败（严格模式）：%s", exc)
            return 1

    if client is not None:
        ok, err = llm_preflight_check(client)
        if not ok:
            if args.allow_rule_fallback:
                logger.warning("LLM 预检失败，按 --allow-rule-fallback 降级: %s", err)
                client = None
            else:
                logger.error("LLM 预检失败（严格模式）：%s", err)
                return 1

    t0 = time.perf_counter()
    sessions = 0
    total_exps = 0
    llm_exps = 0
    proc_neg_total = 0
    proc_neg_rule_fallback = 0

    for bundle in run_layer2_batch(
        input_dir=input_dir,
        output_dir=output_dir,
        client=client,
        save=True,
    ):
        sessions += 1
        total_exps += getattr(bundle, "total_count", 0)
        for exp in getattr(bundle, "experiences", []):
            src = getattr(getattr(exp, "metadata", None), "extraction_source", "")
            src_val = getattr(src, "value", str(src))
            if src_val == "llm":
                llm_exps += 1

            layer = getattr(exp, "knowledge_layer", "")
            layer_val = getattr(layer, "value", str(layer))
            if layer_val == "PROCEDURAL_NEG":
                proc_neg_total += 1
                if exp.content.get("decision_rule_source") == "rule_fallback":
                    proc_neg_rule_fallback += 1

    elapsed = time.perf_counter() - t0
    logger.info(
        "Layer2 完成: sessions=%d total_exps=%d llm_exps=%d proc_neg_rule_fallback=%d/%d elapsed=%.2fs output=%s",
        sessions,
        total_exps,
        llm_exps,
        proc_neg_rule_fallback,
        proc_neg_total,
        elapsed,
        output_dir,
    )

    if input_files and sessions == 0:
        logger.error("Layer2 未产生任何有效会话输出（输入文件=%d）", len(input_files))
        return 1

    if input_files and total_exps == 0:
        logger.error(
            "Layer2 处理了 %d 个会话但提取经验为 0，判定为失败（请检查 Layer1 标注质量/LLM 可用性）",
            sessions,
        )
        return 1

    if client is not None and llm_exps == 0:
        msg = "Layer2 未产生任何 LLM 来源经验，判定 LLM 提取不可用"
        if args.allow_rule_fallback:
            logger.warning(msg)
        else:
            logger.error(msg)
            return 1

    if client is not None and proc_neg_total > 0 and proc_neg_rule_fallback >= proc_neg_total:
        msg = "Layer2 的 PROCEDURAL_NEG 全部来自 rule_fallback，判定根因语义分析不可用"
        if args.allow_rule_fallback:
            logger.warning(msg)
        else:
            logger.error(msg)
            return 1

    if args.no_ragflow:
        logger.info("--no-ragflow 已启用，跳过上传")
        return 0

    upload_rc = _run_ragflow_upload()
    if upload_rc != 0:
        logger.error("RAGFlow 上传失败，exit=%d", upload_rc)
        return upload_rc

    logger.info("RAGFlow 上传完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
