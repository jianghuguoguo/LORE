#!/usr/bin/env python3
"""
scripts/run_layer0.py
=====================
Layer 0 命令行入口点

用法示例：

    # 处理单个日志文件
    python scripts/run_layer0.py --file ../logs/cai_xxx.jsonl --output-dir ../data/processed

    # 批量处理整个目录
    python scripts/run_layer0.py --log-dir ../logs --output-dir ../data/processed

    # 自定义配置文件
    python scripts/run_layer0.py --log-dir ../logs --config configs/my_config.yaml

    # 仅输出统计信息，不保存文件
    python scripts/run_layer0.py --log-dir ../logs --dry-run

    # 输出 JSON 摘要
    python scripts/run_layer0.py --log-dir ../logs --output-dir out/ --summary summary.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# ── 使项目根目录可被 import ────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.layer0.pipeline import run_layer0, run_layer0_batch
from src.utils.config_loader import Config, get_config
from src.utils.log_utils import get_logger

logger = get_logger("run_layer0")


# ─────────────────────────────────────────────────────────────────────────────
# CLI 解析
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_layer0",
        description="RefPenTest Layer 0 流水线：将原始 JSONL 日志转换为 TurnSequence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # 输入：二选一
    input_group = p.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--file", "-f",
        type=Path,
        metavar="LOG_FILE",
        help="处理单个 JSONL 日志文件",
    )
    input_group.add_argument(
        "--log-dir", "-d",
        type=Path,
        metavar="LOG_DIR",
        help="批量处理目录下的所有 JSONL 文件",
    )

    # 输出
    p.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=None,
        metavar="OUTPUT_DIR",
        help="TurnSequence 输出目录（默认与输入同目录）",
    )

    # 配置
    p.add_argument(
        "--config", "-c",
        type=Path,
        default=None,
        metavar="CONFIG_FILE",
        help="YAML 配置文件路径（默认: configs/config.yaml）",
    )

    # 模式
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="仅解析并输出统计，不保存输出文件",
    )

    p.add_argument(
        "--summary",
        type=Path,
        default=None,
        metavar="SUMMARY_JSON",
        help="将批量处理摘要写入指定 JSON 文件",
    )

    # 日志级别
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="日志级别（默认: INFO）",
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
# 主逻辑
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    args = build_parser().parse_args()

    # 设置日志级别
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # 加载配置
    try:
        cfg = get_config(args.config) if args.config else get_config()
    except Exception as e:
        logger.error("加载配置失败: %s", e)
        return 2

    # ── 单文件处理 ────────────────────────────────────────────────────────
    if args.file is not None:
        return _process_single(args.file, args.output_dir, cfg, args.dry_run)

    # ── 批量处理 ──────────────────────────────────────────────────────────
    return _process_batch(args.log_dir, args.output_dir, cfg, args.dry_run, args.summary)


def _process_single(
    log_file: Path,
    output_dir: Path | None,
    cfg: Config,
    dry_run: bool,
) -> int:
    """处理单个日志文件。"""
    if not log_file.exists():
        logger.error("文件不存在: %s", log_file)
        return 1

    t0 = time.perf_counter()
    try:
        seq = run_layer0(log_file, cfg)
    except Exception as e:
        logger.error("解析失败 [%s]: %s", log_file.name, e, exc_info=True)
        return 1

    elapsed = time.perf_counter() - t0
    _print_seq_stats(seq, elapsed)

    if not dry_run:
        out_dir = output_dir or log_file.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"layer0_{seq.metadata.session_id}.jsonl"
        from src.utils.serializer import save_turn_sequence
        save_turn_sequence(seq, out_file)
        print(f"[OK] 输出: {out_file}")

    return 0


def _process_batch(
    log_dir: Path,
    output_dir: Path | None,
    cfg: Config,
    dry_run: bool,
    summary_path: Path | None,
) -> int:
    """批量处理目录下的所有日志文件。"""
    if not log_dir.exists():
        logger.error("目录不存在: %s", log_dir)
        return 1

    out_dir = output_dir or (log_dir.parent / "layer0_output")
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    summary_records = []
    errors = 0
    total_start = time.perf_counter()

    log_files = sorted(log_dir.glob("*.jsonl"))
    if not log_files:
        logger.warning("目录下无 JSONL 文件: %s", log_dir)
        return 0

    print(f"[INFO] 发现 {len(log_files)} 个日志文件，开始处理...")

    for log_file in log_files:
        t0 = time.perf_counter()
        try:
            seq = run_layer0(log_file, cfg)
            elapsed = time.perf_counter() - t0

            record = {
                "file": log_file.name,
                "session_id": seq.metadata.session_id,
                "turns": seq.turn_count,
                "events": seq.event_count,
                "rag_calls": seq.rag_call_count,
                "elapsed_s": round(elapsed, 4),
                "status": "OK",
            }

            if not dry_run:
                out_file = out_dir / f"layer0_{seq.metadata.session_id}.jsonl"
                from src.utils.serializer import save_turn_sequence
                save_turn_sequence(seq, out_file)
                record["output"] = str(out_file)

            summary_records.append(record)
            _print_seq_stats(seq, elapsed, prefix=f"  [{log_file.name}]")

        except Exception as e:
            elapsed = time.perf_counter() - t0
            logger.error("解析失败 [%s]: %s", log_file.name, e, exc_info=True)
            summary_records.append({
                "file": log_file.name,
                "elapsed_s": round(elapsed, 4),
                "status": "ERROR",
                "error": str(e),
            })
            errors += 1

    total_elapsed = time.perf_counter() - total_start
    ok = len(log_files) - errors

    print(f"\n[完成] 成功: {ok}/{len(log_files)}  失败: {errors}  总耗时: {total_elapsed:.2f}s")

    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_records, f, ensure_ascii=False, indent=2)
        print(f"[摘要] 已写入: {summary_path}")

    return 1 if errors > 0 else 0


def _print_seq_stats(seq, elapsed: float, prefix: str = "") -> None:
    rag_ctx = sum(1 for e in seq.all_events if e.has_rag_context)
    code_writes = sum(
        1 for e in seq.all_events
        if e.call.action_category is not None
        and e.call.action_category.value == "code_write"
    )
    print(
        f"{prefix} session={seq.metadata.session_id[:8]}...  "
        f"turns={seq.turn_count}  events={seq.event_count}  "
        f"rag={seq.rag_call_count}  rag_ctx_events={rag_ctx}  "
        f"code_writes={code_writes}  [{elapsed*1000:.1f}ms]"
    )


if __name__ == "__main__":
    sys.exit(main())
