#!/usr/bin/env python3
"""
scripts/run_pipeline_track_tokens.py
=====================================
运行 layer0 → layer1 → layer2 流水线（不上传 RAGflow），
统计每个日志文件处理的 token 消耗。

用法：
    python scripts/run_pipeline_track_tokens.py --log-dir ../logs
    python scripts/run_pipeline_track_tokens.py --log-dir ../logs --verbose

输出：
    - Layer 0 / Layer 1 / Layer 2 逐文件处理结果
    - 每个文件的 token 消耗统计表（prompt / completion / total）
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.layer0.pipeline import run_layer0
from src.layer1.pipeline import run_layer1_with_llm
from src.layer2.pipeline import run_layer2
from src.llm_client import LLMClient, LLMCallResult
from src.utils.config_loader import get_config
from src.utils.log_utils import get_logger
from src.utils.serializer import load_turn_sequence, save_turn_sequence

logger = get_logger("token_tracker")


# ─────────────────────────────────────────────────────────────────────────────
# Token 统计数据结构
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileTokenStats:
    """单个日志文件的 token 消耗统计。"""
    log_file: str
    session_id: str
    layer0_ok: bool = False
    layer0_elapsed: float = 0.0
    layer0_msg_count: int = 0

    layer1_ok: bool = False
    layer1_elapsed: float = 0.0
    layer1_prompt_tokens: int = 0
    layer1_completion_tokens: int = 0
    layer1_total_tokens: int = 0
    layer1_call_count: int = 0

    layer2_ok: bool = False
    layer2_elapsed: float = 0.0
    layer2_prompt_tokens: int = 0
    layer2_completion_tokens: int = 0
    layer2_total_tokens: int = 0
    layer2_call_count: int = 0
    layer2_experience_count: int = 0

    @property
    def total_prompt(self) -> int:
        return self.layer1_prompt_tokens + self.layer2_prompt_tokens

    @property
    def total_completion(self) -> int:
        return self.layer1_completion_tokens + self.layer2_completion_tokens

    @property
    def total_tokens(self) -> int:
        return self.layer1_total_tokens + self.layer2_total_tokens

    @property
    def total_elapsed(self) -> float:
        return self.layer0_elapsed + self.layer1_elapsed + self.layer2_elapsed


# ─────────────────────────────────────────────────────────────────────────────
# 有状态 Token 计数 LLM 客户端包装器
# ─────────────────────────────────────────────────────────────────────────────

class TokenTrackingClient:
    """包装 LLMClient，记录每次调用的 token 消耗。"""

    def __init__(self, client: LLMClient):
        self._client = client
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0
        self.call_count: int = 0

    def chat_json(self, *args, **kwargs) -> LLMCallResult:
        result = self._client.chat_json(*args, **kwargs)
        if result.success:
            self.prompt_tokens += result.prompt_tokens
            self.completion_tokens += result.completion_tokens
            self.total_tokens += result.total_tokens
            self.call_count += 1
        return result

    def reset(self) -> None:
        """重置计数器（用于切换到下一个文件前）。"""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.call_count = 0

    @property
    def model(self) -> str:
        return self._client.model


# ─────────────────────────────────────────────────────────────────────────────
# 流水线处理函数
# ─────────────────────────────────────────────────────────────────────────────

def process_log_file(
    log_path: Path,
    layer0_out_dir: Path,
    layer1_out_dir: Path,
    layer2_out_dir: Path,
    llm_client: TokenTrackingClient,
    cfg,
    verbose: bool = False,
) -> FileTokenStats:
    """处理单个日志文件，返回 token 统计。"""
    stats = FileTokenStats(log_file=log_path.name, session_id="???")

    # ── 清空 LLM 的旧计数 ────────────────────────────────────────────────
    llm_client.reset()

    # ── Layer 0: 日志标准化 ──────────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        seq = run_layer0(log_path, cfg)
        stats.layer0_elapsed = time.perf_counter() - t0
        stats.layer0_ok = True
        stats.session_id = seq.metadata.session_id
        stats.layer0_msg_count = len(seq.all_events)

        # 保存 layer0 结果
        out_file = layer0_out_dir / f"layer0_{seq.metadata.session_id}.jsonl"
        save_turn_sequence(seq, out_file)
        if verbose:
            print(f"  [Layer0] {log_path.name} → {out_file.name}  ({stats.layer0_elapsed:.1f}s)")
    except Exception as e:
        stats.layer0_elapsed = time.perf_counter() - t0
        print(f"  [Layer0] ✘ {log_path.name}: {e}")
        return stats

    # ── Layer 1: LLM 会话标注 ────────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        ann_seq = run_layer1_with_llm(seq, client=llm_client)
        stats.layer1_elapsed = time.perf_counter() - t0
        stats.layer1_ok = True
        stats.layer1_prompt_tokens = llm_client.prompt_tokens
        stats.layer1_completion_tokens = llm_client.completion_tokens
        stats.layer1_total_tokens = llm_client.total_tokens
        stats.layer1_call_count = llm_client.call_count

        # 保存 layer1 结果
        from src.layer1.pipeline import save_annotated_turn_sequence
        out_file = layer1_out_dir / f"layer1_{stats.session_id}.jsonl"
        save_annotated_turn_sequence(ann_seq, out_file)
        if verbose:
            print(f"  [Layer1] {stats.session_id[:8]}  tokens={stats.layer1_total_tokens}  calls={stats.layer1_call_count}  ({stats.layer1_elapsed:.1f}s)")
    except Exception as e:
        stats.layer1_elapsed = time.perf_counter() - t0
        print(f"  [Layer1] ✘ {stats.session_id[:8]}: {e}")
        # 即使 layer1 失败也继续 layer2

    # ── Layer 2: 经验蒸馏 ────────────────────────────────────────────────
    # 重置 LLM 计数器，单独追踪 layer2 的 token
    llm_client.reset()
    t0 = time.perf_counter()
    try:
        bundle = run_layer2(ann_seq, client=llm_client, save=True, output_dir=layer2_out_dir)
        stats.layer2_elapsed = time.perf_counter() - t0
        stats.layer2_ok = True
        stats.layer2_prompt_tokens = llm_client.prompt_tokens
        stats.layer2_completion_tokens = llm_client.completion_tokens
        stats.layer2_total_tokens = llm_client.total_tokens
        stats.layer2_call_count = llm_client.call_count
        stats.layer2_experience_count = bundle.total_count
        if verbose:
            print(f"  [Layer2] {stats.session_id[:8]}  tokens={stats.layer2_total_tokens}  calls={stats.layer2_call_count}  exps={bundle.total_count}  ({stats.layer2_elapsed:.1f}s)")
    except Exception as e:
        stats.layer2_elapsed = time.perf_counter() - t0
        print(f"  [Layer2] ✘ {stats.session_id[:8]}: {e}")

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# 结果展示
# ─────────────────────────────────────────────────────────────────────────────

def print_token_summary(all_stats: List[FileTokenStats]) -> None:
    """打印 Token 消耗汇总表。"""
    sep = "-" * 120
    print("\n" + sep)
    print(f"{'日志文件':<50s} {'会话ID':<12s} {'阶段':<8s} {'Prompt':>10s} {'Completion':>10s} {'Total':>10s} {'调用次数':>8s} {'耗时':>8s}")
    print(sep)

    grand_prompt = 0
    grand_completion = 0
    grand_total = 0
    grand_calls = 0
    grand_elapsed = 0.0

    for s in all_stats:
        file_label = s.log_file[:48] if len(s.log_file) > 48 else s.log_file
        sid = s.session_id[:10]

        # Layer 1 行
        if s.layer1_ok:
            print(f"{file_label:<50s} {sid:<12s} {'Layer1':<8s} {s.layer1_prompt_tokens:>10,d} {s.layer1_completion_tokens:>10,d} {s.layer1_total_tokens:>10,d} {s.layer1_call_count:>8d} {s.layer1_elapsed:>7.1f}s")
        else:
            print(f"{file_label:<50s} {sid:<12s} {'Layer1':<8s} {'✘ 失败':>30s} {'':>8s} {s.layer1_elapsed:>7.1f}s")

        # Layer 2 行
        if s.layer2_ok:
            print(f"{'':50s} {'':12s} {'Layer2':<8s} {s.layer2_prompt_tokens:>10,d} {s.layer2_completion_tokens:>10,d} {s.layer2_total_tokens:>10,d} {s.layer2_call_count:>8d} {s.layer2_elapsed:>7.1f}s")
        else:
            print(f"{'':50s} {'':12s} {'Layer2':<8s} {'✘ 失败':>30s} {'':>8s} {s.layer2_elapsed:>7.1f}s")

        # 小计
        sub_total = s.total_tokens
        sub_calls = s.layer1_call_count + s.layer2_call_count
        sub_elapsed = s.total_elapsed
        print(f"{'':50s} {'':12s} {'小计':<8s} {s.total_prompt:>10,d} {s.total_completion:>10,d} {sub_total:>10,d} {sub_calls:>8d} {sub_elapsed:>7.1f}s")
        print(sep)

        grand_prompt += s.total_prompt
        grand_completion += s.total_completion
        grand_total += sub_total
        grand_calls += sub_calls
        grand_elapsed += sub_elapsed

    # 总计
    print(f"{'总计':<50s} {'':12s} {'':8s} {grand_prompt:>10,d} {grand_completion:>10,d} {grand_total:>10,d} {grand_calls:>8d} {grand_elapsed:>7.1f}s")
    print(sep)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_pipeline_track_tokens",
        description="运行 layer0→layer1→layer2 并统计每个文件的 token 消耗",
    )
    p.add_argument("--log-dir", "-d", type=Path, default=None,
                    help="日志目录（默认: ../logs 即项目 logs 目录）")
    p.add_argument("--output-dir", "-o", type=Path, default=None,
                    help="输出根目录（默认: ../data）")
    p.add_argument("--verbose", "-v", action="store_true", default=False,
                    help="输出详细处理日志")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                    default="WARNING", help="日志级别")
    return p


def main() -> int:
    args = build_parser().parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    root = _ROOT
    log_dir = args.log_dir or (root / "logs")
    output_root = args.output_dir or (root / "data")

    if not log_dir.exists():
        print(f"[错误] 日志目录不存在: {log_dir}")
        return 1

    # 收集日志文件
    log_files = sorted(log_dir.glob("*.jsonl"))
    # 排除 last 文件和 layer* 输出文件
    log_files = [f for f in log_files
                 if f.name != "last"
                 and not f.name.startswith("layer0_")
                 and not f.name.startswith("layer1_")
                 and not f.name.startswith("layer2_")
                 and not f.name.startswith("cai_")]  # cai_ files handled separately if they exist

    # 也包含 cai_ 格式的文件
    cai_files = sorted(log_dir.glob("cai_*.jsonl"))
    all_files = sorted(set(log_files) | set(cai_files))

    if not all_files:
        print(f"[错误] 日志目录下无 JSONL 文件: {log_dir}")
        return 1

    print(f"\n找到 {len(all_files)} 个日志文件:")
    for f in all_files:
        size_kb = f.stat().st_size / 1024
        print(f"  {f.name}  ({size_kb:.1f} KB)")
    print()

    # 准备输出目录
    layer0_out = output_root / "layer0_output"
    layer1_out = output_root / "layer1_output"
    layer2_out = output_root / "layer2_output"
    layer0_out.mkdir(parents=True, exist_ok=True)
    layer1_out.mkdir(parents=True, exist_ok=True)
    layer2_out.mkdir(parents=True, exist_ok=True)

    # 加载配置
    try:
        cfg = get_config()
    except Exception as e:
        print(f"[错误] 加载配置失败: {e}")
        return 1

    # 构建 LLM 客户端
    try:
        from src.llm_client import build_llm_client_from_config
        raw_client = build_llm_client_from_config()
        tracking_client = TokenTrackingClient(raw_client)
        print(f"LLM 模型: {raw_client.model}  Provider: {raw_client.provider}\n")
    except Exception as e:
        print(f"[错误] 构建 LLM 客户端失败: {e}")
        print("请确保已设置环境变量或配置文件中有 API Key。")
        return 1

    # ── 逐文件处理 ────────────────────────────────────────────────────────
    all_stats: List[FileTokenStats] = []
    total_start = time.perf_counter()

    for i, log_path in enumerate(all_files, 1):
        print(f"[{i}/{len(all_files)}] 处理: {log_path.name}")
        stats = process_log_file(
            log_path=log_path,
            layer0_out_dir=layer0_out,
            layer1_out_dir=layer1_out,
            layer2_out_dir=layer2_out,
            llm_client=tracking_client,
            cfg=cfg,
            verbose=args.verbose,
        )
        all_stats.append(stats)
        print()

    total_elapsed = time.perf_counter() - total_start

    # ── 打印汇总 ──────────────────────────────────────────────────────────
    print("=" * 120)
    print("  Token 消耗统计汇总")
    print("=" * 120)
    print_token_summary(all_stats)

    print(f"总耗时: {total_elapsed:.1f}s")
    print(f"输出目录:")
    print(f"  Layer 0: {layer0_out}")
    print(f"  Layer 1: {layer1_out}")
    print(f"  Layer 2: {layer2_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
