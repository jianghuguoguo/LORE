"""
run/run_full_pipeline.py
========================
LORE 全流程 CLI 后端入口。

串联执行五层知识蒸馏流水线：

    Layer 0  日志标准化 (AdapterRegistry → CanonicalAgentTurn)
    Layer 1  LLM 会话标注 (outcome / CVE / failure_root_cause)
    Layer 2  经验蒸馏 (五类结构化经验，不上传)
    Layer 3  XPEC 跨会话融合 (Phase 1-5: SEC / EWC / RME / BCC / KLM)
    Reflux   RAGflow 经验回流上传（正常写入）

每阶段结果持久化到::

    data/layer0_output/      — 标准化 TurnSequence
    data/layer1_output/      — LLM 标注结果
    data/layer2_output/      — 五类经验 + experience_raw.jsonl
    data/layer3_output/      — 等价集 / ConsolidatedExp / KLM 注册表

用法::

    # 完整流水线（默认）
    python run/run_full_pipeline.py

    # 仅运行指定阶段（可组合）
    python run/run_full_pipeline.py --stages layer0 layer1 layer2

    # 跳过 RAGflow 上传
    python run/run_full_pipeline.py --no-ragflow

    # 详细日志
    python run/run_full_pipeline.py --verbose

    # 显示当前流水线阶段状态（不执行）
    python run/run_full_pipeline.py --status

退出码::

    0  — 全部阶段成功
    1  — 至少一个阶段失败
    2  — 参数解析错误
"""
from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys

# ── Windows GBK 终端强制 UTF-8 输出（防止 Rich / print 编码崩溃）──────────────────
if hasattr(sys.stdout, 'buffer') and getattr(sys.stdout, 'encoding', 'utf-8').upper() not in ('UTF-8', 'UTF8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'buffer') and getattr(sys.stderr, 'encoding', 'utf-8').upper() not in ('UTF-8', 'UTF8'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── rich (可选，降级到普通 print) ─────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False  # type: ignore

ROOT = Path(__file__).resolve().parent.parent

# ─────────────────────────────────────────────────────────────────────────────
# 阶段定义
# ─────────────────────────────────────────────────────────────────────────────

# (stage_key, 显示名称, CLI 命令模板, 输出目录/文件)
_STAGES: List[Tuple[str, str, str, str]] = [
    (
        "layer0",
        "Layer 0  日志标准化",
        "python run/run_layer0.py --log-dir logs --output-dir data/layer0_output",
        "data/layer0_output",
    ),
    (
        "layer1",
        "Layer 1  LLM 会话标注",
        "python run/run_layer1_llm_batch.py",
        "data/layer1_output",
    ),
    (
        "layer2",
        "Layer 2  经验蒸馏",
        "python run/run_layer2_analysis.py --no-ragflow",
        "data/layer2_output",
    ),
    (
        "layer3_p12",
        "Layer 3  Phase 1+2  SEC / EWC",
        "python run/run_layer3_phase12.py",
        "data/layer3_output/phase12_result.jsonl",
    ),
    (
        "layer3_p34",
        "Layer 3  Phase 3+4  RME / BCC",
        "python run/run_layer3_phase34.py",
        "data/layer3_output/phase34_consolidated.jsonl",
    ),
    (
        "layer3_p5",
        "Layer 3  Phase 5    KLM",
        "python run/run_layer3_phase5.py",
        "data/layer3_output/phase5_klm_registry.jsonl",
    ),
    (
        "layer4",
        "Layer 4  缺口感知 + 冲突检测",
        "python run/run_layer4_gap_dispatch.py --no-crawl",
        "data/layer4_output/gap_dispatch_summary.json",
    ),
    (
        "upload",
        "Upload   上传 Layer3 融合经验到 RAGflow",
        "python -m src.ragflow.uploader --source fused",
        "data/layer3_output/phase34_consolidated.jsonl",
    ),
]

_STAGE_KEYS = [s[0] for s in _STAGES]

# ─────────────────────────────────────────────────────────────────────────────
# 输出工具（rich / fallback）
# ─────────────────────────────────────────────────────────────────────────────

if _RICH:
    _console = Console(highlight=False, legacy_windows=False)

    def _print(msg: str, style: str = "") -> None:
        _console.print(msg, style=style)

    def _print_header(title: str) -> None:
        _console.print(Panel(f"[bold white]{title}[/]", box=box.DOUBLE_EDGE,
                             border_style="cyan", expand=False))

    def _print_success(msg: str) -> None:
        _console.print(f"  [bold green]✔[/]  {msg}")

    def _print_failure(msg: str) -> None:
        _console.print(f"  [bold red]✘[/]  {msg}")

    def _print_skip(msg: str) -> None:
        _console.print(f"  [bold yellow]–[/]  {msg}")

else:
    def _print(msg: str, style: str = "") -> None:          # type: ignore[misc]
        print(msg)

    def _print_header(title: str) -> None:                  # type: ignore[misc]
        bar = "=" * 60
        print(f"\n{bar}\n  {title}\n{bar}")

    def _print_success(msg: str) -> None:                   # type: ignore[misc]
        print(f"  [OK]  {msg}")

    def _print_failure(msg: str) -> None:                   # type: ignore[misc]
        print(f"  [FAIL]  {msg}")

    def _print_skip(msg: str) -> None:                      # type: ignore[misc]
        print(f"  [SKIP]  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# 状态追踪
# ─────────────────────────────────────────────────────────────────────────────

_STATE_FILE = ROOT / "data" / ".pipeline_state.json"

STATUS_PENDING  = "pending"
STATUS_RUNNING  = "running"
STATUS_DONE     = "done"
STATUS_FAILED   = "failed"
STATUS_SKIPPED  = "skipped"


def _load_state() -> Dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: Dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _output_exists(output_path: str) -> bool:
    p = ROOT / output_path
    return p.exists()


# ─────────────────────────────────────────────────────────────────────────────
# --status 展示
# ─────────────────────────────────────────────────────────────────────────────

def show_status() -> None:
    state = _load_state()

    if _RICH:
        table = Table(
            title="LORE 流水线阶段状态",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            show_lines=True,
        )
        table.add_column("#",          justify="right",  style="dim",       width=3)
        table.add_column("阶段",        justify="left",   style="bold white", min_width=34)
        table.add_column("状态",        justify="center",                    width=10)
        table.add_column("耗时",        justify="right",  style="dim",       width=10)
        table.add_column("完成时间",    justify="left",   style="dim",       width=22)
        table.add_column("输出",        justify="left",   style="dim",       width=10)

        _STATUS_STYLE = {
            STATUS_DONE:    ("[bold green]done[/]",    "green"),
            STATUS_FAILED:  ("[bold red]FAILED[/]",    "red"),
            STATUS_RUNNING: ("[bold yellow]running[/]","yellow"),
            STATUS_SKIPPED: ("[dim]skipped[/]",        "dim"),
            STATUS_PENDING: ("[dim]pending[/]",        "dim"),
        }

        for i, (key, label, _cmd, output_path) in enumerate(_STAGES, 1):
            rec = state.get(key, {})
            status = rec.get("status", STATUS_PENDING)
            elapsed = f"{rec['elapsed']:.1f}s" if rec.get("elapsed") else "—"
            finished = rec.get("finished_at", "—")
            if finished and finished != "—":
                finished = finished[:19].replace("T", " ")
            out_ok = "✔" if _output_exists(output_path) else "—"
            status_str, _ = _STATUS_STYLE.get(status, (status, "dim"))
            table.add_row(str(i), label, status_str, elapsed, finished, out_ok)

        _console.print()
        _console.print(table)
        _console.print()
    else:
        print("\nLORE 流水线阶段状态")
        print("-" * 70)
        for i, (key, label, _cmd, output_path) in enumerate(_STAGES, 1):
            rec = state.get(key, {})
            status = rec.get("status", STATUS_PENDING)
            elapsed = f"{rec['elapsed']:.1f}s" if rec.get("elapsed") else "—"
            out_ok = "✔" if _output_exists(output_path) else "—"
            print(f"  [{i}] {label:<40s} {status:<10s} {elapsed:>8s}  output={out_ok}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# 单阶段执行
# ─────────────────────────────────────────────────────────────────────────────

def _run_stage(
    key: str,
    label: str,
    cmd: str,
    output_path: str,
    *,
    verbose: bool = False,
    state: Dict,
) -> bool:
    """执行单个阶段，更新 state，返回是否成功。"""

    if verbose:
        cmd = cmd + " --verbose"

    if _RICH:
        _console.rule(f"[bold cyan]{label}[/]")
    else:
        _print_header(label)

    _print(f"  [dim]命令:[/] {cmd}", style="")
    _print(f"  [dim]输出:[/] {output_path}", style="")

    state[key] = {
        "status":     STATUS_RUNNING,
        "started_at": datetime.now(tz=timezone.utc).isoformat(),
        "command":    cmd,
        "output":     output_path,
    }
    _save_state(state)

    t0 = time.perf_counter()
    try:
        env = {**__import__("os").environ, "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=ROOT,
            check=True,
            env=env,
        )
        elapsed = time.perf_counter() - t0
        state[key].update({
            "status":      STATUS_DONE,
            "elapsed":     round(elapsed, 2),
            "returncode":  0,
            "finished_at": datetime.now(tz=timezone.utc).isoformat(),
        })
        _save_state(state)
        _print_success(f"{label}  [{elapsed:.1f}s]")
        return True

    except subprocess.CalledProcessError as exc:
        elapsed = time.perf_counter() - t0
        state[key].update({
            "status":      STATUS_FAILED,
            "elapsed":     round(elapsed, 2),
            "returncode":  exc.returncode,
            "finished_at": datetime.now(tz=timezone.utc).isoformat(),
            "error":       str(exc),
        })
        _save_state(state)
        _print_failure(f"{label} 执行失败  (exit={exc.returncode}, {elapsed:.1f}s)")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 完成汇总
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(results: List[Tuple[str, str, bool, float]]) -> None:
    """results: [(key, label, ok, elapsed), ...]"""
    total     = len(results)
    succeeded = sum(1 for _, _, ok, _ in results if ok)
    failed    = total - succeeded

    if _RICH:
        _console.rule("[bold white]流水线执行摘要[/]")
        table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
        table.add_column("阶段",     justify="left",  min_width=34)
        table.add_column("结果",     justify="center", width=10)
        table.add_column("耗时",     justify="right",  width=10)
        for key, label, ok, elapsed in results:
            status_str = "[bold green]✔ done[/]" if ok else "[bold red]✘ FAILED[/]"
            table.add_row(label, status_str, f"{elapsed:.1f}s")
        _console.print(table)
        if failed == 0:
            _console.print(Panel(
                f"[bold green]全部 {total} 个阶段执行成功[/]",
                border_style="green", expand=False,
            ))
        else:
            _console.print(Panel(
                f"[bold red]{failed}/{total} 个阶段失败[/] — 请检查以上日志",
                border_style="red", expand=False,
            ))
        _console.print()
    else:
        print("\n" + "=" * 60)
        print("流水线执行摘要")
        print("=" * 60)
        for key, label, ok, elapsed in results:
            mark = "OK  " if ok else "FAIL"
            print(f"  [{mark}]  {label:<40s}  {elapsed:.1f}s")
        print("-" * 60)
        if failed == 0:
            print(f"  全部 {total} 个阶段执行成功")
        else:
            print(f"  {failed}/{total} 个阶段失败，请检查以上日志")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI 参数解析
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_full_pipeline",
        description=(
            "LORE 全流程 CLI — 五层知识蒸馏流水线\n\n"
            "阶段键值：" + "  ".join(_STAGE_KEYS)
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python run/run_full_pipeline.py                      # 完整流水线\n"
            "  python run/run_full_pipeline.py --stages layer1 layer2  # 仅标注+蒸馏\n"
            "  python run/run_full_pipeline.py --no-ragflow          # 跳过末尾统一上传（离线调试用）\n"
            "  python run/run_full_pipeline.py --status              # 展示各阶段状态\n"
            "  python run/run_full_pipeline.py --verbose             # 详细日志\n"
        ),
    )

    parser.add_argument(
        "--stages",
        nargs="+",
        metavar="STAGE",
        choices=_STAGE_KEYS,
        default=None,
        help=(
            "仅运行指定阶段（空格分隔，默认全部）。\n"
            f"可选值: {', '.join(_STAGE_KEYS)}"
        ),
    )
    parser.add_argument(
        "--no-ragflow",
        action="store_true",
        default=False,
        help="跳过末尾统一上传 RAGflow（Layer 2 蒸馏不受影响，始终不上传）",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="各阶段传入 --verbose，输出详细调试日志",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        default=False,
        help="展示各阶段历史执行状态后退出（不执行任何阶段）",
    )
    parser.add_argument(
        "--reset-state",
        action="store_true",
        default=False,
        help="清除历史执行状态记录后退出",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="LORE run_full_pipeline 1.0.0",
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --status
    if args.status:
        show_status()
        return 0

    # --reset-state
    if args.reset_state:
        if _STATE_FILE.exists():
            _STATE_FILE.unlink()
        _print_success("状态记录已清除")
        return 0

    # 确定要运行的阶段
    target_keys: List[str] = args.stages if args.stages else _STAGE_KEYS
    stages_to_run = [s for s in _STAGES if s[0] in target_keys]

    # 按 _STAGE_KEYS 中定义的顺序执行（不按 --stages 的输入顺序）
    stages_to_run.sort(key=lambda s: _STAGE_KEYS.index(s[0]))

    # Banner
    if _RICH:
        _console.print()
        _console.print(Panel.fit(
            "[bold cyan]LORE[/]  全流程知识蒸馏流水线\n"
            f"[dim]阶段: {', '.join(s[0] for s in stages_to_run)}[/]\n"
            f"[dim]末尾RAGflow上传: {'已禁用' if args.no_ragflow else '已启用'}[/]  "
            f"[dim]详细日志: {'是' if args.verbose else '否'}[/]",
            box=box.DOUBLE,
            border_style="cyan",
        ))
        _console.print()
    else:
        _print_header(
            f"LORE 全流程知识蒸馏流水线\n"
            f"  阶段: {', '.join(s[0] for s in stages_to_run)}"
        )

    state = _load_state()
    results: List[Tuple[str, str, bool, float]] = []
    overall_ok = True
    pipeline_t0 = time.perf_counter()

    for key, label, cmd, output_path in stages_to_run:
        if key not in target_keys:
            state[key] = {"status": STATUS_SKIPPED}
            _save_state(state)
            _print_skip(f"{label} — 跳过")
            results.append((key, label, True, 0.0))
            continue

        # --no-ragflow 时跳过最终上传阶段
        if args.no_ragflow and key == "upload":
            state[key] = {"status": STATUS_SKIPPED, "skip_reason": "no_ragflow_flag"}
            _save_state(state)
            _print_skip(f"{label} — 已跳过 (--no-ragflow)")
            results.append((key, label, True, 0.0))
            continue

        t0 = time.perf_counter()
        ok = _run_stage(
            key, label, cmd, output_path,
            verbose=args.verbose,
            state=state,
        )
        elapsed = time.perf_counter() - t0
        results.append((key, label, ok, elapsed))

        if not ok:
            overall_ok = False
            if _RICH:
                _console.print(
                    f"\n  [bold red]阶段 [{key}] 失败，流水线中止。[/]\n"
                    f"  [dim]后续阶段: "
                    + ", ".join(s[0] for s in stages_to_run
                                if _STAGE_KEYS.index(s[0]) > _STAGE_KEYS.index(key))
                    + " 已跳过[/]\n"
                )
            else:
                print(f"\n  阶段 [{key}] 失败，流水线中止。")
            # 标记后续为 skipped
            remaining = [s for s in stages_to_run
                         if _STAGE_KEYS.index(s[0]) > _STAGE_KEYS.index(key)]
            for rk, rl, _, _ in remaining:
                state[rk] = {"status": STATUS_SKIPPED, "skip_reason": f"upstream_{key}_failed"}
                results.append((rk, rl, False, 0.0))
            _save_state(state)
            break

    total_elapsed = time.perf_counter() - pipeline_t0
    _print_summary(results)

    if _RICH:
        _console.print(
            f"  [dim]总耗时: {total_elapsed:.1f}s[/]  "
            f"[dim]状态记录: {_STATE_FILE.relative_to(ROOT)}[/]\n"
        )
    else:
        print(f"  总耗时: {total_elapsed:.1f}s  状态记录: {_STATE_FILE.relative_to(ROOT)}\n")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())

