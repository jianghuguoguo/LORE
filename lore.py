#!/usr/bin/env python3
"""
LORE 命令行工具

用法:
    python lore.py              # 进入交互 TUI
    python lore.py --tui        # 同上（显式指定）
    python lore.py run          # 运行完整流水线
    python lore.py run --stages layer1 layer2
    python lore.py status       # 查看各阶段状态
    python lore.py upload       # 上传 Layer3 融合经验到 RAGflow
    python lore.py reset        # 清除状态记录
"""
from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import subprocess
import sys

# ── Windows GBK 终端强制 UTF-8 输出────────────────────────────────────────────
if hasattr(sys.stdout, 'buffer') and getattr(sys.stdout, 'encoding', 'utf-8').upper() not in ('UTF-8', 'UTF8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'buffer') and getattr(sys.stderr, 'encoding', 'utf-8').upper() not in ('UTF-8', 'UTF8'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent

# ── 依赖检查（rich / questionary）────────────────────────────────────────────
def _require(pkg: str) -> bool:
    try:
        importlib.import_module(pkg)
        return True
    except ImportError:
        return False

_HAS_RICH = _require("rich")
_HAS_Q    = _require("questionary")

if not _HAS_RICH or not _HAS_Q:
    miss = [p for p, ok in [("rich", _HAS_RICH), ("questionary", _HAS_Q)] if not ok]
    print(f"[LORE] 缺少依赖: {', '.join(miss)}")
    print(f"  请运行: pip install {' '.join(miss)}")
    sys.exit(1)

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn,
    TaskProgressColumn, TextColumn, TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
import questionary
from questionary import Style as QStyle

console = Console(legacy_windows=False)

# ─────────────────────────────────────────────────────────────────────────────
# 品牌样式
# ─────────────────────────────────────────────────────────────────────────────

_BANNER = (
    " _      ___  ____  _____\n"
    "| |    / _ \\|  _ \\| ____|\n"
    "| |   | | | | |_) |  _|\n"
    "| |___| |_| |  _ <| |___\n"
    "|_____|\\___/|_| \\_\\_____|"
)

_Q_STYLE = QStyle([
    ("qmark",         "fg:#00d7ff bold"),
    ("question",      "bold"),
    ("answer",        "fg:#00ff87 bold"),
    ("pointer",       "fg:#00d7ff bold"),
    ("highlighted",   "fg:#ffffff bg:#005f87 bold"),
    ("selected",      "fg:#00ff87"),
    ("separator",     "fg:#444444"),
    ("instruction",   "fg:#888888"),
    ("text",          ""),
    ("disabled",      "fg:#444444 italic"),
])

# ─────────────────────────────────────────────────────────────────────────────
# 阶段定义（与 run/run_full_pipeline.py 保持一致）
# ─────────────────────────────────────────────────────────────────────────────

STAGES = [
    ("layer0",    "Layer 0  日志标准化",           "data/layer0_output"),
    ("layer1",    "Layer 1  LLM 会话标注",         "data/layer1_output"),
    ("layer2",    "Layer 2  经验蒸馏",            "data/layer2_output"),
    ("layer3_p12","Layer 3  Phase 1+2  SEC/EWC",   "data/layer3_output/phase12_result.jsonl"),
    ("layer3_p34","Layer 3  Phase 3+4  RME/BCC",   "data/layer3_output/phase34_consolidated.jsonl"),
    ("layer3_p5", "Layer 3  Phase 5    KLM",        "data/layer3_output/phase5_klm_registry.jsonl"),
    ("layer4",    "Layer 4  缺口感知 + 冲突检测",  "data/layer4_output/gap_dispatch_summary.json"),
    ("upload",    "Upload   上传 Layer3 融合经验到 RAGflow", "data/layer3_output/phase34_consolidated.jsonl"),
]
STAGE_KEYS   = [s[0] for s in STAGES]
STAGE_LABELS = {s[0]: s[1] for s in STAGES}

_STATE_FILE = ROOT / "data" / ".pipeline_state.json"

STATUS_COLORS = {
    "done":    "bold green",
    "failed":  "bold red",
    "running": "bold yellow",
    "skipped": "dim",
    "pending": "dim",
}
STATUS_ICONS = {
    "done":    "✔",
    "failed":  "✘",
    "running": "⟳",
    "skipped": "–",
    "pending": "·",
}

# ─────────────────────────────────────────────────────────────────────────────
# 状态 I/O
# ─────────────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
    )

# ─────────────────────────────────────────────────────────────────────────────
# 欢迎 Banner
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    console.print()
    banner_text = Text(_BANNER, style="bold cyan")
    console.print(Align.center(banner_text))
    console.print(Align.center(
        Text("LORE · Knowledge Distillation System",
             style="dim italic")
    ))
    console.print(Align.center(Text("v1.0.0  |  Layer 0→4 Pipeline", style="dim")))
    console.print()

# ─────────────────────────────────────────────────────────────────────────────
# 状态表格
# ─────────────────────────────────────────────────────────────────────────────

def build_status_table(state: dict) -> Table:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
        title="[bold white]流水线阶段状态[/]",
    )
    table.add_column("#",       justify="right",  style="dim",       width=3)
    table.add_column("阶段",    justify="left",   style="bold white", min_width=36)
    table.add_column("状态",    justify="center",                     width=10)
    table.add_column("耗时",    justify="right",  style="dim",        width=8)
    table.add_column("完成时间",justify="left",   style="dim",        width=20)
    table.add_column("输出",    justify="center",                     width=6)

    for i, (key, label, output_path) in enumerate(STAGES, 1):
        rec    = state.get(key, {})
        status = rec.get("status", "pending")
        color  = STATUS_COLORS.get(status, "dim")
        icon   = STATUS_ICONS.get(status, "·")
        elapsed = f"{rec['elapsed']:.1f}s" if rec.get("elapsed") else "—"
        finished = rec.get("finished_at", "")
        if finished:
            finished = finished[:19].replace("T", " ")
        else:
            finished = "—"
        out_ok = "[green]✔[/]" if (ROOT / output_path).exists() else "[dim]—[/]"
        table.add_row(
            str(i), label,
            f"[{color}]{icon} {status}[/]",
            elapsed, finished, out_ok,
        )
    return table

def cmd_status() -> None:
    state = load_state()
    console.print()
    console.print(build_status_table(state))
    console.print()

# ─────────────────────────────────────────────────────────────────────────────
# 执行流水线（调用 run/run_full_pipeline.py）
# ─────────────────────────────────────────────────────────────────────────────

def _build_run_cmd(
    stages: Optional[List[str]],
    no_ragflow: bool,
    verbose: bool,
) -> str:
    python = sys.executable
    parts = [python, "run/run_full_pipeline.py"]
    if stages:
        parts += ["--stages"] + stages
    if no_ragflow:
        parts.append("--no-ragflow")
    if verbose:
        parts.append("--verbose")
    return " ".join(parts)


def cmd_run(
    stages: Optional[List[str]] = None,
    no_ragflow: bool = False,
    verbose: bool = False,
) -> int:
    cmd = _build_run_cmd(stages, no_ragflow, verbose)
    console.print(f"\n  [dim]执行:[/] {cmd}\n")
    try:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        ret = subprocess.run(cmd, shell=True, cwd=ROOT, env=env)
        return ret.returncode
    except KeyboardInterrupt:
        console.print("\n[yellow]  ⚠  用户中断[/]\n")
        return 130


def cmd_upload() -> int:
    python = sys.executable
    cmd = f"{python} -m src.ragflow.uploader --source fused"
    console.print(f"\n  [dim]执行:[/] {cmd}\n")
    try:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        ret = subprocess.run(cmd, shell=True, cwd=ROOT, env=env)
        return ret.returncode
    except KeyboardInterrupt:
        return 130


def cmd_reset() -> None:
    if _STATE_FILE.exists():
        _STATE_FILE.unlink()
    console.print("  [green]✔[/]  状态记录已清除\n")

# ─────────────────────────────────────────────────────────────────────────────
# TUI 交互流程
# ─────────────────────────────────────────────────────────────────────────────

def _ask_stage_selection() -> Optional[List[str]]:
    choices = [
        questionary.Choice(title=label, value=key)
        for key, label, _ in STAGES
    ]
    selected = questionary.checkbox(
        "选择要运行的阶段（空格选中 / 全不选 = 全部）:",
        choices=choices,
        style=_Q_STYLE,
    ).ask()
    if selected is None:
        return None          # Ctrl-C
    return selected if selected else None   # 空选 = 全部


def _ask_options() -> Optional[dict]:
    options = questionary.checkbox(
        "启用选项（可多选）:",
        choices=[
            questionary.Choice("跳过 RAGflow 上传  [--no-ragflow]", value="no_ragflow"),
            questionary.Choice("详细日志            [--verbose]",    value="verbose"),
        ],
        style=_Q_STYLE,
    ).ask()
    if options is None:
        return None
    return {
        "no_ragflow": "no_ragflow" in options,
        "verbose":    "verbose"    in options,
    }


def _confirm(question: str) -> bool:
    ans = questionary.confirm(question, default=False, style=_Q_STYLE).ask()
    return bool(ans)


def tui_main() -> int:
    print_banner()

    MAIN_CHOICES = [
        questionary.Choice("▶  运行流水线",         value="run"),
        questionary.Choice("📋  查看阶段状态",       value="status"),
        questionary.Choice("☁  重新上传至 RAGflow", value="upload"),
        questionary.Choice("🗑  清除状态记录",       value="reset"),
        questionary.Separator(),
        questionary.Choice("✕   退出",              value="exit"),
    ]

    while True:
        # 快速状态摘要
        state = load_state()
        done  = sum(1 for k in STAGE_KEYS if state.get(k, {}).get("status") == "done")
        fail  = sum(1 for k in STAGE_KEYS if state.get(k, {}).get("status") == "failed")
        hint  = (
            f"[dim]  阶段进度: {done}/{len(STAGE_KEYS)} 完成"
            + (f"  |  {fail} 失败" if fail else "")
            + "[/]"
        )
        console.print(hint)
        console.print()

        action = questionary.select(
            "请选择操作:",
            choices=MAIN_CHOICES,
            style=_Q_STYLE,
        ).ask()

        if action is None or action == "exit":
            console.print("\n  [dim]再见。[/]\n")
            return 0

        # ── 运行流水线 ────────────────────────────────────────────────────────
        if action == "run":
            console.print()
            run_mode = questionary.select(
                "运行模式:",
                choices=[
                    questionary.Choice("全部阶段（完整流水线）", value="all"),
                    questionary.Choice("自选阶段",               value="select"),
                ],
                style=_Q_STYLE,
            ).ask()
            if run_mode is None:
                continue

            stages = None
            if run_mode == "select":
                stages = _ask_stage_selection()
                if stages is None:
                    continue

            opts = _ask_options()
            if opts is None:
                continue

            # 预览
            console.print()
            preview_rows = []
            run_keys = stages or STAGE_KEYS
            for key, label, _ in STAGES:
                if key in run_keys:
                    preview_rows.append(f"  [cyan]•[/] {label}")
            console.print(Panel(
                "\n".join(preview_rows)
                + f"\n\n  [dim]RAGflow 上传: {'禁用' if opts['no_ragflow'] else '启用'}[/]"
                + f"  [dim]  详细日志: {'是' if opts['verbose'] else '否'}[/]",
                title="[bold white]即将执行[/]",
                border_style="cyan",
                expand=False,
            ))
            console.print()

            if not _confirm("确认开始运行?"):
                continue

            rc = cmd_run(stages=stages, **opts)
            console.print()
            if rc == 0:
                console.print(Panel("[bold green]流水线执行完毕 ✔[/]",
                                    border_style="green", expand=False))
            else:
                console.print(Panel(f"[bold red]流水线退出码: {rc}[/]",
                                    border_style="red", expand=False))
            console.print()
            input("  按 Enter 返回主菜单…")
            console.clear()
            print_banner()

        # ── 状态查看 ──────────────────────────────────────────────────────────
        elif action == "status":
            console.print()
            cmd_status()
            input("  按 Enter 返回主菜单…")
            console.clear()
            print_banner()

        # ── RAGflow 上传 ──────────────────────────────────────────────────────
        elif action == "upload":
            console.print()
            if not _confirm("将 Layer3 融合经验上传至 RAGflow？"):
                continue
            rc = cmd_upload()
            console.print()
            if rc == 0:
                console.print("  [green]✔[/]  上传完成\n")
            else:
                console.print(f"  [red]✘[/]  上传失败 (exit={rc})\n")
            input("  按 Enter 返回主菜单…")
            console.clear()
            print_banner()

        # ── 清除状态 ──────────────────────────────────────────────────────────
        elif action == "reset":
            console.print()
            if _confirm("确认清除所有阶段状态记录？"):
                cmd_reset()
            console.clear()
            print_banner()

# ─────────────────────────────────────────────────────────────────────────────
# CLI 参数解析
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="LORE",
        description="LORE — 渗透测试知识蒸馏系统命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python lore.py              # 进入交互 TUI\n"
            "  python lore.py --tui        # 同上\n"
            "  python lore.py run          # 运行完整流水线\n"
            "  python lore.py run --stages layer1 layer2\n"
            "  python lore.py run --no-ragflow --verbose\n"
            "  python lore.py status       # 查看阶段状态\n"
            "  python lore.py upload       # 上传到 RAGflow\n"
            "  python lore.py reset        # 清除状态记录\n"
        ),
    )
    p.add_argument("--tui",     action="store_true", help="进入交互 TUI（默认行为）")
    p.add_argument("--version", action="version",    version="LORE 1.0.0")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # run
    p_run = sub.add_parser("run", help="运行流水线")
    p_run.add_argument(
        "--stages", nargs="+", metavar="STAGE",
        choices=STAGE_KEYS, default=None,
        help=f"指定阶段 (默认全部): {', '.join(STAGE_KEYS)}",
    )
    p_run.add_argument("--no-ragflow", action="store_true", help="跳过 RAGflow 上传")
    p_run.add_argument("--verbose", "-v", action="store_true", help="输出详细日志")

    # status
    sub.add_parser("status",  help="查看各阶段执行状态")

    # upload
    sub.add_parser("upload",  help="重新上传 Layer3 融合经验至 RAGflow")

    # reset
    sub.add_parser("reset",   help="清除状态记录 (.pipeline_state.json)")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # 无子命令 / --tui → 进 TUI
    if args.command is None or args.tui:
        try:
            return tui_main()
        except KeyboardInterrupt:
            console.print("\n  [dim]已退出。[/]\n")
            return 0

    if args.command == "run":
        return cmd_run(
            stages=args.stages,
            no_ragflow=args.no_ragflow,
            verbose=args.verbose,
        )

    if args.command == "status":
        cmd_status()
        return 0

    if args.command == "upload":
        return cmd_upload()

    if args.command == "reset":
        cmd_reset()
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

