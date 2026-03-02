"""
run_layer4_gap_dispatch.py
==========================
Layer 4 缺口感知 + 冲突检测一键运行脚本。

职责：
  1. 扫描 Layer 1 标注输出，从失败事件中提取知识缺口信号（GapSignal），
     写入 queues/gap_queue.jsonl（去重）
  2. 立即处理 P0 缺口（INT/INCOMPLETE_RECON 类），触发定向爬取
  3. P1/P2 缺口写入队列，由 scheduler.py 定期消费
  4. 对 Layer 3 KLM 注册表执行冲突检测（PROCEDURAL_NEG vs PROCEDURAL_POS）
  5. 将冲突/衰减结果写入 data/layer3_output/conflict_report.jsonl

输出：
  queues/gap_queue.jsonl              — 缺口信号队列
  queues/static_remediations.jsonl    — 静态修复建议（BINARY_MISSING 等）
  raw_data/layer4/                    — P0 定向爬取结果
  data/layer3_output/conflict_report.jsonl
  data/layer3_output/conflict_summary.json
  data/layer4_output/gap_dispatch_summary.json — 本次运行统计摘要

用法：
  python run_layer4_gap_dispatch.py
  python run_layer4_gap_dispatch.py --no-crawl    # 仅生成缺口信号，跳过爬取
  python run_layer4_gap_dispatch.py --no-conflict # 跳过冲突检测
  python run_layer4_gap_dispatch.py --verbose
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ─────────────────────────────────────────────────────────────────────────────
# 日志配置
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

logger = logging.getLogger("run_layer4")

# ─────────────────────────────────────────────────────────────────────────────
# 路径
# ─────────────────────────────────────────────────────────────────────────────

LAYER1_DIR     = ROOT / "data" / "layer1_output"
LAYER3_DIR     = ROOT / "data" / "layer3_output"
OUTPUT_DIR     = ROOT / "data" / "layer4_output"
QUEUES_DIR     = ROOT / "queues"
RAWDATA_L4_DIR = ROOT / "raw_data" / "layer4"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: 从 Layer 1 输出提取缺口信号
# ─────────────────────────────────────────────────────────────────────────────

# 需要触发爬取的失败维度 → 优先级映射
_DIM_PRIORITY = {
    "INT":  "P0",   # 情报/认知缺口，最高优先
    "INV":  "P1",   # 调用方式问题（工具文档）
    "DEF":  "P1",   # 目标防御（绕过技术）
    "ENV":  "P1",   # 执行环境（部分子类）
    "EFF":  "P2",   # 执行效果（较低优先）
}

# 不触发爬取的子维度（静态修复即可）
_SKIP_SUBDIMS = {
    "BINARY_MISSING", "TIMEOUT", "PERMISSION",
    "DEPENDENCY_MISSING", "AUTHENTICATION", "AUTHORIZATION",
    "ACTIVE_BLOCKING", "BLIND_EXECUTION",
}


def _extract_gap_signals(layer1_files: List[Path]) -> List[Dict[str, Any]]:
    """
    遍历所有 Layer 1 JSONL 文件，从失败事件中提取 GapSignal 列表。
    返回 dict 列表（直接兼容 GapSignal.from_dict()）。
    """
    signals: List[Dict[str, Any]] = []
    existing_event_ids: set = set()

    for path in layer1_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("跳过 %s: %s", path.name, e)
            continue

        session_id = data.get("metadata", {}).get("session_id", path.stem)
        events     = data.get("annotated_events", [])

        for ev in events:
            outcome = ev.get("outcome_label", "")
            if outcome != "failure":
                continue

            event_id = ev.get("event_id") or ev.get("id", "")
            if event_id in existing_event_ids:
                continue
            existing_event_ids.add(event_id)

            frc = ev.get("failure_root_cause") or {}
            dim = frc.get("dimension", "")
            sub = frc.get("sub_dimension", "") or frc.get("sub_type", "")

            if not dim:
                continue
            if sub.upper() in _SKIP_SUBDIMS:
                # 静态修复：记录但不触发爬取信号
                continue

            priority = _DIM_PRIORITY.get(dim.upper(), "P2")

            # 目标服务推断
            base_meta = ev.get("base", {}) or {}
            target_raw = (
                data.get("metadata", {}).get("target_raw", "")
                or base_meta.get("target_raw", "")
            )
            cve_ids = []
            session_meta = data.get("metadata", {}) or {}
            if session_meta.get("primary_cve"):
                cve_ids = [session_meta["primary_cve"]]

            # 构建搜索关键词
            tool_name   = (base_meta.get("call", {}) or {}).get("tool_name", "")
            evidence    = frc.get("evidence", "")
            queries: List[str] = []
            if cve_ids:
                queries.append(f"{cve_ids[0]} exploit writeup")
                queries.append(f"{cve_ids[0]} PoC penetration testing")
            if tool_name:
                queries.append(f"{tool_name} usage guide penetration testing")
            if sub:
                queries.append(f"{sub.lower().replace('_', ' ')} pentest technique")

            signal = {
                "gap_id":          str(uuid.uuid4()),
                "session_id":      session_id,
                "event_id":        event_id,
                "priority":        priority,
                "root_cause_dim":  dim.upper(),
                "root_cause_sub":  sub.upper() if sub else "",
                "target_service":  target_raw[:80],
                "cve_ids":         cve_ids,
                "gap_description": (
                    f"[{dim}/{sub}] {evidence[:120]}" if evidence else f"[{dim}/{sub}]"
                ),
                "search_queries":  queries[:4],
                "status":          "pending",
                "created_at":      datetime.now(tz=timezone.utc).isoformat(),
                "processed_at":    "",
                "retry_count":     0,
            }
            signals.append(signal)

    logger.info("提取 Gap 信号: %d 条（来自 %d 个会话）",
                len(signals), len(layer1_files))
    return signals


def _push_signals_to_queue(signals: List[Dict[str, Any]]) -> Dict[str, int]:
    """将 GapSignal 写入 queues/gap_queue.jsonl，跳过已存在 gap_id。"""
    from src.layer4.gap_queue import GapQueue, GAP_QUEUE_FILE, QUEUE_DIR
    QUEUE_DIR.mkdir(parents=True, exist_ok=True)

    gq       = GapQueue()
    existing = gq.existing_ids()

    stats = Counter()
    for s in signals:
        if s["gap_id"] in existing:
            stats["skipped"] += 1
            continue
        from src.layer4.models import GapSignal
        gq.push(GapSignal.from_dict(s))
        stats[s["priority"]] += 1

    logger.info(
        "队列写入: P0=%d P1=%d P2=%d skipped=%d",
        stats["P0"], stats["P1"], stats["P2"], stats["skipped"],
    )
    return dict(stats)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: P0 立即调度
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_p0(max_gaps: int = 10) -> int:
    """处理队列中所有 pending P0 信号，返回处理数量。"""
    try:
        from src.layer4.dispatcher import Layer4Dispatcher
        dispatcher = Layer4Dispatcher({
            "crawler": {
                "sources":    ["csdn", "github"],
                "max_pages":  2,
                "min_quality": 0.3,
                "max_docs_per_gap": 5,
            },
            "p0_immediate": True,
        })
        count = dispatcher.handle_p0(limit=max_gaps)
        logger.info("P0 调度完成: 处理 %d 个缺口", count)
        return count
    except Exception as e:
        logger.warning("P0 调度跳过（可能无爬虫配置或网络不可达）: %s", e)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: 冲突检测
# ─────────────────────────────────────────────────────────────────────────────

def _run_conflict_detection() -> Dict[str, Any]:
    """
    对 KLM 注册表中所有 PROCEDURAL_NEG 经验执行冲突检测。
    使用 LocalKLMBackend 从 JSONL 文件加载数据（与 src/layer4/conflict.py 接口一致）。
    返回冲突检测统计摘要。
    """
    klm_file = LAYER3_DIR / "phase5_klm_registry.jsonl"
    if not klm_file.exists():
        logger.warning("KLM 注册表不存在，跳过冲突检测: %s", klm_file)
        return {"skipped": True, "reason": "klm_registry_not_found"}

    try:
        from src.layer4.conflict import ConflictDetector, LocalKLMBackend
    except Exception as e:
        logger.warning("ConflictDetector 导入失败，跳过冲突检测: %s", e)
        return {"skipped": True, "reason": str(e)}

    consolidated_file = LAYER3_DIR / "phase34_consolidated.jsonl"
    backend = LocalKLMBackend(
        klm_path=klm_file,
        consolidated_path=consolidated_file if consolidated_file.exists() else None,
    )
    # 预加载，获取 neg_exps 供计数
    backend.load()
    neg_exps = list(backend.iter_by_layer("PROCEDURAL_NEG", status="active"))

    if not neg_exps:
        logger.info("无 active PROCEDURAL_NEG 经验，跳过冲突检测")
        return {"checked": 0, "conflicts_found": 0}

    logger.info("冲突检测: 对 %d 条 PROCEDURAL_NEG 经验检测...", len(neg_exps))

    try:
        detector   = ConflictDetector(backend=backend)
        detector._loaded = True  # 已预加载，避免重复读盘
        conflicts  = 0
        report_path = LAYER3_DIR / "conflict_report.jsonl"
        LAYER3_DIR.mkdir(parents=True, exist_ok=True)

        with report_path.open("w", encoding="utf-8") as rf:
            for neg_exp in neg_exps:
                result = detector.process_neg_exp(neg_exp)
                if result:
                    conflicts += result if isinstance(result, int) else len(result)

        summary = {
            "checked":        len(neg_exps),
            "conflicts_found": conflicts,
            "report":         str(report_path),
            "generated_at":   datetime.now(tz=timezone.utc).isoformat(),
        }
        summary_path = LAYER3_DIR / "conflict_summary.json"
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        logger.info("冲突检测完成: 发现 %d 处冲突", conflicts)
        return summary

    except Exception as e:
        logger.error("冲突检测异常: %s", e, exc_info=True)
        return {"skipped": True, "reason": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# 摘要输出
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(
    n_sessions: int,
    signals: List[Dict],
    queue_stats: Dict,
    p0_dispatched: int,
    conflict_result: Dict,
) -> None:
    pri_count = Counter(s["priority"] for s in signals)
    dim_count = Counter(s["root_cause_dim"] for s in signals)

    print(f"\n{'='*60}")
    print(f"  Layer 4  缺口感知 + 冲突检测  执行完毕")
    print(f"  扫描会话数           : {n_sessions}")
    print(f"  提取缺口信号数       : {len(signals)}")
    print(f"  ├── P0 (立即)        : {pri_count.get('P0', 0)}")
    print(f"  ├── P1 (每日)        : {pri_count.get('P1', 0)}")
    print(f"  └── P2 (每周)        : {pri_count.get('P2', 0)}")
    print(f"  失败维度分布         : {dict(dim_count)}")
    print(f"  P0 立即调度          : {p0_dispatched} 个已触发爬取")
    if conflict_result.get("skipped"):
        print(f"  冲突检测             : 跳过 ({conflict_result.get('reason', '')})")
    else:
        print(f"  冲突检测             : 检查 {conflict_result.get('checked', 0)} 条，"
              f"发现 {conflict_result.get('conflicts_found', 0)} 处冲突")
    print(f"  输出目录             : {OUTPUT_DIR}")
    print(f"{'='*60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Layer 4 缺口感知 + 冲突检测"
    )
    ap.add_argument("--no-crawl",    action="store_true", help="跳过 P0 立即爬取")
    ap.add_argument("--no-conflict", action="store_true", help="跳过冲突检测")
    ap.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    args = ap.parse_args()

    _setup_logging(args.verbose)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── 读取 Layer 1 输出 ─────────────────────────────────────────────────────
    layer1_files = sorted(LAYER1_DIR.glob("layer1_*.jsonl"))
    if not layer1_files:
        logger.warning("Layer 1 输出目录无 layer1_*.jsonl 文件: %s  —— 跳过 Gap 提取", LAYER1_DIR)
        # 写出空摘要，让流水线可以继续
        summary: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sessions_processed": 0,
            "signals_extracted": 0,
            "signals_pushed": 0,
            "p0_dispatched": 0,
            "conflict": {},
            "note": "Layer 1 尚未生成 JSONL 输出，跳过 Gap 感知",
        }
        out_path = OUTPUT_DIR / "gap_dispatch_summary.json"
        out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("已写出空摘要: %s", out_path)
        return 0

    logger.info("Layer 4 启动  会话数=%d", len(layer1_files))

    # ── Step 1: 提取缺口信号 ──────────────────────────────────────────────────
    signals    = _extract_gap_signals(layer1_files)
    queue_stats = _push_signals_to_queue(signals)

    # ── Step 2: P0 立即调度 ───────────────────────────────────────────────────
    p0_dispatched = 0
    if not args.no_crawl:
        p0_dispatched = _dispatch_p0()
    else:
        logger.info("--no-crawl: 跳过 P0 爬取")

    # ── Step 3: 冲突检测 ──────────────────────────────────────────────────────
    conflict_result: Dict[str, Any] = {}
    if not args.no_conflict:
        conflict_result = _run_conflict_detection()
    else:
        logger.info("--no-conflict: 跳过冲突检测")
        conflict_result = {"skipped": True, "reason": "--no-conflict flag"}

    # ── 保存摘要 ─────────────────────────────────────────────────────────────
    pri_count = Counter(s["priority"] for s in signals)
    dim_count = Counter(s["root_cause_dim"] for s in signals)
    run_summary = {
        "generated_at":    datetime.now(tz=timezone.utc).isoformat(),
        "sessions_scanned": len(layer1_files),
        "signals_extracted": len(signals),
        "by_priority":     dict(pri_count),
        "by_dimension":    dict(dim_count),
        "queue_write":     queue_stats,
        "p0_dispatched":   p0_dispatched,
        "conflict":        conflict_result,
    }
    summary_path = OUTPUT_DIR / "gap_dispatch_summary.json"
    summary_path.write_text(
        json.dumps(run_summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    _print_summary(len(layer1_files), signals, queue_stats, p0_dispatched, conflict_result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
