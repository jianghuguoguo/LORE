# src/layer4/dispatcher.py
"""
Layer 4 调度器 — 消费缺口队列，驱动 CrawlWorker。

P0 立即触发：session 处理完成后同步调用 handle_p0()
P1 每日批量：APScheduler  cron  每天 02:00
P2 每周更新：APScheduler  cron  每周一 03:00

使用单例模式，Layer 1 通过 get_dispatcher_instance() 获取共享实例。
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from .gap_queue import GapQueue
from .models import GapPriority
from .crawler import CrawlWorker

if TYPE_CHECKING:
    from .crawler import CrawlResult

logger = logging.getLogger(__name__)

# ── 全局单例 ─────────────────────────────────────────────────────────────────
_instance: Optional["Layer4Dispatcher"] = None
_instance_lock = threading.Lock()


def get_dispatcher_instance(config: Optional[dict] = None) -> "Layer4Dispatcher":
    """
    获取 Layer4Dispatcher 单例。
    首次调用时必须传入 config，后续调用无需传参。
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = Layer4Dispatcher(config or {})
    return _instance


class Layer4Dispatcher:
    """
    Layer 4 总调度器。

    config 字段（均有合理默认值）：
      crawler.sources       : list[str]  爬取数据源，默认 DEFAULT_SOURCES
      crawler.max_pages     : int        每关键词最大页数，默认 3
      crawler.min_quality   : float      质量阈值，默认 0.3
      crawler.max_docs_per_gap: int      每缺口最多入库多少篇，默认 5（暂只记日志）
      p0_immediate          : bool       P0 是否在同进程立即触发，默认 True
      schedule.daily_hour   : int        P1 执行小时（0-23），默认 2
      schedule.weekly_day   : str        P2 执行星期（'mon'~'sun'），默认 'mon'
      schedule.weekly_hour  : int        P2 执行小时，默认 3
    """

    def __init__(self, config: dict):
        self.config   = config
        self.queue    = GapQueue()

        # CrawlWorker 配置
        crawler_cfg = config.get("crawler", {})
        self.worker = CrawlWorker(
            sources    = crawler_cfg.get("sources"),
            max_pages  = crawler_cfg.get("max_pages", 3),
            min_quality= crawler_cfg.get("min_quality", 0.3),
        )
        self._max_docs_per_gap = crawler_cfg.get("max_docs_per_gap", 5)

        logger.info("Layer4Dispatcher 初始化完成，数据源=%s", self.worker.sources)

    # ── P0：立即触发 ─────────────────────────────────────────────────────────

    def handle_p0(self, limit: int = 5) -> int:
        """
        处理所有 pending 的 P0 缺口（立即执行，同步）。
        返回实际处理的缺口数量。
        """
        signals = self.queue.pop_by_priority(GapPriority.P0, limit=limit)
        if not signals:
            return 0

        logger.info("P0 Dispatcher: 处理 %d 个高优先缺口", len(signals))
        processed = 0
        for signal in signals:
            try:
                results = self.worker.process(signal)
                self.queue.mark_done(signal.gap_id, success=True)
                processed += 1
                logger.info(
                    "P0 完成: gap=%s  爬取 %d 篇有效结果",
                    signal.gap_id[:8], len(results),
                )
            except Exception as exc:
                logger.error("P0 处理失败 gap=%s: %s", signal.gap_id[:8], exc, exc_info=True)
                self.queue.mark_done(signal.gap_id, success=False)

        return processed

    # ── P1：每日批量任务 ─────────────────────────────────────────────────────

    def run_daily_job(self) -> None:
        """APScheduler daily job：处理 P1 缺口 + conflict_queue。"""
        ts = datetime.now(tz=timezone.utc).isoformat()
        logger.info("P1 Daily job 开始: %s", ts)

        signals = self.queue.pop_by_priority(GapPriority.P1, limit=20)
        for signal in signals:
            try:
                results = self.worker.process(signal)
                self.queue.mark_done(signal.gap_id, success=True)
                logger.info(
                    "P1 完成: gap=%s  爬取 %d 篇有效结果",
                    signal.gap_id[:8], len(results),
                )
            except Exception as exc:
                logger.error("P1 处理失败 gap=%s: %s", signal.gap_id[:8], exc, exc_info=True)
                self.queue.mark_done(signal.gap_id, success=False)

        # 处理冲突队列（仅记日志，待 conflict.py 完成后扩展）
        self._drain_conflict_queue()

        logger.info("P1 Daily job 结束，处理了 %d 个 P1 缺口", len(signals))

    # ── P2：每周更新任务 ─────────────────────────────────────────────────────

    def run_weekly_job(self) -> None:
        """APScheduler weekly job：P2 常规更新。"""
        logger.info("P2 Weekly job 开始")

        signals = self.queue.pop_by_priority(GapPriority.P2, limit=50)
        for signal in signals:
            try:
                results = self.worker.process(signal)
                self.queue.mark_done(signal.gap_id, success=True)
            except Exception as exc:
                logger.error("P2 处理失败 gap=%s: %s", signal.gap_id[:8], exc, exc_info=True)
                self.queue.mark_done(signal.gap_id, success=False)

        logger.info("P2 Weekly job 结束，处理了 %d 个 P2 缺口", len(signals))

    # ── 辅助 ─────────────────────────────────────────────────────────────────

    def _drain_conflict_queue(self, batch_limit: int = 10) -> None:
        """
        消费 conflict_queue.jsonl 中 pending 状态的冲突请求。

        每次批量处理 batch_limit 条（避免 daily job 超时）。
        处理完成后将请求状态更新为 'done'，冲突条目写回 KLM registry。
        """
        import json
        from pathlib import Path
        from .gap_queue import QUEUE_DIR
        from .conflict import ConflictDetector, LocalKLMBackend, _LAYER3_DIR

        conflict_file = QUEUE_DIR / "conflict_queue.jsonl"
        if not conflict_file.exists():
            return

        # ── 读取全部请求 ──────────────────────────────────────────────────
        rows: list = []
        pending: list = []
        try:
            with open(conflict_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                        rows.append(req)
                        if req.get("status", "pending") == "pending":
                            pending.append(req)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.warning("读取 conflict_queue 失败: %s", exc)
            return

        if not pending:
            return

        logger.info("conflict_queue: %d 条 pending，本批处理前 %d 条", len(pending), batch_limit)

        # ── 初始化 ConflictDetector ──────────────────────────────────────
        klm_path = _LAYER3_DIR / "phase5_klm_registry.jsonl"
        consolidated_path = _LAYER3_DIR / "phase34_consolidated.jsonl"

        try:
            backend  = LocalKLMBackend(klm_path=klm_path, consolidated_path=consolidated_path)
            detector = ConflictDetector(backend=backend, dry_run=False)
            detector.load()
        except Exception as exc:
            logger.error("ConflictDetector 初始化失败: %s", exc, exc_info=True)
            return

        # ── 逐条处理 pending 请求 ─────────────────────────────────────────
        updated_ids: set = set()
        for req in pending[:batch_limit]:
            req_id = req.get("request_id", "?")
            exp_id = req.get("exp_id", "")
            if not exp_id:
                req["status"] = "skip"
                req["skip_reason"] = "missing exp_id"
                updated_ids.add(req_id)
                continue

            # 在 KLM 中查找对应 PROCEDURAL_NEG 经验
            exp = None
            for e in backend.iter_by_layer("PROCEDURAL_NEG"):
                if e.get("exp_id") == exp_id:
                    exp = e
                    break

            if exp is None:
                logger.warning("conflict_queue req=%s 引用的 exp_id 不存在: %s", req_id[:8], exp_id)
                req["status"] = "skip"
                req["skip_reason"] = "exp_id not found in KLM"
                updated_ids.add(req_id)
                continue

            try:
                tagged = detector.process_neg_exp(exp)
                req["status"] = "done"
                req["tagged_count"] = tagged
                req["processed_at"] = __import__("datetime").datetime.now(
                    tz=__import__("datetime").timezone.utc
                ).isoformat()
                updated_ids.add(req_id)
                logger.info(
                    "conflict_queue req=%s 处理完成: exp=%s  标记 %d 条冲突",
                    req_id[:8], exp_id[:12], tagged,
                )
            except Exception as exc:
                logger.error("冲突检测失败 req=%s: %s", req_id[:8], exc, exc_info=True)

        # ── 写回磁盘 ─────────────────────────────────────────────────────
        if updated_ids:
            tmp_path = conflict_file.with_suffix(".jsonl.tmp")
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    for row in rows:
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
                tmp_path.replace(conflict_file)
                logger.info("conflict_queue 已更新（%d 条标记为 done/skip）", len(updated_ids))
            except Exception as exc:
                logger.error("conflict_queue 回写失败: %s", exc)
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)

            # KLM 变更写回
            try:
                detector.commit()
            except Exception as exc:
                logger.error("KLM 写回失败: %s", exc, exc_info=True)

    def queue_stats(self) -> dict:
        """返回当前队列统计（供 dashboard 或 CLI 展示）。"""
        return self.queue.stats()

# ─────────────────────────────────────────────────────────────────────────────
# 模块级便捷函数（供 maintenance.py 调用）
# ─────────────────────────────────────────────────────────────────────────────

def run_daily_job(dry_run: bool = False) -> int:
    """
    模块级 daily job 入口，供 maintenance.py Task4 调用。

    尝试获取已存在的 Dispatcher 单例；若无则创建临时实例（空配置）。
    Returns: 处理的 P1 缺口数量。
    """
    global _instance
    dispatcher = _instance
    if dispatcher is None:
        try:
            dispatcher = Layer4Dispatcher(config={})
        except Exception as exc:
            logger.warning("run_daily_job: 无法创建 Dispatcher: %s", exc)
            return 0

    signals_before = len(dispatcher.queue.pop_by_priority.__doc__ or "")  # 不实际弹出
    try:
        if dry_run:
            stats = dispatcher.queue_stats()
            p1_count = stats.get("P1", {}).get("pending", 0) if isinstance(stats.get("P1"), dict) else 0
            logger.info("run_daily_job [dry-run]: P1 队列中有 %d 条待处理", p1_count)
            return p1_count
        else:
            dispatcher.run_daily_job()
            return 0
    except Exception as exc:
        logger.error("run_daily_job 失败: %s", exc, exc_info=True)
        return 0