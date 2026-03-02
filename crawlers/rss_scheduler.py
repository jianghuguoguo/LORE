"""
crawlers/rss_scheduler.py — RSS Feed 定时调度器
================================================
使用 APScheduler 定期拉取所有已配置 RSS Feed 的新内容。

特性：
  ● 基于 APScheduler BlockingScheduler，无需额外服务
  ● 默认每 2 小时执行一次（可通过参数或环境变量覆盖）
  ● 首次启动立即执行一次，之后按间隔周期触发
  ● 单任务互斥：若上一轮未完成，跳过本轮（避免堆积）
  ● 异常不中断下一次调度

启动方式：
  python crawlers/rss_scheduler.py              # 使用默认间隔（2h）
  python crawlers/rss_scheduler.py --interval 4 # 每 4 小时一次
  python crawlers/rss_scheduler.py --once       # 立即执行一次后退出

停止：Ctrl+C
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from datetime import datetime
from pathlib import Path

# 确保项目根目录在 sys.path
_HERE = Path(__file__).parent        # crawlers/
_ROOT = _HERE.parent                 # RefPenTest/
for _p in (str(_ROOT), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

log = logging.getLogger(__name__)

# 全局锁：防止并发重入
_job_lock = threading.Lock()


# ── 核心任务 ──────────────────────────────────────────────────────────────────

def run_rss_sync(query: str = "") -> None:
    """
    执行一次 RSS 全量增量同步。
    该函数由调度器周期性调用，也可直接调用。
    """
    if not _job_lock.acquire(blocking=False):
        log.warning("[RSS调度] 上一轮任务仍在运行，跳过本次触发")
        return

    try:
        log.info("=" * 60)
        log.info("[RSS调度] 开始同步 — %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        log.info("=" * 60)

        from crawlers.rss_crawler import RSSAggregator
        agg = RSSAggregator()
        results = agg.fetch_all(query=query, save=True)

        total = sum(len(v) for v in results.values())
        log.info("[RSS调度] 同步完成，共 %d 篇新文章", total)

    except Exception as exc:
        log.exception("[RSS调度] 同步异常: %s", exc)
    finally:
        _job_lock.release()


# ── 调度器入口 ────────────────────────────────────────────────────────────────

def start_scheduler(interval_hours: float = 2.0, query: str = "") -> None:
    """
    启动 APScheduler 定时调度器（阻塞运行，Ctrl+C 退出）。

    Args:
        interval_hours: 轮询间隔（小时），支持小数（如 0.5 = 30 分钟）
        query:          关键词过滤，空字符串 = 全部
    """
    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
        from apscheduler.triggers.interval import IntervalTrigger
    except ImportError:
        log.error("缺少 apscheduler，请运行: pip install apscheduler>=3.10")
        sys.exit(1)

    scheduler = BlockingScheduler(timezone="Asia/Shanghai")

    # 立即执行第一次
    log.info("[RSS调度] 首次同步开始...")
    run_rss_sync(query=query)

    # 按间隔周期触发
    scheduler.add_job(
        func=run_rss_sync,
        trigger=IntervalTrigger(hours=interval_hours),
        kwargs={"query": query},
        id="rss_sync",
        name="RSS增量同步",
        max_instances=1,          # 同一时间只允许一个实例运行
        coalesce=True,            # 若错过多次，只补执行一次
        misfire_grace_time=600,   # 10 分钟内的 misfire 仍会补跑
    )

    log.info(
        "[RSS调度] 调度器已启动，每 %.1f 小时同步一次。按 Ctrl+C 停止。",
        interval_hours,
    )

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("[RSS调度] 调度器已停止")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="RSS Feed 定时调度器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python crawlers/rss_scheduler.py                 # 每 2 小时同步
  python crawlers/rss_scheduler.py --interval 4    # 每 4 小时同步
  python crawlers/rss_scheduler.py --interval 0.5  # 每 30 分钟同步
  python crawlers/rss_scheduler.py --once          # 立即执行一次后退出
  python crawlers/rss_scheduler.py --query 内网渗透  # 只保存包含关键词的文章
        """,
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=2.0,
        help="轮询间隔（小时，默认 2）",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="立即执行一次后退出（不启动调度循环）",
    )
    parser.add_argument(
        "--query", "-q",
        default="",
        help="关键词过滤（空 = 全部）",
    )
    parser.add_argument(
        "--feeds", "-f",
        default="",
        help="逗号分隔的 feed 名称，默认全部",
    )
    args = parser.parse_args()

    # 若指定了特定 feed，临时替换 RSSAggregator 的 feeds
    if args.feeds:
        from crawlers.config import RSS_FEEDS
        names = {n.strip() for n in args.feeds.split(",")}
        filtered = {k: v for k, v in RSS_FEEDS.items() if k in names}
        if not filtered:
            log.error("未找到指定 feed: %s，可用: %s", args.feeds, list(RSS_FEEDS))
            sys.exit(1)
        # monkey-patch: 让 run_rss_sync 使用过滤后的 feeds
        import crawlers.config as _cfg
        _cfg.RSS_FEEDS = filtered

    if args.once:
        run_rss_sync(query=args.query)
    else:
        start_scheduler(interval_hours=args.interval, query=args.query)


if __name__ == "__main__":
    main()
