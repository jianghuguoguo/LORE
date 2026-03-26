# src/layer4/scheduler.py
"""
Layer 4 APScheduler 调度器。

作为模块使用：
  from src.layer4.scheduler import start_scheduler
  sched = start_scheduler(dispatcher, config)

作为独立脚本运行：
  python -m src.layer4.scheduler [--config configs/config.yaml]
  # 前台运行，Ctrl+C 退出

调度规则（默认值，可在 config.yaml layer4.schedule 下覆盖）：
  P1 daily   — 每天 02:00
  P2 weekly  — 每周一 03:00
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .dispatcher import Layer4Dispatcher

from ..utils.config_loader import get_config

logger = logging.getLogger(__name__)


def start_scheduler(
    dispatcher: "Layer4Dispatcher",
    config: Optional[dict] = None,
) -> "BackgroundScheduler":
    """
    启动后台 APScheduler（BackgroundScheduler — 不阻塞主线程）。
    返回 scheduler 实例，调用者可以在需要时调用 scheduler.shutdown()。
    """
    from apscheduler.schedulers.background import BackgroundScheduler

    sched_cfg = (config or {}).get("schedule", {})
    daily_hour  = int(sched_cfg.get("daily_hour", 2))
    weekly_day  = sched_cfg.get("weekly_day", "mon")
    weekly_hour = int(sched_cfg.get("weekly_hour", 3))

    scheduler = BackgroundScheduler(
        job_defaults={"max_instances": 1, "coalesce": True}
    )

    # P1：每日批量
    scheduler.add_job(
        dispatcher.run_daily_job,
        trigger="cron",
        hour=daily_hour,
        minute=0,
        id="layer4_p1_daily",
        replace_existing=True,
    )
    # P2：每周更新
    scheduler.add_job(
        dispatcher.run_weekly_job,
        trigger="cron",
        day_of_week=weekly_day,
        hour=weekly_hour,
        minute=0,
        id="layer4_p2_weekly",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        "Layer4 APScheduler 已启动  P1=每天%02d:00  P2=每周%s %02d:00",
        daily_hour, weekly_day, weekly_hour,
    )
    return scheduler


# ── 作为独立脚本运行 ──────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 确保 LORE/ 在 sys.path
    _root = Path(__file__).parent.parent.parent
    for _p in [str(_root), str(_root / "crawlers")]:
        if _p not in sys.path:
            sys.path.insert(0, _p)

    parser = argparse.ArgumentParser(description="Layer 4 定时调度器")
    parser.add_argument(
        "--config",
        default=str(_root / "configs" / "config.yaml"),
        help="用户配置路径（默认 configs/config.yaml；设计参数自动从 configs/design.yaml 合并）",
    )
    parser.add_argument(
        "--run-now",
        choices=["p0", "p1", "p2"],
        help="立即运行一次指定任务后退出",
    )
    args = parser.parse_args()

    try:
        layer4_cfg = get_config(Path(args.config)).layer4_config
    except Exception as exc:
        logger.warning("配置文件加载失败，使用默认值: %s", exc)
        layer4_cfg = {}

    from .dispatcher import Layer4Dispatcher
    dispatcher = Layer4Dispatcher(layer4_cfg)

    if args.run_now:
        logger.info("手动触发 %s 任务...", args.run_now.upper())
        if args.run_now == "p0":
            dispatcher.handle_p0()
        elif args.run_now == "p1":
            dispatcher.run_daily_job()
        elif args.run_now == "p2":
            dispatcher.run_weekly_job()
        logger.info("任务完成，退出")
        return

    # 后台调度，前台阻塞
    scheduler = start_scheduler(dispatcher, layer4_cfg)
    logger.info("Layer4 调度器运行中，Ctrl+C 退出")
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Layer4 调度器停止")
        scheduler.shutdown()


if __name__ == "__main__":
    main()

