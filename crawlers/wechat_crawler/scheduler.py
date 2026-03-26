"""
scheduler.py — 微信爬虫调度器（APScheduler + SQLite）
=======================================================
替代原 Celery + Redis 方案，实现零外来服务依赖：

  Redis pub/sub   →  threading.Queue（进程内冷却信号）
  Redis Hash      →  SQLite（断点状态持久化）
  Celery Beat     →  APScheduler BackgroundScheduler
  Celery Worker   →  ThreadPoolExecutor（并发爬取）

启动方式（不需要任何 celery worker 命令）：
    python scheduler.py

依赖（均为纯 Python，无外部服务）：
    pip install apscheduler
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, List, Optional

# ── APScheduler（可选，无则仅支持手动触发）────────────────────────────────
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _SCHED_AVAILABLE = True
except ImportError:
    _SCHED_AVAILABLE = False

log = logging.getLogger(__name__)

# ── sys.path：LORE/ → crawlers.wechat_crawler.*；wechat_crawler/ → discovery.* ──
import sys as _sys
_WC   = Path(__file__).parent                        # crawlers/wechat_crawler/
_REFR = _WC.parent.parent                            # LORE/
for _p in (str(_REFR), str(_WC)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
_ROOT  = Path(__file__).parent                       # crawlers/wechat_crawler/
_REFROOT = _ROOT.parent.parent                       # LORE/
_DB    = _REFROOT / 'data' / 'crawl_state.db'
# interceptor.py 写入此文件通知冷却，scheduler 读取后清除（同目录）
_COOLDOWN_FLAG = _ROOT / 'cooldown.flag'

# ── 进程内冷却信号队列（ui_bot 的 progress_callback 中检测）─────────────────
_cooldown_q: queue.Queue = queue.Queue()


# ─────────────────────────────────────────────────────────────────────────────
# SQLite 断点状态存储（替代 Redis Hash）
# ─────────────────────────────────────────────────────────────────────────────

class CrawlStateDB:
    """
    用 SQLite 持久化每个账号的爬取断点 offset。
    线程安全（check_same_thread=False + 显式锁）。
    """

    def __init__(self, db_path: Path = _DB) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS crawl_state (
                account_id TEXT PRIMARY KEY,
                offset     INTEGER DEFAULT 0,
                updated_at TEXT
            )
        """)
        self._conn.commit()
        log.debug(f'CrawlStateDB 初始化: {db_path}')

    def get_offset(self, account_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT offset FROM crawl_state WHERE account_id=?",
                (account_id,),
            ).fetchone()
        return row[0] if row else 0

    def set_offset(self, account_id: str, offset: int) -> None:
        with self._lock:
            self._conn.execute("""
                INSERT INTO crawl_state(account_id, offset, updated_at)
                VALUES(?, ?, datetime('now'))
                ON CONFLICT(account_id) DO UPDATE
                    SET offset=excluded.offset,
                        updated_at=excluded.updated_at
            """, (account_id, offset))
            self._conn.commit()

    def clear(self, account_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM crawl_state WHERE account_id=?",
                (account_id,),
            )
            self._conn.commit()

    def all_pending(self) -> list[tuple[str, int]]:
        """返回所有未完成的 (account_id, offset) 列表。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT account_id, offset FROM crawl_state WHERE offset > 0"
            ).fetchall()
        return rows  # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────────────────
# 冷却信号检测（替代 Redis pub/sub）
# ─────────────────────────────────────────────────────────────────────────────

def _check_cooldown_flag() -> bool:
    """
    检测 interceptor.py 写入的冷却标志文件。
    文件存在且写入时间在 60 秒内 → 触发冷却。
    """
    if not _COOLDOWN_FLAG.exists():
        return False
    try:
        age = time.time() - _COOLDOWN_FLAG.stat().st_mtime
        return age < 60  # 60 秒内写入的 flag 认为是有效冷却信号
    except OSError:
        return False


def _consume_cooldown_flag(cooldown_sec: int = 300) -> None:
    """检测到冷却信号后，删除 flag 并休眠。"""
    try:
        _COOLDOWN_FLAG.unlink(missing_ok=True)
    except OSError:
        pass
    log.warning(f'[Cooldown] 检测到风控冷却信号，暂停 {cooldown_sec}s ...')
    time.sleep(cooldown_sec)


# ─────────────────────────────────────────────────────────────────────────────
# 活跃时间窗检测
# ─────────────────────────────────────────────────────────────────────────────

def _is_active_hour(start: int = 8, end: int = 23) -> bool:
    return start <= int(time.strftime('%H')) < end


def _wait_for_active_window(start: int = 8, end: int = 23, timeout: int = 3600) -> bool:
    deadline = time.time() + timeout
    while not _is_active_hour(start, end):
        if time.time() > deadline:
            return False
        log.info('[Scheduler] 不在活跃时间窗口，等待 60s ...')
        time.sleep(60)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# 主调度器
# ─────────────────────────────────────────────────────────────────────────────

class PentestCrawlerScheduler:
    """
    微信爬虫主调度器（APScheduler + SQLite）。

    替代关系
    --------
    Celery Worker   → ThreadPoolExecutor
    Celery Beat     → APScheduler BackgroundScheduler
    Redis Hash      → CrawlStateDB (SQLite)
    Redis pub/sub   → cooldown.flag 文件 + threading.Queue
    """

    def __init__(
        self,
        max_workers: int = 2,
        db_path:     Path = _DB,
    ) -> None:
        self.db     = CrawlStateDB(db_path)
        self._pool  = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='wechat')
        self._sched = None

        if _SCHED_AVAILABLE:
            self._sched = BackgroundScheduler(timezone='Asia/Shanghai')
            self._register_jobs()
            log.info('[Scheduler] APScheduler 已配置')
        else:
            log.warning(
                '[Scheduler] apscheduler 未安装，定时任务不可用。'
                '请运行: pip install apscheduler'
            )

    # ── 定时任务注册（替代 celeryconfig.py beat_schedule）────────────────────

    def _register_jobs(self) -> None:
        assert self._sched is not None
        # 每日 02:00 — 完整三通道发现
        self._sched.add_job(
            self.run_full_discovery,
            trigger='cron', hour=2,
            id='daily_discovery', replace_existing=True,
        )
        # 每周日 03:00 — GitHub 社区同步
        self._sched.add_job(
            self._run_community_sync,
            trigger='cron', day_of_week='sun', hour=3,
            id='weekly_community', replace_existing=True,
        )

    # ── 单账号爬取（含断点续爬 + 冷却检测）─────────────────────────────────

    def crawl_account(
        self,
        account_id:   str,
        account_name: str,
        target_count: int = 30,
        force:        bool = False,
    ) -> dict:
        """
        爬取指定公众号，支持断点续爬。

        断点机制：每成功点击一篇，offset 写入 SQLite；
        下次调用自动从上次位置继续；完整完成后清除记录。
        """
        from crawlers.wechat_crawler.config import MITM_CONFIG
        from crawlers.wechat_crawler.ui_bot import WeChatUIBot

        active_start, active_end = MITM_CONFIG.get('ACTIVE_HOURS', (8, 23))
        cooldown_sec = MITM_CONFIG.get('RATE_LIMIT', {}).get('COOLDOWN_SECONDS', 300)

        # 时间窗口检查：仅 daemon 定时任务执行时生效；手动 crawl 调用直接跳过
        if not force and not _is_active_hour(active_start, active_end):
            log.warning(f'[{account_name}] 不在活跃时间窗口（{active_start}:00-{active_end}:00），跳过。使用 --force 可强制执行')
            return {'account_id': account_id, 'crawled': 0, 'skipped': 0, 'reason': 'inactive_hour'}

        offset = self.db.get_offset(account_id)
        if offset:
            log.info(f'[{account_name}] 断点续爬，从 offset={offset} 开始')

        articles_clicked = 0

        def on_progress(delta: int) -> None:
            nonlocal articles_clicked
            articles_clicked += delta
            # 持久化断点（替代 Redis hset）
            self.db.set_offset(account_id, offset + articles_clicked)
            # 检测冷却信号（替代 Redis pub/sub subscribe）
            if _check_cooldown_flag():
                _consume_cooldown_flag(cooldown_sec)

        bot = WeChatUIBot()
        try:
            bot.find_wechat_window()
            count = bot.browse_account(
                account_name=account_name,
                count=target_count - offset,
                offset=offset,
                progress_callback=on_progress,
            )
            # 完整完成，清除断点
            self.db.clear(account_id)
            log.info(f'[{account_name}] 完成，共点击 {count} 篇')

            # ★ per-crawl 引用提取（每次爬取完成后自动发现新来源）
            try:
                from discovery.discovery_scheduler import DiscoveryScheduler
                new_accounts = DiscoveryScheduler().run_citation_only()
                if new_accounts:
                    log.info(f'[{account_name}] 引用提取发现 {len(new_accounts)} 个新候选账号')
            except Exception as _ce:
                log.debug(f'[{account_name}] 引用提取跳过: {_ce}')

            return {
                'account_id':   account_id,
                'account_name': account_name,
                'crawled':      count,
                'skipped':      offset,
            }
        except Exception as exc:
            log.error(f'[{account_name}] 爬取异常（进度已保存，下次自动续爬）: {exc}', exc_info=True)
            return {
                'account_id':   account_id,
                'account_name': account_name,
                'crawled':      articles_clicked,
                'skipped':      offset,
                'error':        str(exc),
            }

    # ── 订阅号流爬取（不指定账号）────────────────────────────────────────────

    def crawl_feed(self, count: int = 50) -> dict:
        """浏览订阅号消息流，适用于 TARGET_ACCOUNTS 为空的场景。"""
        from crawlers.wechat_crawler.ui_bot import WeChatUIBot
        from crawlers.wechat_crawler.config import MITM_CONFIG

        cooldown_sec = MITM_CONFIG.get('RATE_LIMIT', {}).get('COOLDOWN_SECONDS', 300)
        articles_clicked = 0

        def on_progress(delta: int) -> None:
            nonlocal articles_clicked
            articles_clicked += delta
            if _check_cooldown_flag():
                _consume_cooldown_flag(cooldown_sec)

        bot = WeChatUIBot()
        try:
            bot.find_wechat_window()
            n = bot.browse_subscription_feed(count=count, progress_callback=on_progress)
            return {'crawled': n}
        except Exception as exc:
            log.error(f'[Feed] 爬取异常: {exc}', exc_info=True)
            return {'crawled': articles_clicked, 'error': str(exc)}

    # ── 批量并发爬取 ──────────────────────────────────────────────────────────

    def batch_crawl(
        self,
        accounts:     List[dict],
        target_count: int = 30,
        force:        bool = False,
    ) -> List[dict]:
        """
        并发爬取多个账号。

        Parameters
        ----------
        accounts : [{'id': str, 'name': str}, ...]
        force    : 跳过活跃时间窗口限制
        """
        futures = {
            self._pool.submit(
                self.crawl_account,
                a['id'], a['name'], target_count, force,
            ): a
            for a in accounts
        }
        results = []
        for fut in as_completed(futures):
            acct = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                log.error(f"[BatchCrawl] {acct['name']} 异常: {exc}")
                results.append({'account_id': acct['id'], 'error': str(exc)})
        return results

    # ── 账号发现 ──────────────────────────────────────────────────────────────

    def run_full_discovery(
        self,
        keywords: Optional[List[str]] = None,
    ) -> None:
        """执行完整三通道账号发现（替代 Celery full_discovery_task）。"""
        try:
            from discovery.discovery_scheduler import DiscoveryScheduler
            DiscoveryScheduler().run_full_discovery(keywords)
        except Exception as e:
            log.error(f'[Discovery] 完整发现流程失败: {e}', exc_info=True)

    def _run_community_sync(self) -> None:
        """执行 GitHub 社区同步（替代 Celery community_sync_task）。"""
        try:
            from discovery.community_sync import CommunityCrossValidator
            CommunityCrossValidator().sync_from_github()
        except Exception as e:
            log.error(f'[Community] 同步失败: {e}', exc_info=True)

    # ── 生命周期 ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        """启动后台定时调度（非阻塞）。"""
        if self._sched:
            self._sched.start()
            log.info('[Scheduler] 定时调度已启动')
            for job in self._sched.get_jobs():
                log.info(f'  • {job.id}: {job.next_run_time}')

    def stop(self) -> None:
        if self._sched and self._sched.running:
            self._sched.shutdown(wait=False)
        self._pool.shutdown(wait=False)
        log.info('[Scheduler] 已停止')

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 命令行入口
# ─────────────────────────────────────────────────────────────────────────────

def _load_seed_accounts() -> List[dict]:
    """从 seed_accounts.yaml 加载所有有效账号列表。"""
    seed_file = _ROOT / 'seed_accounts.yaml'
    if not seed_file.exists():
        return []
    try:
        import yaml
        with seed_file.open(encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        accounts = []
        for cat, items in (data.get('categories') or {}).items():
            for item in (items or []):
                if isinstance(item, dict) and item.get('name'):
                    accounts.append({
                        'id':   item.get('biz') or item['name'],
                        'name': item['name'],
                    })
                elif isinstance(item, str):
                    accounts.append({'id': item, 'name': item})
        return accounts
    except Exception as e:
        log.warning(f'加载 seed_accounts.yaml 失败: {e}')
        return []


if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s %(name)s — %(message)s',
        datefmt='%H:%M:%S',
    )

    parser = argparse.ArgumentParser(description='LORE 微信爬虫调度器')
    sub = parser.add_subparsers(dest='cmd')

    # crawl 子命令
    p_crawl = sub.add_parser('crawl', help='立即执行批量爬取')
    p_crawl.add_argument('--accounts', nargs='+', help='账号名称列表（不传则读 seed_accounts.yaml）')
    p_crawl.add_argument('--count', type=int, default=30, help='每账号采集篇数')
    p_crawl.add_argument('--force', action='store_true', help='跳过活跃时间窗口限制，立即执行')

    # discover 子命令
    p_disc = sub.add_parser('discover', help='立即执行账号发现')
    p_disc.add_argument('--keywords', nargs='+', help='额外搜索关键词')

    # daemon 子命令（后台常驻）
    sub.add_parser('daemon', help='启动后台定时调度（APScheduler 模式）')

    args = parser.parse_args()

    scheduler = PentestCrawlerScheduler()

    if args.cmd == 'crawl':
        if args.accounts:
            accounts = [{'id': a, 'name': a} for a in args.accounts]
        else:
            accounts = _load_seed_accounts()
        if not accounts:
            print('⚠  没有找到账号，请在 seed_accounts.yaml 中配置或通过 --accounts 指定')
        else:
            print(f'开始爬取 {len(accounts)} 个账号...')
            results = scheduler.batch_crawl(accounts, target_count=args.count, force=getattr(args, 'force', False))
            for r in results:
                print(r)

    elif args.cmd == 'discover':
        scheduler.run_full_discovery(args.keywords)

    elif args.cmd == 'daemon':
        if not _SCHED_AVAILABLE:
            print('❌ 请先安装: pip install apscheduler')
        else:
            scheduler.start()
            print('✓ 定时调度已启动（Ctrl+C 停止）')
            try:
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                scheduler.stop()
                print('\n已停止')

    else:
        parser.print_help()

