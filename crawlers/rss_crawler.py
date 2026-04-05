"""
crawlers/rss_crawler.py — 通用 RSS/Atom Feed 增量爬虫
======================================================
支持 FreeBuf、安全客、绿盟科技、嘶吼、Seebug Paper 等安全社区 RSS 订阅。

特性：
  ● 增量拉取：记录每个 Feed 已见过的条目 ID，避免重复下载
  ● 全文提取：对摘要不完整的文章，按配置的 CSS 选择器提取正文
  ● 统一输出：与其他爬虫相同的 dict schema（title/link/date/summary/content/site）
  ● 状态持久化：state 文件存于 data/rss_state.json

使用方式：
  from crawlers.rss_crawler import RSSCrawler
  crawler = RSSCrawler("freebuf", "https://www.freebuf.com/feed")
  results = crawler.crawl("")          # 拉取所有新内容
  results = crawler.crawl("内网渗透")  # 拉取并按关键词过滤
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys

# Windows 控制台下避免 UnicodeEncodeError 影响同步线程。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from crawlers.base_crawler import BaseCrawler

log = logging.getLogger(__name__)

# 状态文件路径（LORE/data/rss_state.json）
_ROOT = Path(__file__).parent.parent
_STATE_FILE = _ROOT / "data" / "rss_state.json"
_OUTPUT_BASE = _ROOT / "raw_data"

# 请求超时
_TIMEOUT = 20

# 一个条目中摘要过短时，才去抓全文（减少请求量）
_SUMMARY_MIN_LEN = 200


# ── 各社区文章内容 CSS 选择器 ─────────────────────────────────────────────────

CONTENT_SELECTORS_MAP: Dict[str, List[str]] = {
    "freebuf": [
        ".article-content", ".content-detail",
        ".post-content", "article .content",
    ],
    "anquanke": [
        ".article-content", ".detail-body",
        ".post-body", "article",
    ],
    "nsfocus": [
        ".post-content", ".entry-content",
        "article .content", ".blog-content",
    ],
    "4hou": [
        ".article-detail-con", ".article-content",
        ".news-detail", ".post-content",
    ],
    "seebug": [
        ".post-content", ".markdown-body",
        ".entry-content", "article",
    ],
    "default": [
        ".article-content", ".post-content",
        ".entry-content", ".content",
        "article", "main",
    ],
}


# ── 状态管理 ──────────────────────────────────────────────────────────────────

def _load_state() -> Dict[str, Any]:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: Dict[str, Any]) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


# ── 通用 RSS 爬虫 ─────────────────────────────────────────────────────────────

class RSSCrawler(BaseCrawler):
    """
    通用 RSS/Atom Feed 增量爬虫。

    每次 crawl() 只返回上次抓取以来的新条目；
    若 query 不为空，则在新条目中按标题/摘要关键词过滤。
    """

    def __init__(
        self,
        feed_name: str,
        feed_url: str,
        content_selectors: Optional[List[str]] = None,
        session=None,
        always_fetch_content: bool = False,
    ):
        """
        Args:
            feed_name:           数据源短名称，用于日志、存储目录、状态 key
            feed_url:            RSS/Atom Feed URL
            content_selectors:   正文提取 CSS 选择器（None 则用内置映射或 default）
            always_fetch_content: True = 每篇都抓全文（慢但完整）
        """
        super().__init__(session)
        self.feed_name = feed_name
        self.feed_url = feed_url
        self.always_fetch_content = always_fetch_content
        self._selectors = (
            content_selectors
            or CONTENT_SELECTORS_MAP.get(feed_name)
            or CONTENT_SELECTORS_MAP["default"]
        )

    # ── BaseCrawler 接口 ──────────────────────────────────────────────────────

    def get_source_name(self) -> str:
        return self.feed_name

    def crawl(self, query: str = "", **kwargs) -> List[Dict[str, Any]]:
        """
        拉取 RSS Feed 中的新条目。

        Args:
            query: 关键词过滤（空字符串 = 不过滤）
            max_items: 最多返回条目数（默认 50）
            skip_state: True = 忽略状态文件，拉取全量（调试用）

        Returns:
            标准化文章列表
        """
        max_items: int = kwargs.get("max_items", 50)
        skip_state: bool = kwargs.get("skip_state", False)

        print(f"\n[RSS] {self.feed_name} — {self.feed_url}")

        # 加载状态
        state = _load_state()
        feed_state = state.get(self.feed_name, {})
        seen_ids: set[str] = set(feed_state.get("seen_ids", []))
        last_fetch: Optional[datetime] = None
        if not skip_state and feed_state.get("last_fetch"):
            try:
                last_fetch = datetime.fromisoformat(feed_state["last_fetch"])
            except ValueError:
                pass

        # 拉取 Feed
        entries = self._fetch_feed()
        if entries is None:
            return []

        print(f"  Feed 条目总数: {len(entries)}")

        # 筛选新条目（未见过 ID）
        new_entries = []
        for entry in entries:
            entry_id = entry.get("id") or entry.get("link", "")
            if not skip_state and entry_id in seen_ids:
                continue
            # 按发布时间过滤（可选优化，防止 Feed 没有 guid 的情况）
            pub = entry.get("_pub_dt")
            if last_fetch and pub and pub <= last_fetch:
                continue
            new_entries.append(entry)

        if not new_entries:
            print(f"  无新条目（已是最新）")
            return []

        print(f"  新条目: {len(new_entries)} 篇")

        # 关键词过滤
        if query:
            kw = query.lower()
            new_entries = [
                e for e in new_entries
                if kw in (e.get("title") or "").lower()
                or kw in (e.get("summary") or "").lower()
            ]
            print(f"  关键词「{query}」过滤后: {len(new_entries)} 篇")

        if not new_entries:
            return []

        # 限制数量
        new_entries = new_entries[:max_items]

        # 提取全文
        results = []
        for i, entry in enumerate(new_entries, 1):
            print(f"  [{i}/{len(new_entries)}] {entry.get('title', '无标题')[:60]}")
            article = self._process_entry(entry)
            if article:
                results.append(article)
            time.sleep(1.0)  # 礼貌延时

        # 更新状态
        now_ids = {(e.get("id") or e.get("link", "")) for e in new_entries}
        seen_ids.update(now_ids)
        # 只保留最近 2000 个 ID，防止无限增长
        if len(seen_ids) > 2000:
            seen_ids = set(list(seen_ids)[-2000:])
        state[self.feed_name] = {
            "last_fetch": datetime.now().isoformat(),
            "seen_ids": list(seen_ids),
        }
        _save_state(state)

        print(f"  [OK] {self.feed_name}: 共获取 {len(results)} 篇新文章")
        return results

    # ── 内部方法 ──────────────────────────────────────────────────────────────

    def _fetch_feed(self) -> Optional[List[Dict[str, Any]]]:
        """拉取并解析 RSS/Atom Feed，返回统一格式的条目列表。"""
        try:
            import feedparser
        except ImportError:
            print("  [ERROR] 缺少依赖: feedparser。请运行: pip install feedparser")
            return None

        try:
            # feedparser 支持直接传 URL；设置 User-Agent 避免部分站点 403
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (compatible; LORE-RSSBot/1.0; "
                    "+https://github.com/your/lore)"
                )
            }
            resp = self.safe_request(self.feed_url, timeout=_TIMEOUT, headers=headers)
            if resp is None:
                # 回退：让 feedparser 自行处理
                feed = feedparser.parse(self.feed_url)
            else:
                feed = feedparser.parse(resp.content)

            if feed.bozo and not feed.entries:
                print(f"  [WARN] Feed 解析异常: {feed.bozo_exception}")
                return None

            entries = []
            for e in feed.entries:
                pub_dt = self._parse_pub_time(e)
                entries.append({
                    "id":      getattr(e, "id", None) or getattr(e, "link", ""),
                    "title":   getattr(e, "title", ""),
                    "link":    getattr(e, "link", ""),
                    "summary": self._strip_html(
                        getattr(e, "summary", "")
                        or (e.content[0].value if hasattr(e, "content") and e.content else "")
                    ),
                    "date":    pub_dt.strftime("%Y-%m-%d %H:%M:%S") if pub_dt else "",
                    "_pub_dt": pub_dt,
                })
            return entries

        except Exception as exc:
            print(f"  [ERROR] 拉取 Feed 失败: {exc}")
            return None

    def _process_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理单篇条目：需要时抓取全文，组装标准化 dict。"""
        url = entry.get("link", "")
        summary = entry.get("summary", "")

        content = summary
        if self.always_fetch_content or len(summary) < _SUMMARY_MIN_LEN:
            full = self._extract_full_content(url)
            if full:
                content = full

        return {
            "title":        entry.get("title", ""),
            "link":         url,
            "date":         entry.get("date", ""),
            "summary":      summary[:500] if summary else "",
            "content":      content,
            "site":         self.feed_name,
            "type":         "rss",
            "scraped_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _extract_full_content(self, url: str) -> Optional[str]:
        """用 BeautifulSoup 抓取文章正文。"""
        if not url:
            return None
        try:
            resp = self.safe_request(url, timeout=_TIMEOUT)
            if not resp:
                return None
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.content, "lxml")
            # 移除干扰元素
            for tag in soup.select("script,style,nav,aside,header,footer,.ad,.comment,.sidebar"):
                tag.decompose()
            for sel in self._selectors:
                node = soup.select_one(sel)
                if node:
                    text = node.get_text(separator="\n", strip=True)
                    if len(text) >= 50:
                        return text
            # 兜底：body 全文
            body = soup.find("body")
            if body:
                return body.get_text(separator="\n", strip=True)[:5000]
        except Exception as exc:
            log.debug("全文提取失败 %s: %s", url, exc)
        return None

    @staticmethod
    def _parse_pub_time(entry) -> Optional[datetime]:
        """从 feedparser entry 解析发布时间，统一返回 naive datetime（UTC）。"""
        import time as _time
        tt = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
        if tt:
            try:
                return datetime(*tt[:6], tzinfo=timezone.utc).replace(tzinfo=None)
            except Exception:
                pass
        # 字符串回退
        for field in ("published", "updated", "created"):
            raw = getattr(entry, field, None)
            if raw:
                for fmt in (
                    "%a, %d %b %Y %H:%M:%S %z",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                ):
                    try:
                        dt = datetime.strptime(raw[:25], fmt)
                        return dt.replace(tzinfo=None)
                    except ValueError:
                        continue
        return None

    @staticmethod
    def _strip_html(text: str) -> str:
        """简单去除 HTML 标签。"""
        if not text:
            return ""
        try:
            from bs4 import BeautifulSoup
            return BeautifulSoup(text, "lxml").get_text(separator=" ", strip=True)
        except Exception:
            import re
            return re.sub(r"<[^>]+>", " ", text).strip()


# ── 便捷聚合器 ────────────────────────────────────────────────────────────────

class RSSAggregator:
    """
    管理多个 RSS Feed，一次性拉取所有新内容并保存到本地。

    示例：
        from crawlers.rss_crawler import RSSAggregator
        agg = RSSAggregator()
        agg.fetch_all()
    """

    def __init__(self, feeds: Optional[Dict[str, str]] = None):
        """
        Args:
            feeds: {feed_name: feed_url}，None 则从 config.RSS_FEEDS 读取
        """
        if feeds is None:
            from crawlers.config import RSS_FEEDS
            feeds = RSS_FEEDS
        self.crawlers: Dict[str, RSSCrawler] = {
            name: RSSCrawler(name, url)
            for name, url in feeds.items()
        }

    def fetch_all(
        self,
        query: str = "",
        save: bool = True,
        skip_state: bool = False,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        拉取所有 Feed 的新内容。

        Args:
            query:      关键词过滤（空 = 全部）
            save:       是否保存到 raw_data/{name}/
            skip_state: 忽略状态，拉取全量（调试）

        Returns:
            {feed_name: [article, ...]}
        """
        all_results: Dict[str, List[Dict[str, Any]]] = {}
        for name, crawler in self.crawlers.items():
            try:
                results = crawler.crawl(query, skip_state=skip_state)
                all_results[name] = results
                if save and results:
                    self._save(name, results)
            except Exception as exc:
                log.error("[RSSAggregator] %s 失败: %s", name, exc)
                all_results[name] = []

        total = sum(len(v) for v in all_results.values())
        print(f"\n[RSS 汇总] 本次共获取 {total} 篇新文章")
        return all_results

    @staticmethod
    def _save(feed_name: str, results: List[Dict[str, Any]]) -> None:
        """按 raw_data/{feed_name}/YYYYMMDD_HHMMSS.json 存储。"""
        out_dir = _OUTPUT_BASE / feed_name
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = out_dir / f"rss_{ts}.json"
        path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  [SAVE] {feed_name}: 已保存 {len(results)} 篇 -> {path}")


# ── 命令行入口 ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="手动触发 RSS 增量爬取")
    parser.add_argument("--feeds", "-f", default="",
                        help="逗号分隔的 feed 名称，默认全部")
    parser.add_argument("--query", "-q", default="",
                        help="关键词过滤")
    parser.add_argument("--skip-state", action="store_true",
                        help="忽略状态文件，拉取全量（调试）")
    parser.add_argument("--no-save", action="store_true",
                        help="仅打印，不保存文件")
    args = parser.parse_args()

    from crawlers.config import RSS_FEEDS

    feeds_to_use = RSS_FEEDS
    if args.feeds:
        names = {n.strip() for n in args.feeds.split(",")}
        feeds_to_use = {k: v for k, v in RSS_FEEDS.items() if k in names}
        if not feeds_to_use:
            print(f"[ERROR] 未找到指定 feed: {args.feeds}，可用: {list(RSS_FEEDS)}")
            sys.exit(1)

    agg = RSSAggregator(feeds_to_use)
    agg.fetch_all(query=args.query, save=not args.no_save, skip_state=args.skip_state)

