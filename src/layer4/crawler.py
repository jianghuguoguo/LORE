# src/layer4/crawler.py
"""
CrawlWorker — 外部知识获取模块。

职责：
  1. 将 GapSignal.search_queries 作为关键词
  2. 调用项目现有的 CrawlerManager（main_crawler 同款接口）爬取四大网站数据源
     （csdn · github · xianzhi · qianxin）
  3. 每条关键词最多取 max_pages 页，结果保存到 raw_data/<source>/layer4_<timestamp>/ 目录
  4. 返回实际爬取的文章数量（CrawlResult 列表）

"外部知识获取就是调用 main_crawler，输入爬取关键词即可"
"""
from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .models import GapSignal, CrawlResult

logger = logging.getLogger(__name__)

# ── 确保 crawlers/ 在 sys.path ────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent.parent          # RefPenTest/
for _p in [str(_ROOT), str(_ROOT / "crawlers")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# 默认爬取的数据源（与 main_crawler --sources 对应）
DEFAULT_SOURCES = ["csdn", "github", "xianzhi", "qianxin"]
# 每个关键词爬取的最大页数（较小，避免 P0 拖太久）
DEFAULT_MAX_PAGES = 3


class CrawlWorker:
    """
    负责把 GapSignal → 网站爬取 → raw_data/ 的完整流程。

    参数
    ----
    sources      : 要使用的数据源列表，默认 DEFAULT_SOURCES
    max_pages    : 每个关键词每个数据源爬取的最大页数，默认 3
    min_quality  : 最小质量分（0~1），低于此值的结果不计入 CrawlResult，默认 0.3
    output_subdir: raw_data/ 下的子目录前缀，默认 "layer4"
    """

    def __init__(
        self,
        sources: Optional[List[str]] = None,
        max_pages: int = DEFAULT_MAX_PAGES,
        min_quality: float = 0.3,
        output_subdir: str = "raw_data/layer4",
    ):
        self.sources        = sources or list(DEFAULT_SOURCES)
        self.max_pages      = max_pages
        self.min_quality    = min_quality
        self.output_subdir  = output_subdir
        self._manager       = None   # 延迟初始化，避免导入时就拉起 requests.Session

    # ── 公开接口 ────────────────────────────────────────────────────────────────

    # ── 字节预算配置（BUG-7A/D）────────────────────────────────────────────────
    MAX_DOCS_PER_GAP  = 5          # 每条缺口最多接受 5 篇文档
    MAX_BYTES_PER_GAP = 100_000    # 每条缺口最多 100KB 内容（~5篇×20KB）

    def process(self, signal: GapSignal) -> List[CrawlResult]:
        """
        处理单个 GapSignal：
          对每条 search_query 调用 CrawlerManager，汇总返回 CrawlResult 列表。
        如果 search_queries 为空，用 gap_description 作为兜底关键词。

        BUG-7A/D 修复：严格执行 MAX_DOCS_PER_GAP 和 MAX_BYTES_PER_GAP 双重门禁。
        """
        queries = list(signal.search_queries)
        if not queries:
            desc = signal.gap_description.strip()
            if desc:
                queries = [desc[:120]]
            elif signal.cve_ids:
                queries = [f"{c} exploit PoC" for c in signal.cve_ids[:2]]
        if not queries:
            logger.warning("GapSignal %s 没有可用的搜索关键词，跳过", signal.gap_id)
            return []

        manager = self._get_manager()
        all_results: List[CrawlResult] = []
        total_bytes = 0

        for query in queries:
            # 检查是否已达到本 gap 的预算上限
            if len(all_results) >= self.MAX_DOCS_PER_GAP:
                logger.info(
                    "[Layer4] gap=%s 已达 max_docs=%d，停止爬取后续关键词",
                    signal.gap_id[:8], self.MAX_DOCS_PER_GAP,
                )
                break
            if total_bytes >= self.MAX_BYTES_PER_GAP:
                logger.info(
                    "[Layer4] gap=%s 已达 max_bytes=%d，停止爬取后续关键词",
                    signal.gap_id[:8], self.MAX_BYTES_PER_GAP,
                )
                break

            logger.info(
                "[Layer4] gap=%s  query='%s'  sources=%s",
                signal.gap_id[:8], query, self.sources,
            )
            try:
                results = self._crawl_query(manager, signal.gap_id, query)
                for r in results:
                    if len(all_results) >= self.MAX_DOCS_PER_GAP:
                        break
                    doc_bytes = len(r.content.encode("utf-8", errors="replace"))
                    if total_bytes + doc_bytes > self.MAX_BYTES_PER_GAP:
                        logger.debug(
                            "[Layer4] gap=%s 字节预算将溢出（+%dB），停止接受更多文档",
                            signal.gap_id[:8], doc_bytes,
                        )
                        break
                    all_results.append(r)
                    total_bytes += doc_bytes
            except Exception as exc:
                logger.error("[Layer4] 爬取失败 query='%s': %s", query, exc, exc_info=True)

        logger.info(
            "[Layer4] gap=%s 爬取完成，共 %d 篇 / %d 字节（%d 个关键词）",
            signal.gap_id[:8], len(all_results), total_bytes, len(queries),
        )
        return all_results

    def crawl_single_query(self, query: str, gap_id: str = "manual") -> List[CrawlResult]:
        """直接按关键词爬取（无需 GapSignal，便于手动调用和测试）。"""
        manager = self._get_manager()
        return self._crawl_query(manager, gap_id, query)

    # ── 内部实现 ────────────────────────────────────────────────────────────────

    def _get_manager(self):
        """延迟初始化 CrawlerManager（单例，避免重复建立 requests.Session）。"""
        if self._manager is None:
            from crawlers.crawler_manager import CrawlerManager
            self._manager = CrawlerManager()
        return self._manager

    def _crawl_query(
        self, manager, gap_id: str, query: str
    ) -> List[CrawlResult]:
        """
        对单条关键词调用 CrawlerManager，保存原始 JSON，
        并将结果转换为 CrawlResult 列表。
        """
        # 确定本次保存目录（raw_data/layer4/YYYYMMDD_HHmmss_<gap_id[:8]>/）
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = f"{self.output_subdir}/{ts}_{gap_id[:8]}"

        raw_results: dict = {}
        available = manager.list_crawlers()

        for source in self.sources:
            if source not in available:
                logger.debug("数据源 %s 未注册，跳过", source)
                continue
            try:
                items = manager.crawl_single_source(
                    source, query, max_pages=self.max_pages
                )
                if items:
                    raw_results[source] = items
                    logger.info("  [%s] %s → %d 条", source, query, len(items))
                else:
                    logger.debug("  [%s] %s → 0 条", source, query)
            except Exception as exc:
                logger.warning("  [%s] 爬取异常: %s", source, exc)

        # 保存原始数据（即使为空也保存，方便调试）
        if raw_results:
            try:
                manager.save_results(raw_results, query, output_dir=out_dir)
            except Exception as exc:
                logger.warning("[Layer4] save_results 失败: %s", exc)

        # 转换为 CrawlResult
        from .quality_filter import filter_content
        crawl_results: List[CrawlResult] = []
        for source, items in raw_results.items():
            for item in items:
                content = str(item.get("content") or item.get("body") or "")
                url     = str(item.get("url") or item.get("link") or "")
                title   = str(item.get("title") or "")
                qr      = filter_content(content, url)
                if qr.score < self.min_quality:
                    continue
                crawl_results.append(CrawlResult(
                    gap_id        = gap_id,
                    source        = source,
                    url           = url,
                    title         = title,
                    content       = content[:8000],   # 截断，避免超大
                    quality_score = qr.score,
                    has_poc       = qr.has_poc,
                    has_commands  = qr.has_commands,
                ))

        return crawl_results
