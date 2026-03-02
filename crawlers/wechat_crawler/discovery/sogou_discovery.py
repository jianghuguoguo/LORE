"""
discovery/sogou_discovery.py — 搜狗微信搜索驱动的公众号发现
=============================================================
通过搜狗微信搜索（weixin.sogou.com）自动发现与渗透测试领域相关的优质公众号。

特性：
  ● 零成本 — 无需 API Key，搜狗对微信内容有完整索引
  ● 双模式搜索 — type=1（公众号直接搜索）+ type=2（从文章倒推公众号）
  ● 自动限速 — 搜索间隔随机 3-6 秒，带 User-Agent 轮换
  ● 关键词扩展 — 内置 20+ 渗透测试核心关键词

依赖：httpx>=0.27, beautifulsoup4>=4.12, lxml>=5.0
"""

from __future__ import annotations

import logging
import random
import re
import time
from typing import Generator, List

log = logging.getLogger(__name__)

# ── 可选依赖 ─────────────────────────────────────────────────────────────────
try:
    import httpx
    from bs4 import BeautifulSoup
    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False
    log.warning('搜狗发现依赖缺失，请运行: pip install httpx beautifulsoup4 lxml')

# 路径修复：确保 crawlers.wechat_crawler 及 discovery 包可被导入
import sys as _sys
from pathlib import Path as _Path
_WC = _Path(__file__).parent.parent          # crawlers/wechat_crawler/
_RT = _WC.parent.parent                      # RefPenTest/
for _p in (str(_RT), str(_WC)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
del _sys, _Path, _p

from discovery.models import AccountCandidate

# ── 渗透测试核心关键词（按搜索优先级排列）────────────────────────────────────
PENTEST_KEYWORDS: List[str] = [
    # 技术主题（高相关性）
    '内网渗透', '红队实战', '代码审计', 'bypass WAF', 'SQL注入实战',
    'SSRF漏洞', '内存马', '免杀技术', 'Active Directory渗透', '权限提升',
    # 工具/框架
    'CobaltStrike使用', 'Metasploit', '蚁剑webshell', 'CS上线',
    # 漏洞类型
    '漏洞复现', 'RCE漏洞', 'Java反序列化', 'PHP代码审计',
    'CSRF绕过', 'XSS绕过', '供应链攻击', '0day漏洞',
    # CVE/严重漏洞（动态当年）
    'CVE-202', 'Kerberos攻击', '横向移动', '持久化后门',
]

# User-Agent 池（避免单一 UA 被识别）
_USER_AGENTS: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
]


class SogouAccountDiscovery:
    """
    通过搜狗微信搜索发现优质安全公众号。

    搜狗对微信内容有完整索引，无需登录，是最稳定的零成本发现通道。
    """

    BASE_URL = 'https://weixin.sogou.com/weixin'

    def __init__(self, rate_limit_sec: tuple[float, float] = (3.0, 6.0)) -> None:
        if not _DEPS_AVAILABLE:
            raise ImportError('缺少依赖：pip install httpx beautifulsoup4 lxml')
        self._rate_limit = rate_limit_sec
        self._discovered: dict[str, AccountCandidate] = {}   # name → candidate
        self._session = self._make_session()

    @staticmethod
    def _make_session() -> 'httpx.Client':
        return httpx.Client(
            headers={'User-Agent': random.choice(_USER_AGENTS)},
            timeout=15.0,
            follow_redirects=True,
            proxy='http://127.0.0.1:7890',   # Bug6 修复：与项目其他模块保持一致，通过 7890 代理访问搜狗
        )

    def _throttle(self) -> None:
        sleep_sec = random.uniform(*self._rate_limit)
        log.debug(f'[Sogou] 限速等待 {sleep_sec:.1f}s')
        time.sleep(sleep_sec)

    # ── 主入口 ────────────────────────────────────────────────────────────────

    def discover_by_keywords(
        self,
        keywords: List[str] | None = None,
    ) -> List[AccountCandidate]:
        """
        对每个关键词依次执行双模式搜索，返回去重后的候选列表。

        Parameters
        ----------
        keywords : 搜索关键词列表，None 时使用内置列表

        Returns
        -------
        List[AccountCandidate] — 去重后的候选账号列表
        """
        kws = keywords or PENTEST_KEYWORDS
        for kw in kws:
            log.info(f'[Sogou] 搜索关键词: {kw!r}')
            # 公众号搜索（type=1）
            for c in self._search_accounts(kw):
                self._upsert(c, kw)
            self._throttle()

            # 文章搜索（type=2）
            for c in self._search_articles_for_accounts(kw):
                self._upsert(c, kw)
            self._throttle()

        candidates = list(self._discovered.values())
        log.info(f'[Sogou] 发现候选账号 {len(candidates)} 个')
        return candidates

    # ── 搜索模式 A：公众号搜索（type=1）─────────────────────────────────────

    def _search_accounts(self, keyword: str) -> Generator[AccountCandidate, None, None]:
        """
        type=1：公众号名称搜索，直接返回公众号卡片。
        典型 DOM：.news-box .news-list li → .txt-box h3 a（名称）
                  .txt-box p（简介）
        """
        try:
            resp = self._session.get(
                self.BASE_URL,
                params={'type': 1, 'query': keyword, 'ie': 'utf8'},
            )
            resp.raise_for_status()
        except Exception as e:
            log.warning(f'[Sogou] type=1 请求失败: {e}')
            return

        soup = BeautifulSoup(resp.text, 'lxml')

        for item in soup.select('.news-box .news-list li, .weixin-list .weixin-list-item'):
            name_tag = (
                item.select_one('.txt-box h3 a')
                or item.select_one('.account-list-item a')
            )
            if name_tag is None:
                continue
            name = name_tag.get_text(strip=True)
            if not name or not self._is_valid_name(name):
                continue

            desc_tag = item.select_one('.txt-box p, .account-desc')
            desc = desc_tag.get_text(strip=True) if desc_tag else ''

            yield AccountCandidate(
                name=name,
                description=desc[:200],
                source='sogou_account_search',
                discovery_keyword=keyword,
                first_seen=time.strftime('%Y-%m-%dT%H:%M:%S'),
            )

    # ── 搜索模式 B：文章搜索（type=2），从文章来源倒推公众号 ─────────────────

    def _search_articles_for_accounts(self, keyword: str) -> Generator[AccountCandidate, None, None]:
        """
        type=2：文章搜索，从文章列表中提取来源公众号名。
        典型 DOM：.news-list li .txt-box → span.all-time-y2 a（来源名）
        """
        try:
            resp = self._session.get(
                self.BASE_URL,
                params={'type': 2, 'query': keyword, 'ie': 'utf8'},
            )
            resp.raise_for_status()
        except Exception as e:
            log.warning(f'[Sogou] type=2 请求失败: {e}')
            return

        soup = BeautifulSoup(resp.text, 'lxml')

        for item in soup.select('.news-list li .txt-box, .news-list .news-item'):
            # 来源账号有多种 CSS 路径，逐一尝试
            source_tag = (
                item.select_one('span.all-time-y2 a')
                or item.select_one('.media-nick a')
                or item.select_one('.account-nickname a')
            )
            if source_tag is None:
                continue
            name = source_tag.get_text(strip=True)
            if not name or not self._is_valid_name(name):
                continue

            yield AccountCandidate(
                name=name,
                source='sogou_article_search',
                discovery_keyword=keyword,
                first_seen=time.strftime('%Y-%m-%dT%H:%M:%S'),
            )

    # ── 辅助方法 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _is_valid_name(name: str) -> bool:
        """过滤明显非公众号的名称。"""
        if len(name) < 2 or len(name) > 40:
            return False
        blacklist = {'微信', '朋友圈', '公众号', '关注', '原文', '作者', '编辑',
                     '新闻', '视频', '更多', '推荐', '广告', '...'}
        return name not in blacklist

    def _upsert(self, candidate: AccountCandidate, keyword: str) -> None:
        """去重合并：同名账号只保留一条，追加标签。"""
        existing = self._discovered.get(candidate.name)
        if existing is None:
            self._discovered[candidate.name] = candidate
        else:
            # 已存在：补充发现渠道和关键词信息
            if keyword not in existing.tags:
                existing.tags.append(keyword)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass
