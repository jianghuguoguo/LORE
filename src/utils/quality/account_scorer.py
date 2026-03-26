"""
src/utils/quality/account_scorer.py — 公众号账号质量评分
=================================================
基于采样文章对候选公众号进行多维度自动质量评分，决定是否纳入爬取计划。

评分维度（总计 100 分）：
  ● 相关性 relevance    ×0.40 — 与渗透测试领域的主题匹配程度
  ● 活跃度 activity     ×0.20 — 更新频率与最近发文时间
  ● 原创性 originality  ×0.25 — 原创文章占比（非转载）
  ● 技术深度 depth      ×0.15 — 代码密度、文章长度、技术术语密度

等级划分：
  A ≥ 75 / B ≥ 50 / C ≥ 30 / D < 30

设计参考 PageRank 思路：
  被高质量账号引用（citation 渠道来源）= 质量加分
  代码密度高 = 技术深度加分
  原创比例高 = 原创性加分
"""

from __future__ import annotations

import dataclasses
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


# ── 数据类 ───────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class AccountScore:
    """公众号质量评分结果。"""
    account_id:         str
    total_score:        float           # 0-100
    relevance_score:    float           # 内容相关性分（0-100）
    activity_score:     float           # 更新活跃度分（0-100）
    originality_score:  float           # 原创性分（0-100）
    depth_score:        float           # 技术深度分（0-100）
    grade:              str             # A/B/C/D
    sample_size:        int    = 0      # 评分用的文章采样数

    @classmethod
    def zero(cls, account_id: str = '') -> 'AccountScore':
        return cls(
            account_id=account_id, total_score=0.0,
            relevance_score=0.0, activity_score=50.0,
            originality_score=0.0, depth_score=0.0,
            grade='D',
        )

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ── 评分器 ───────────────────────────────────────────────────────────────────

class AccountQualityScorer:
    """
    对候选公众号进行自动质量评分。

    Usage::

        scorer = AccountQualityScorer()
        articles = [...]  # 采样文章列表（建议 10-20 篇）
        result: AccountScore = scorer.score_from_sample(articles, account_id='example')
        print(result.grade, result.total_score)
    """

    # ── 渗透测试关键词权重表 ─────────────────────────────────────────────────
    PENTEST_KEYWORDS: Dict[str, List[str]] = {
        'critical': [
            '渗透测试', '红队', '漏洞挖掘', '代码审计', '内网渗透',
            '漏洞利用', 'exploit', 'payload', 'webshell', 'RCE',
            'Active Directory', 'Kerberos', '横向移动', '持久化',
            'BypassAV', '免杀', '提权', '权限维持',
        ],
        'important': [
            '安全', 'CTF', 'Writeup', '靶场', '漏洞', 'vulnerability',
            'C2', 'CobaltStrike', 'Metasploit', 'mimikatz',
            'SQL注入', 'XSS', 'SSRF', 'XXE', 'CSRF', '命令注入',
            '反序列化', '文件包含', '目录遍历', '越权',
        ],
        'bonus': [
            'CVE', 'POC', 'EXP', '零日', '0day', '威胁情报',
            '应急响应', 'APT', '供应链', '沙盒逃逸',
        ],
    }

    # 转载标记（原创性检测用）
    _REPOST_MARKERS: List[str] = [
        '转载', '来源：', '来源:', '原文链接', '原文地址',
        '作者：', '作者:', '首发于', '本文来自',
    ]

    # 技术术语密度计算用的关键词组
    _TECH_TERMS: List[str] = [
        'payload', 'exploit', 'poc', 'exp', 'rce', 'sql', 'xss', 'ssrf',
        'ldap', 'ntlm', 'kerberos', 'mimikatz', 'cobalt', 'metasploit',
        'reverse shell', 'bind shell', 'c2', 'c&c', 'bypass', 'webshell',
        'privilege', 'escalation', 'lateral movement', 'persistence',
        '渗透', '漏洞', '代码审计', '内网', '提权', '后门',
    ]

    def score_from_sample(
        self,
        articles:   List[dict],
        account_id: str = '',
    ) -> AccountScore:
        """
        基于采样文章计算账号质量分（建议采样最近 10-20 篇）。

        Parameters
        ----------
        articles   : 文章字典列表（需含 title, content, publish_time 字段）
        account_id : 账号标识（用于结果记录）

        Returns
        -------
        AccountScore
        """
        if not articles:
            log.warning(f'[Scorer] {account_id!r} 无采样文章，返回零分')
            return AccountScore.zero(account_id)

        relevance    = self._calc_relevance(articles)
        activity     = self._calc_activity(articles)
        originality  = self._calc_originality(articles)
        depth        = self._calc_technical_depth(articles)

        # 加权总分
        total = (
            relevance   * 0.40 +
            activity    * 0.20 +
            originality * 0.25 +
            depth       * 0.15
        )

        grade = (
            'A' if total >= 75 else
            'B' if total >= 50 else
            'C' if total >= 30 else 'D'
        )

        score = AccountScore(
            account_id=account_id,
            total_score=round(total, 2),
            relevance_score=round(relevance, 2),
            activity_score=round(activity, 2),
            originality_score=round(originality, 2),
            depth_score=round(depth, 2),
            grade=grade,
            sample_size=len(articles),
        )
        log.info(
            f'[Scorer] {account_id!r} '
            f'总分={score.total_score:.1f}({grade}) '
            f'相关={relevance:.0f} 活跃={activity:.0f} '
            f'原创={originality:.0f} 深度={depth:.0f} '
            f'(n={len(articles)})'
        )
        return score

    # ── 子维度计算 ────────────────────────────────────────────────────────────

    def _calc_relevance(self, articles: List[dict]) -> float:
        """
        计算与渗透测试领域的相关性（0-100）。
        每篇文章独立计算命中的关键词权重之和，取平均后归一化。
        """
        weights = {'critical': 5, 'important': 2, 'bonus': 1}
        article_scores: List[float] = []

        for article in articles:
            text = (
                (article.get('title') or '') + ' ' +
                (article.get('content') or '')
            ).lower()

            art_score = 0.0
            for tier, kw_list in self.PENTEST_KEYWORDS.items():
                w = weights[tier]
                for kw in kw_list:
                    if kw.lower() in text:
                        art_score += w
            # 单篇上限 10 分（归一化前），避免极端值拉高
            article_scores.append(min(art_score, 10.0))

        if not article_scores:
            return 0.0
        avg = sum(article_scores) / len(article_scores)
        # 映射到 0-100：avg=0→0, avg=5→50, avg=10→100
        return min(avg * 10.0, 100.0)

    def _calc_activity(self, articles: List[dict]) -> float:
        """
        计算近期更新活跃度（0-100）。
        综合：最近发文距今天数（recency）+ 近 30 天发文频次（frequency）。
        """
        times: List[datetime] = []
        for a in articles:
            pt = a.get('publish_time', '')
            if not pt:
                continue
            try:
                # 兼容多种格式：'2024-01-15 10:30:00' 或 '2024-01-15'
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
                    try:
                        times.append(datetime.strptime(pt[:19], fmt))
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        if len(times) < 1:
            return 50.0  # 无法判断时给中间分

        now = datetime.now()
        times.sort(reverse=True)

        # recency：最近发文距今天数（越近越高）
        days_since_last = (now - times[0]).days
        recency = max(0.0, 100.0 - days_since_last * 2)

        # frequency：近 30 天发文数（每篇 10 分，上限 100）
        recent_count = sum(1 for t in times if (now - t).days <= 30)
        frequency = min(recent_count * 10.0, 100.0)

        return recency * 0.6 + frequency * 0.4

    def _calc_originality(self, articles: List[dict]) -> float:
        """
        计算原创比例（0-100）。
        检查文章前 200 字符是否含转载标记。
        """
        if not articles:
            return 0.0
        original_count = sum(
            1 for a in articles
            if not any(
                marker in (a.get('content') or '')[:200]
                for marker in self._REPOST_MARKERS
            )
        )
        return (original_count / len(articles)) * 100.0

    def _calc_technical_depth(self, articles: List[dict]) -> float:
        """
        计算技术深度（0-100）。
        综合：代码块密度 + 文章长度 + 技术术语密度。
        """
        scores: List[float] = []

        for article in articles:
            content = article.get('content', '') or ''

            # 代码块数量（每个代码块 +15，上限 45）
            code_block_count = content.count('```') // 2
            code_score = min(code_block_count * 15.0, 45.0)

            # 文章长度分（500以下=0，2000以上=30，线性内插）
            char_count = len(content)
            length_score = min(max(0.0, (char_count - 500) / 1500 * 30.0), 30.0)

            # 技术术语密度（每千字含多少个技术词，上限 25）
            content_lower = content.lower()
            term_count = sum(1 for t in self._TECH_TERMS if t in content_lower)
            words_k = max(len(content) / 1000, 1)
            density_score = min((term_count / words_k) * 5.0, 25.0)

            scores.append(code_score + length_score + density_score)

        if not scores:
            return 0.0
        return min(sum(scores) / len(scores), 100.0)

    # ── 批量评分 ──────────────────────────────────────────────────────────────

    def score_accounts(
        self,
        account_articles_map: Dict[str, List[dict]],
    ) -> Dict[str, AccountScore]:
        """
        批量对多个账号评分。

        Parameters
        ----------
        account_articles_map : {account_id: [articles...]}

        Returns
        -------
        {account_id: AccountScore}
        """
        return {
            account_id: self.score_from_sample(arts, account_id)
            for account_id, arts in account_articles_map.items()
        }
