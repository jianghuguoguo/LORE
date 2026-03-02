"""
discovery/discovery_scheduler.py — 来源发现调度器
====================================================
整合三个发现通道，实现持续的账号来源自动扩充。

运行策略（由 Celery Beat 调度）：
  ● 每天凌晨 02:00 — 完整发现流程（搜狗 + 引用提取）
  ● 每周日 03:00   — 深度社区同步（GitHub awesome 列表）
  ● 每次爬取完成后 — 立即运行引用提取（per_crawl 模式）

评分门控：
  ● score ≥ 40 → 自动加入 TARGET_ACCOUNTS（auto_add=True）
  ● score 25-39 → 写入 review_queue.jsonl 等待人工审核
  ● score < 25  → 丢弃

依赖：discovery/* + quality/account_scorer.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

# ── sys.path：供 discovery.* 和 crawlers.wechat_crawler.* 导入 ───────────────
_WC = Path(__file__).parent.parent   # crawlers/wechat_crawler/
_RT = _WC.parent.parent              # RefPenTest/
for _p in (str(_RT), str(_WC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

log = logging.getLogger(__name__)

from discovery.models import AccountCandidate


# ── 配置 ─────────────────────────────────────────────────────────────────────
AUTO_ADD_THRESHOLD    = int(os.environ.get('DISCOVERY_AUTO_THRESHOLD', '40'))
REVIEW_THRESHOLD      = int(os.environ.get('DISCOVERY_REVIEW_THRESHOLD', '25'))
REVIEW_QUEUE_FILE     = Path(os.environ.get(
    'DISCOVERY_REVIEW_FILE',
    _RT / 'data' / 'discovery_review_queue.jsonl',
))


class DiscoveryScheduler:
    """
    整合三个发现通道，实现持续的账号来源扩充。

    Usage::

        scheduler = DiscoveryScheduler()
        new_accounts = scheduler.run_full_discovery()
        # new_accounts 已自动写入 TARGET_ACCOUNTS（通过 seed_accounts.yaml）
        # 低分候选写入 review_queue.jsonl 等待人工审核
    """

    def __init__(self) -> None:
        self._scorer = self._init_scorer()

    @staticmethod
    def _init_scorer():
        try:
            from quality.account_scorer import AccountQualityScorer
            return AccountQualityScorer()
        except ImportError:
            log.warning('[Scheduler] AccountQualityScorer 未找到，发现结果将跳过评分直接加入')
            return None

    # ── 主流程 ────────────────────────────────────────────────────────────────

    def run_full_discovery(
        self,
        keywords: List[str] | None = None,
    ) -> List[AccountCandidate]:
        """
        完整发现流程（三通道并行）。

        Returns
        -------
        List[AccountCandidate]  经过评分门控后自动加入的账号列表
        """
        log.info('[Scheduler] 启动完整来源发现流程...')
        all_candidates: dict[str, AccountCandidate] = {}

        # ── 1. 三通道并行 ──────────────────────────────────────────────────────
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix='discovery') as ex:
            futures = {
                ex.submit(self._run_sogou, keywords): 'sogou',
                ex.submit(self._run_citation): 'citation',
                ex.submit(self._run_community): 'community',
            }
            for future in as_completed(futures):
                channel = futures[future]
                try:
                    results = future.result(timeout=120)
                    for c in results:
                        key = c.biz if c.biz else c.name
                        if key not in all_candidates:
                            all_candidates[key] = c
                    log.info(f'[Scheduler] {channel} 返回 {len(results)} 个候选')
                except Exception as e:
                    log.error(f'[Scheduler] {channel} 渠道失败: {e}', exc_info=True)

        # ── 2. 去重合并 ───────────────────────────────────────────────────────
        merged = list(all_candidates.values())
        log.info(f'[Scheduler] 三通道合并后共 {len(merged)} 个候选')

        # ── 3. 过滤已知账号 ───────────────────────────────────────────────────
        known = self._load_known_accounts()
        merged = [c for c in merged if c.name not in known]
        log.info(f'[Scheduler] 过滤已知账号后剩余 {len(merged)} 个')

        # ── 4. 两阶段评分 ───────────────────────────────────────────────────
        # 第一阶段：元数据快速评分（_quick_score）
        # 第二阶段：若 captured_queue.jsonl 已有该账号的文章，用 AccountQualityScorer 补充内容评分
        qualified: List[AccountCandidate] = []
        review_queue: List[AccountCandidate] = []

        for candidate in merged:
            # 阶段 1：元数据评分（名称关键词 + 来源可信度）
            quick_score = self._quick_score(candidate)

            # 阶段 2：内容评分（如果队列文件已有该账号的文章）
            score = quick_score
            if self._scorer is not None:
                sample = self._fetch_sample_articles(candidate.name)
                if len(sample) >= 2:
                    try:
                        full = self._scorer.score_from_sample(sample, candidate.name)
                        # 内容评分占 70%，元数据评分占 30%
                        score = quick_score * 0.30 + full.total_score * 0.70
                        log.info(
                            f'[Scheduler] {candidate.name!r} 两阶段评分: '
                            f'quick={quick_score:.1f} full={full.total_score:.1f}(样本{len(sample)}篇) '
                            f'→ 合并={score:.1f}'
                        )
                    except Exception as e:
                        log.debug(f'[Scheduler] {candidate.name!r} 内容评分失败，仅用元数据分: {e}')

            candidate.score = score
            candidate.grade = (
                'A' if score >= 75 else
                'B' if score >= 50 else
                'C' if score >= 30 else 'D'
            )

            if score >= AUTO_ADD_THRESHOLD:
                candidate.auto_add = True
                qualified.append(candidate)
                log.info(f'[Scheduler] ✓ 自动加入: {candidate.name!r} (score={score:.1f})')
            elif score >= REVIEW_THRESHOLD:
                review_queue.append(candidate)
                log.info(f'[Scheduler] ~ 待审核: {candidate.name!r} (score={score:.1f})')
            else:
                log.debug(f'[Scheduler] ✗ 丢弃: {candidate.name!r} (score={score:.1f})')

        # ── 5. 写入结果 ───────────────────────────────────────────────────────
        if qualified:
            self._append_to_targets(qualified)
        if review_queue:
            self._write_review_queue(review_queue)

        log.info(f'[Scheduler] 发现完成: 自动加入 {len(qualified)} 个，待审核 {len(review_queue)} 个')
        return qualified

    def run_citation_only(self) -> List[AccountCandidate]:
        """
        仅运行引用提取（每次爬取完成后调用）。
        速度快，适合高频触发。
        """
        candidates = self._run_citation()
        return self._apply_gate(candidates)

    # ── 三通道实现 ────────────────────────────────────────────────────────────

    @staticmethod
    def _run_sogou(keywords: List[str] | None = None) -> List[AccountCandidate]:
        try:
            from discovery.sogou_discovery import SogouAccountDiscovery
            disc = SogouAccountDiscovery()
            try:
                return disc.discover_by_keywords(keywords)
            finally:
                disc.close()
        except Exception as e:
            log.error(f'[Sogou] 运行失败: {e}')
            return []

    @staticmethod
    def _run_citation() -> List[AccountCandidate]:
        """通道 B：从 raw_data/wechat/*.json 提取引用账号（搜狗爬虫产物）。"""
        try:
            from discovery.citation_extractor import run_channel_b
            raw_dir = _RT / 'raw_data' / 'wechat'
            return run_channel_b(raw_dir=raw_dir, verbose=False) or []
        except Exception as e:
            log.error(f'[Citation] 运行失败: {e}')
            return []

    @staticmethod
    def _run_community() -> List[AccountCandidate]:
        try:
            from discovery.community_sync import CommunityCrossValidator
            val = CommunityCrossValidator()
            return val.sync_from_github()
        except Exception as e:
            log.error(f'[Community] 运行失败: {e}')
            return []

    # ── 评分辅助 ──────────────────────────────────────────────────────────────

    def _fetch_sample_articles(self, account_name: str, max_count: int = 5) -> list[dict]:
        """
        从 raw_data/wechat/ 读取指定账号的已爬取文章作为内容评分样本。
        仅使用本地已有数据，不触发网络请求。
        """
        raw_dir = _RT / 'raw_data' / 'wechat'
        samples: list[dict] = []
        if not raw_dir.exists():
            return samples
        for fpath in raw_dir.glob('*.json'):
            try:
                data = json.loads(fpath.read_text(encoding='utf-8'))
                if data.get('account', '').strip() == account_name.strip():
                    samples.append(data)
                    if len(samples) >= max_count:
                        break
            except Exception:
                pass
        return samples

    def _quick_score(self, candidate: AccountCandidate) -> float:
        """
        对候选账号进行快速评分（不需要采样文章的基础评分）。
        完整评分需采样文章，在有内容后由 AccountQualityScorer 补充。
        """
        score = 0.0

        # 名称相关性评分（最高 40 分）
        name_lower = candidate.name.lower()
        relevance_kws = [
            (['渗透', '红队', '漏洞', '代码审计', '内网', 'security', '安全'], 15),
            (['CTF', '逆向', '二进制', '应急', 'exploit', 'web安全'], 8),
            (['研究', '实验室', 'cert', 'response', '预警'], 3),
        ]
        for kw_list, pts in relevance_kws:
            for kw in kw_list:
                if kw.lower() in name_lower:
                    score += pts
                    break

        # 来源可信度加分
        source_bonus = {
            'community_regex':      18,   # 通道C正则路径（原 community_github 无代码产生，已修正）
            'community_llm':        20,   # 通道C LLM 路径
            'citation':             10,
            'citation_biz':         12,
            'sogou_account_search':  5,
            'sogou_article_search':  3,
        }
        score += source_bonus.get(candidate.source, 0)

        # 简介长度加分（有简介说明来源信息完整）
        if len(candidate.description) > 20:
            score += 5

        return min(score, 100.0)

    # ── 持久化辅助 ────────────────────────────────────────────────────────────

    @staticmethod
    def _load_known_accounts() -> set[str]:
        """从 config.py TARGET_ACCOUNTS 和 seed_accounts.yaml 加载已知账号名。"""
        known: set[str] = set()
        try:
            from crawlers.wechat_crawler.config import MITM_CONFIG
            known.update(MITM_CONFIG.get('TARGET_ACCOUNTS', []))
        except Exception:
            pass

        seed_file = _WC / 'seed_accounts.yaml'
        if seed_file.exists():
            try:
                import yaml
                with seed_file.open(encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                for cat_accounts in (data.get('categories') or {}).values():
                    for acc in (cat_accounts or []):
                        if isinstance(acc, dict):
                            known.add(acc.get('name', ''))
                        elif isinstance(acc, str):
                            known.add(acc)
            except Exception:
                pass
        return known

    @staticmethod
    def _append_to_targets(candidates: List[AccountCandidate]) -> None:
        """
        将通过评分门控的账号自动追加到 seed_accounts.yaml（discovered 分类）。
        """
        seed_file = _WC / 'seed_accounts.yaml'
        try:
            import yaml
            data: dict = {}
            if seed_file.exists():
                with seed_file.open(encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}

            categories = data.setdefault('categories', {})
            discovered = categories.setdefault('auto_discovered', [])

            existing_names = {
                a['name'] if isinstance(a, dict) else a
                for a in discovered
            }
            for c in candidates:
                if c.name not in existing_names:
                    discovered.append({
                        'name':    c.name,
                        'source':  c.source,
                        'score':   round(c.score, 1),
                        'grade':   c.grade,
                        'added_at': time.strftime('%Y-%m-%d'),
                        'tags':    c.tags,
                    })

            seed_file.parent.mkdir(parents=True, exist_ok=True)
            with seed_file.open('w', encoding='utf-8') as f:
                yaml.dump(data, f, allow_unicode=True, default_flow_style=False)

            log.info(f'[Scheduler] 已将 {len(candidates)} 个账号追加到 {seed_file.name}')
        except Exception as e:
            log.error(f'[Scheduler] 写入 seed_accounts.yaml 失败: {e}')

    @staticmethod
    def _write_review_queue(candidates: List[AccountCandidate]) -> None:
        """将待审核账号写入 discovery_review_queue.jsonl。"""
        REVIEW_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            with REVIEW_QUEUE_FILE.open('a', encoding='utf-8') as f:
                for c in candidates:
                    f.write(json.dumps(c.to_dict(), ensure_ascii=False) + '\n')
        except OSError as e:
            log.error(f'[Scheduler] 写入审核队列失败: {e}')

    def _apply_gate(self, candidates: List[AccountCandidate]) -> List[AccountCandidate]:
        """对候选列表应用评分门控，返回通过的列表。"""
        qualified = []
        for c in candidates:
            c.score = self._quick_score(c)
            if c.score >= AUTO_ADD_THRESHOLD:
                c.auto_add = True
                qualified.append(c)
        return qualified
