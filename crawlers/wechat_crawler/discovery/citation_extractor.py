"""
discovery/citation_extractor.py — 通道 B：文章内部引用挖掘
============================================================
从已爬取的文章内容中提取引用的公众号名称，实现"以爬养爬"的图谱扩散策略。

微信文章中常见的引用模式（高精度，命中即为真实来源）：
  ● "转载自 【公众号名】"
  ● "来源：公众号名"
  ● "作者 | 公众号名"
  ● "推荐关注 【公众号名】"
  ● "原文链接" 指向其他公众号文章（提取 __biz 参数）

这一渠道可信度最高：被优质公众号引用过的账号本身通常也是优质账号。

用法（独立运行）：
    python -m discovery.citation_extractor
    python -m discovery.citation_extractor --raw-dir raw_data/wechat --threshold 2
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

# ── sys.path：供 discovery.* 和 crawlers.wechat_crawler.* 导入 ───────────────
_WC = Path(__file__).parent.parent   # crawlers/wechat_crawler/
_RT = _WC.parent.parent              # LORE/
for _p in (str(_RT), str(_WC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

log = logging.getLogger(__name__)

from discovery.models import AccountCandidate

# ── 路径常量（相对于项目根，调用方可覆盖）────────────────────────────────────
_HERE        = _RT                               # LORE/
_WECHAT_DIR  = _HERE / 'raw_data' / 'wechat'
_DISC_DIR    = _HERE / 'raw_data' / 'discovery'
_SEED_FILE   = _WC / 'seed_accounts.yaml'
_B_OUTPUT    = _DISC_DIR / 'channel_b_candidates.json'

# 日期格式校验正则（避免把账号名误用为时间戳）
_DATE_VALID_RE = re.compile(r'\d{4}[-年/.]\d{1,2}')


def _valid_date(val: str) -> str:
    """返回有效的日期字符串；若 val 不像日期（如账号名），则返回当前时间。"""
    if val and _DATE_VALID_RE.search(val):
        return val
    return time.strftime('%Y-%m-%dT%H:%M:%S')


class CitationExtractor:
    """
    从单篇或批量文章中挖掘新公众号来源。

    使用方式：
    >>> extractor = CitationExtractor()
    >>> candidates = extractor.extract_from_article(article_dict)
    >>> all_candidates = extractor.batch_extract(articles_list)
    """

    # ── 引用模式正则（按精度从高到低排列）────────────────────────────────────
    _TEXT_PATTERNS: List[re.Pattern] = [
        # "转载自 【名称】" 或 「名称」或普通括号
        re.compile(r'转载[自来源于来自于]?\s*[【「\[]([^】」\]]{2,25})[】」\]]'),
        # "来源：名称" 或 "来源: 名称"
        re.compile(r'来源[：:]\s*([^\s，,。\n【】「」]{2,25})'),
        # "作者 | 名称"（常见于安全公众号规范化排版）
        re.compile(r'作者\s*[|｜]\s*([^\s，,。\n【】「」]{2,25})'),
        # "推荐关注 【名称】" / "扫码关注【名称】"
        re.compile(r'(?:推荐关注|关注公众号|扫码关注)\s*[「【\[]([^」】\]]{2,25})[」】\]]'),
        # "首发于 名称" / "首发：名称"
        re.compile(r'首发[于:]?\s*([^\s，,。\n【】「」]{2,25})'),
        # "本文来自 名称" / "本文转自 名称"
        re.compile(r'本文(?:来自|转自|摘自|首发于|出处)\s*[：:]?\s*([^\s，,。\n【】「」]{2,25})'),
        # 免责声明末尾 "版权归 xxx 所有"
        re.compile(r'版权归\s*([^\s，,。\n【】「」]{2,20})\s*所有'),
    ]

    # biz 提取（从 mp.weixin.qq.com URL 中）
    _BIZ_PATTERN = re.compile(
        r'mp\.weixin\.qq\.com/s[?/][^"\'>\s]*[?&]__biz=([A-Za-z0-9=+/]{10,})'
    )

    # 黑名单：常见非账号词汇
    _BLACKLIST: Set[str] = {
        '微信', '朋友圈', '公众号', '关注', '原文', '作者', '编辑', '转载',
        '来源', '版权', '声明', '本文', '文章', '链接', '网络', '互联网',
        '以上', '以下', '前者', '后者', '此处', '该文', '相关', '更多',
        '点击', '阅读', '扫描', '扫码', '二维码', '联系', '合作', '投稿',
        '平台', '渠道', '官方', '账号', '号主', '小编',
        # 常见误提取词
        '原作者', '原作', '编译', '整理', '责编', '排版', '审核',
        '摘要', '全文', '部分', '关键词', '参考', '引用', '致谢',
    }

    def extract_from_article(self, article: dict) -> List[AccountCandidate]:
        """
        从单篇文章提取引用的公众号候选。

        Parameters
        ----------
        article : 爬取到的文章字典（需含 content, title, url, account 字段）

        Returns
        -------
        List[AccountCandidate] — 去重后的候选列表（不含来源账号自身）
        """
        text       = (article.get('content', '') + '\n' + article.get('title', ''))
        src_url    = article.get('url', '')
        src_author = article.get('account', '')
        found:     Dict[str, AccountCandidate] = {}

        # ── 文本模式匹配 ──────────────────────────────────────────────────────
        for pattern in self._TEXT_PATTERNS:
            for m in pattern.finditer(text):
                name = m.group(1).strip().rstrip('。，！？…]）』』')
                # 过滤：有效名称、不是自身账号、不在黑名单
                if (
                    self._is_valid_account_name(name)
                    and name not in found
                    and name != src_author
                ):
                    found[name] = AccountCandidate(
                        name=name,
                        source='citation',
                        discovery_keyword=src_url[:100],
                        first_seen=_valid_date(
                            article.get('publish_time') or article.get('pub_time', '')
                        ),
                    )

        # ── biz 提取（精确，可直接定位公众号）────────────────────────────────
        for m in self._BIZ_PATTERN.finditer(text):
            biz = m.group(1)
            key = f'__biz:{biz}'
            if key not in found:
                found[key] = AccountCandidate(
                    name=key,          # 暂时用 biz 作为占位名，后续由 sogou 补全
                    biz=biz,
                    source='citation_biz',
                    discovery_keyword=src_url[:100],
                    first_seen=_valid_date(
                        article.get('publish_time') or article.get('pub_time', '')
                    ),
                )

        return list(found.values())

    def batch_extract(
        self,
        articles: List[dict],
    ) -> List[AccountCandidate]:
        """
        从文章列表批量提取，全局去重后返回，并按引用次数排序。

        Parameters
        ----------
        articles : 文章字典列表

        Returns
        -------
        List[AccountCandidate]（按被引用次数降序）
        """
        # name -> (AccountCandidate, mention_count)
        merged:  Dict[str, AccountCandidate] = {}
        counter: Dict[str, int] = {}

        for art in articles:
            for c in self.extract_from_article(art):
                key = c.biz if c.biz else c.name
                if key not in merged:
                    merged[key]  = c
                    counter[key] = 1
                else:
                    counter[key] += 1

        # 将引用次数写入 mention_count 字段
        for key, c in merged.items():
            c.mention_count = counter[key]

        # 按引用次数降序
        candidates = sorted(merged.values(), key=lambda x: counter.get(x.biz or x.name, 1), reverse=True)
        log.info(f'[ChannelB] 从 {len(articles)} 篇文章中提取到 {len(candidates)} 个候选账号')
        return candidates

    def extract_from_queue_file(self, queue_file: str | Path) -> List[AccountCandidate]:
        """
        从 captured_queue.jsonl（interceptor 输出的 JSONL 文件）批量提取。

        Parameters
        ----------
        queue_file : captured_queue.jsonl 路径

        Returns
        -------
        List[AccountCandidate]
        """
        articles = []
        path = Path(queue_file)
        if not path.exists():
            log.warning(f'[ChannelB] 队列文件不存在: {queue_file}')
            return []

        try:
            with path.open(encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            articles.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError as e:
            log.error(f'[ChannelB] 读取队列文件失败: {e}')

        return self.batch_extract(articles)

    # ── 辅助方法 ──────────────────────────────────────────────────────────────

    def _is_valid_account_name(self, name: str) -> bool:
        """
        判断提取到的名称是否可能是有效的公众号名。
        规则：长度 2-25，不在黑名单，不含纯数字，不以标点开头。
        """
        if not (2 <= len(name) <= 25):
            return False
        if name in self._BLACKLIST:
            return False
        if name.isdigit():
            return False
        # 以常见标点或数字开头的几乎不是账号名
        if re.match(r'^[，,。！!？?、\-\—\.0-9]', name):
            return False
        # 包含 http / www 的是 URL，不是账号名
        if re.search(r'http|www\.', name, re.IGNORECASE):
            return False
        # 末尾残留括号/方括号说明正则边界未对齐，是噪声
        if name.endswith(']') or name.endswith(')') or name.endswith('）'):
            return False
        return True


# ── 独立运行入口：通道 B 主函数 ───────────────────────────────────────────────

def _load_known_names(seed_file: Path) -> Set[str]:
    """从 seed_accounts.yaml 读取所有已知账号名，用于去重。"""
    known: Set[str] = set()
    if not seed_file.exists():
        return known
    try:
        import yaml   # type: ignore
        data = yaml.safe_load(seed_file.read_text(encoding='utf-8')) or {}
        for cat_accounts in (data.get('categories') or {}).values():
            if isinstance(cat_accounts, list):
                for item in cat_accounts:
                    if isinstance(item, dict) and item.get('name'):
                        known.add(item['name'])
    except Exception as e:
        log.warning(f'[ChannelB] 读取 seed_accounts.yaml 失败: {e}')
    return known


def run_channel_b(
    raw_dir   : Path | str = _WECHAT_DIR,
    output    : Path | str = _B_OUTPUT,
    seed_file : Path | str = _SEED_FILE,
    threshold : int        = 1,
    verbose   : bool       = True,
) -> List[AccountCandidate]:
    """
    通道 B 主入口：扫描 raw_data/wechat/ 下全部文章 JSON，提取引用账号。

    Parameters
    ----------
    raw_dir   : 文章 JSON 文件目录
    output    : 候选结果输出 JSON 文件路径
    seed_file : seed_accounts.yaml 路径（用于去重已知账号）
    threshold : 最少被引用 N 次才纳入候选（默认 1，即出现即收录）
    verbose   : 是否打印日志

    Returns
    -------
    新发现（不在种子库中）的 AccountCandidate 列表
    """
    if verbose:
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s %(message)s',
            datefmt='%H:%M:%S',
        )

    raw_dir   = Path(raw_dir)
    output    = Path(output)
    seed_file = Path(seed_file)

    # 1. 加载所有文章
    files = sorted(raw_dir.glob('*.json'))
    if not files:
        log.info(f'[ChannelB] raw_dir 中没有 JSON 文件: {raw_dir}')
        return []

    articles: List[dict] = []
    for f in files:
        try:
            articles.append(json.loads(f.read_text(encoding='utf-8')))
        except Exception as e:
            log.debug(f'[ChannelB] 跳过损坏文件 {f.name}: {e}')

    log.info(f'[ChannelB] 加载文章 {len(articles)} 篇，来自 {raw_dir}')

    # 2. 批量提取
    extractor = CitationExtractor()
    all_cands = extractor.batch_extract(articles)

    # 3. 按 threshold 过滤（引用次数在 description 中）
    def _count(c: AccountCandidate) -> int:
        return c.mention_count if c.mention_count > 0 else 1

    if threshold > 1:
        all_cands = [c for c in all_cands if _count(c) >= threshold]

    # 4. 排除已在种子库中的账号
    known = _load_known_names(seed_file)
    new_cands = [c for c in all_cands if c.name not in known and not c.name.startswith('__biz:')]
    biz_cands = [c for c in all_cands if c.name.startswith('__biz:')]

    log.info(f'[ChannelB] 候选账号: 共 {len(all_cands)} 个 | 新发现 {len(new_cands)} 个 | '
             f'已知 {len(all_cands) - len(new_cands) - len(biz_cands)} 个 | '
             f'biz 待查 {len(biz_cands)} 个')

    # 5. 保存结果
    output.parent.mkdir(parents=True, exist_ok=True)
    result = new_cands + biz_cands
    output.write_text(
        json.dumps([c.to_dict() for c in result], ensure_ascii=False, indent=2),
        encoding='utf-8',
    )
    log.info(f'[ChannelB] 结果已保存 → {output}')

    # 6. 终端摘要
    if verbose and new_cands:
        print('\n════════ 通道 B 新发现账号 ════════')
        for c in new_cands[:30]:
            print(f'  {c.name:<25}  引用次数: {c.mention_count}  来源: {c.discovery_keyword[:60]}')
        if len(new_cands) > 30:
            print(f'  ... 另有 {len(new_cands) - 30} 个，详见 {output}')

    return result


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='通道 B — 文章引用挖掘')
    ap.add_argument('--raw-dir',   default=str(_WECHAT_DIR), help='文章 JSON 目录')
    ap.add_argument('--output',    default=str(_B_OUTPUT),   help='输出 JSON 路径')
    ap.add_argument('--threshold', default=1, type=int,      help='最少引用次数')
    args = ap.parse_args()

    run_channel_b(
        raw_dir=args.raw_dir,
        output=args.output,
        threshold=args.threshold,
    )

