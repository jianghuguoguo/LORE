"""
sogou_crawler.py — 微信公众号文章直接爬取脚本
==============================================
通过搜狗微信搜索接口获取文章 URL，再直接下载全文。
不依赖 mitmproxy / PC 微信客户端，使用现有代理 (7890) 访问外网。

位置：crawlers/wechat_crawler/sogou_crawler.py

用法：
    python crawlers/wechat_crawler/sogou_crawler.py --accounts FreeBuf 安全客 --count 10
    python crawlers/wechat_crawler/sogou_crawler.py --seed     # 爬取 seed_accounts.yaml 全部账号
    python crawlers/wechat_crawler/sogou_crawler.py --accounts FreeBuf  # 单账号测试
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

# ── 路径 ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent                       # crawlers/wechat_crawler/
_ROOT = _HERE.parent.parent                         # LORE/
SAVE_DIR = _ROOT / 'raw_data' / 'wechat'
SAVE_DIR.mkdir(parents=True, exist_ok=True)

SEED_FILE = _HERE / 'seed_accounts.yaml'

# ── 日志 ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('wechat_crawl')

# ── HTTP Session ──────────────────────────────────────────────────────────────
# 使用现有梯子代理（7890）访问搜狗
PROXY = {
    'http':  'http://127.0.0.1:7890',
    'https': 'http://127.0.0.1:7890',
}

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/122.0.0.0 Safari/537.36'
    ),
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Referer': 'https://weixin.sogou.com/',
}

def _make_session() -> requests.Session:
    """创建新的 requests Session 并设置通用 Headers。"""
    s = requests.Session()
    s.headers.update(HEADERS)
    return s


def _get(sess: requests.Session, url: str, **kwargs) -> Optional[requests.Response]:
    """带重试的 GET（通过 7890 代理）。"""
    for attempt in range(3):
        try:
            resp = sess.get(url, proxies=PROXY, timeout=20, **kwargs)
            if resp.status_code == 200:
                return resp
            log.warning(f'HTTP {resp.status_code} for {url[:80]}')
        except Exception as e:
            log.warning(f'请求失败 (尝试 {attempt+1}/3): {e}')
        time.sleep(2 ** attempt)
    return None


# ── 搜狗搜索 ─────────────────────────────────────────────────────────────────

def search_and_resolve_articles(
    sess: requests.Session, account_name: str, page: int = 1,
    query_override: 'Optional[str]' = None,
) -> list[dict]:
    """
    在搜狗微信搜索中搜索指定公众号文章，并在同一 Session 内解析跳转 URL。
    返回 [{title, url(mp.weixin.qq.com), pub_time, account}, ...]

    query_override: 若传入（如 '__biz=XXX'），直接替换搜索关键词，
                    实现公众号 biz 精确搜索，避免混入同品牌其他账号。

    关键：Sogou 的 /link?url=... 与 Session Cookie 绑定，
          必须用"提取该链接的同一 Session"来跟随，不能跨 Session 使用。
    """
    params = {
        'type': '2',          # type=2: 文章搜索
        'query': query_override or account_name,
        'page': page,
    }
    search_url = 'https://weixin.sogou.com/weixin?' + urlencode(params)
    log.debug(f'搜索: {search_url}')

    resp = _get(sess, search_url)
    if not resp:
        return []

    # 被验证码拦截 —— 等待后重试一次，而非直接放弃
    if 'antispider' in resp.url or 'antispider' in resp.text[:300]:
        log.warning('被搜狗验证码拦截，等待 90 秒后重试一次')
        time.sleep(90)
        resp2 = _get(sess, search_url)
        if resp2 and 'antispider' not in resp2.url and 'antispider' not in resp2.text[:300]:
            resp = resp2
            log.info('验证码已解除，继续解析')
        else:
            log.warning('重试仍被拦截，本页放弃')
            return []

    soup = BeautifulSoup(resp.text, 'html.parser')
    items = soup.select('ul.news-list li')
    log.info(f'搜索「{account_name}」第{page}页，找到 {len(items)} 个结果条目')

    articles = []
    for item in items:
        h3_a = item.select_one('h3 a')
        if not h3_a:
            continue
        title = h3_a.get_text(strip=True)
        sogou_href = h3_a.get('href', '')
        if not sogou_href:
            continue

        # 完整 URL
        if sogou_href.startswith('/'):
            sogou_href = 'https://weixin.sogou.com' + sogou_href

        # 账号名（优先用 .account 类）
        acct_el = item.select_one('.account, [class*=account]')
        account_text = acct_el.get_text(strip=True) if acct_el else account_name

        # ── 发布时间：data-ts 属性最可靠（Unix 时间戳，不会与账号名混淆）──
        pub_time = ''
        ts_el = item.find(attrs={'data-ts': True})
        if ts_el:
            try:
                import datetime as _dt
                pub_time = _dt.datetime.fromtimestamp(int(ts_el['data-ts'])).strftime('%Y-%m-%d')
            except Exception:
                pass
        # 备用：查找 em 标签（搜狗有时把时间放在 em 里）
        if not pub_time:
            em_el = item.select_one('.s-p em, .s2 em, em')
            if em_el:
                pub_time = em_el.get_text(strip=True)
        # 安全校验：若看起来不像日期，丢弃（防止把账号名存成时间）
        _DATE_RE = re.compile(r'\d{4}[-年/.]\d{1,2}')
        if pub_time and not _DATE_RE.search(pub_time):
            log.debug(f'丢弃非日期 pub_time: {pub_time!r}')
            pub_time = ''

        # ── 搜索阶段预过滤：非 biz 模式下跳过明显不匹配账号，节省下载请求 ──
        if not query_override and account_text and not _account_matches(account_text, account_name):
            log.debug(f'搜索结果账号不符，跳过解析: {account_text!r}')
            continue

        # ── 同 Session 内解析跳转链接 ──────────────────────────────────────
        real_url = _follow_sogou_link(sess, sogou_href)
        if not real_url:
            log.debug(f'跳转解析失败: {sogou_href[:60]}')
            continue

        articles.append({
            'title':    title,
            'url':      real_url,
            'pub_time': pub_time,
            'account':  account_text,
        })
        time.sleep(random.uniform(1.5, 3))  # 每条链接解析后小停顿

    return articles


def _lookup_account_biz(sess: requests.Session, account_name: str) -> Optional[str]:
    """
    通过搜狗公众号搜索（type=1）查找目标账号的 biz 参数。
    biz 是微信公众号的唯一 base64 标识；用 __biz=xxx 做文章搜索时只返回该账号文章，
    彻底解决同品牌账号混入问题（如搜"360漏洞研究院"混入"360数字安全"等）。
    返回 biz 字符串（如 'MzI3NjA1...'），找不到时返回 None。
    """
    params = {'type': '1', 'query': account_name}
    url = 'https://weixin.sogou.com/weixin?' + urlencode(params)
    resp = _get(sess, url)
    if not resp:
        return None
    if 'antispider' in resp.url or 'antispider' in resp.text[:300]:
        log.debug('公众号搜索被验证码拦截，跳过 biz 查询')
        return None

    soup = BeautifulSoup(resp.text, 'html.parser')
    # 搜狗公众号卡片可能在 .account-list li 或 .vrwrap / .result 等结构下
    for item in soup.select('.account-list li, .result, .vrwrap'):
        name_el = item.select_one('.account-name, .tit a, h3 a')
        if not name_el:
            continue
        if not _account_matches(name_el.get_text(strip=True), account_name):
            continue
        # 账号卡片链接示例：/weixin?type=2&query=__biz%3DMzI3NjI3Mz...
        for a in item.select('a[href]'):
            href = a.get('href', '')
            m = re.search(r'[?&]query=__biz(?:%3D|=)([A-Za-z0-9+/]+={0,2})', href)
            if m:
                biz = m.group(1)
                log.info(f'找到 {account_name!r} 的 biz: {biz[:20]}...')
                return biz
    log.debug(f'未找到 {account_name!r} 的 biz，将使用关键词搜索')
    return None


def _follow_sogou_link(sess: requests.Session, sogou_url: str) -> Optional[str]:
    """
    用同一 Session 跟随 Sogou 跳转链接，返回真实的 mp.weixin.qq.com/s URL。

    Sogou 防爬机制：直接重定向会返回含 JS 字符串拼接的页面，
    真实 URL 由多段 url += '...' 拼合而成，需手动还原。
    """
    if 'mp.weixin.qq.com' in sogou_url:
        return sogou_url

    resp = _get(sess, sogou_url, allow_redirects=True)
    if not resp:
        return None

    final_url = resp.url
    if 'mp.weixin.qq.com' in final_url:
        return final_url

    # ── Sogou JS 拼接模式：url = ''; url += '...'; url += '...' ─────────
    if "url +=" in resp.text:
        parts = re.findall(r"url\s*\+=\s*['\"]([^'\"]*)['\"]", resp.text)
        if parts:
            assembled = ''.join(parts)
            log.debug(f'JS 拼接 URL: {assembled[:120]}')
            if 'mp.weixin.qq.com' in assembled:
                return assembled

    # 备用：直接正则提取完整 mp.weixin URL
    m = re.search(r'https://mp\.weixin\.qq\.com/s[^\s"\'<>\\]+', resp.text)
    if m:
        return m.group(0).rstrip('\\')

    m = re.search(r"window\.location\.href\s*=\s*['\"]([^'\"]+mp\.weixin\.qq\.com[^'\"]+)['\"]", resp.text)
    if m:
        return m.group(1)

    log.debug(f'跟随后落地: {final_url[:80]}，未能提取微信 URL')
    return None


def fetch_article(sess: requests.Session, article_url: str) -> Optional[dict]:
    """
    下载微信文章完整内容。
    返回 {title, author, account, content, pub_time, url} 或 None。
    """
    resp = _get(sess, article_url)
    if not resp:
        return None

    # 检测付费/仅限关注内容
    if '该内容仅限关注' in resp.text or '已停止访问该网页' in resp.text:
        log.warning(f'内容受限，跳过: {article_url[:80]}')
        return None

    soup = BeautifulSoup(resp.text, 'html.parser')

    # 标题
    title = (
        soup.select_one('#activity-name, .rich_media_title')
        or soup.find('h1')
    )
    title = title.get_text(strip=True) if title else ''

    # 作者 / 公众号
    author_el = soup.select_one('#js_author_name, .author')
    account_el = soup.select_one('#js_name, .account_nickname_inner')
    author  = author_el.get_text(strip=True) if author_el else ''
    account = account_el.get_text(strip=True) if account_el else ''

    # 发布时间（多个 CSS 选择器备用）
    pub_time = ''
    time_el = soup.select_one(
        '#publish_time, #js_publish_time, em#publish_time, '
        '.rich_media_meta_text, #meta_content em'
    )
    if time_el:
        candidate = time_el.get_text(strip=True)
        # 过滤：只接受含数字年份的字符串
        if re.search(r'\d{4}', candidate):
            pub_time = candidate
    if not pub_time:
        # 从页面 JS 变量提取时间戳（var ct / ori_create_time / createTime）
        m = re.search(
            r'(?:var\s+ct\s*=\s*["\']|"(?:ori_create_time|createTime)"\s*:\s*)"?(\d{9,10})"?',
            resp.text
        )
        if m:
            ts = int(m.group(1))
            pub_time = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

    # 正文
    content_el = soup.select_one('#js_content, .rich_media_content')
    content = content_el.get_text('\n', strip=True) if content_el else ''

    if not title and not content:
        return None

    return {
        'title':        title,
        'author':       author,
        'account':      account,
        'content':      content,
        'publish_time': pub_time,     # 统一 schema：publish_time（与 MITM 爬虫一致）
        'url':          article_url,
        'captured_at':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # 统一：captured_at
        'site':         'wechat',     # 统一：site（替代 source）
        'biz_id':       '',           # MITM 模式时会填充
        'mid_id':       '',
    }


def save_article(data: dict) -> Path:
    """保存文章 JSON 到 raw_data/wechat/。"""
    url_hash = hashlib.md5(data['url'].encode()).hexdigest()[:8]
    safe_title = re.sub(r'[\\/:*?"<>|]', '_', data['title'])[:50]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f'wechat_{safe_title}_{ts}_{url_hash}.json'
    fpath = SAVE_DIR / fname
    fpath.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    return fpath


# ── Bug7: 技术内容过滤 ─────────────────────────────────────────────────────

# 正向识别关键词：出现即为技术文
_TECH_KEYWORDS = [
    # 渗透测试
    '渗透', '漏洞', '利用', '提权', '内网',  '魂弹', 'exploit', 'payload', 'bypass',
    'rce', 'lfi', 'rfi', 'ssrf', 'ssti', 'xxe', 'deseri',
    # web 安全
    'sql注入', 'xss', 'csrf', '注入', '序列化', '文件包含', '命令执行', '上传',
    'web安全', '请求伪造',
    # 漏洞/CVE
    'cve-', 'cve编号', 'cnnvd', 'cnvd', '0day', '0-day', 'poc', 'exp ',
    '高危漏洞', '严重漏洞', '远程代码执行', '任意代码执行',
    # 恶意软件/威胁情报
    '威胁', '恶意软件', '勒索', '木马', '后门', 'apt', '魚叉攻击', 'c2',
    '尾部', '水坑攻击', '晚期', 'malware', 'ransomware', 'trojan',
    # CTF/逆向工程
    'ctf', '逆向', '调试', 'pwn', 'shellcode', '二进制分析',
    # 代码审计
    '代码审计', '稿件分析', '漏洞分析', '文件分析',
    # 安全工具/技术
    'nmap', 'burp', 'metasploit', 'cobalt', 'mimikatz', 'sqlmap',
    '扫描', '字典爆破', '哈希', '密码破解',
]

# 负向关键词：标题包含即直接丢弃
_NOISE_TITLE_KEYWORDS = [
    '情报汇报', '年度盘点', '荣誉之路', '展会', '幕后', '内测开启',
    '电台', '招聘', '招聘信息', '活动规划', '公报', '周报',
    '快讯', '年动', '年报', 'pr稿', '宣传', '公司诎生', '周年庆',
]

MIN_CONTENT_LEN = 300  # 正文少于此字数直接丢弃


def _is_tech_relevant(data: dict) -> tuple[bool, str]:
    """
    判断文章是否具备渗透测试/信息安全的技术价值。
    返回 (True, '') 表示通过，返回 (False, 原因) 表示过滤。
    """
    title   = data.get('title', '').lower()
    content = data.get('content', '').lower()
    clen    = len(data.get('content', ''))

    # 1. 内容过短
    if clen < MIN_CONTENT_LEN:
        return False, f'正文过短({clen}字<{MIN_CONTENT_LEN})'

    # 2. 标题包含噪声词，直接丢弃
    for kw in _NOISE_TITLE_KEYWORDS:
        if kw in title:
            return False, f'标题包含噪声词[{kw}]'

    # 3. 标题命中技术关键词 → 直接通过
    for kw in _TECH_KEYWORDS:
        if kw in title:
            return True, ''

    # 4. 正文中需出现 ≥ 2 个技术关键词才通过（标题模糊的情况）
    hits = sum(1 for kw in _TECH_KEYWORDS if kw in content)
    if hits >= 2:
        return True, ''

    return False, f'未命中技术关键词(正文命中={hits})'


def _account_matches(actual: str, target: str) -> bool:
    """
    判断文章实际账号名是否与目标搜索账号名匹配。
    支持以下几种情形：
      · 完全一致 / 大小写不同
      · 包含关系（绿盟科技 ∈ 绿盟科技研究院 → 匹配）
      · 英文账号去括号（nu1l team vs nu1l）
    """
    a = actual.strip().lower().replace(' ', '')
    t = target.strip().lower().replace(' ', '')
    if not a:  # 文章页未提取到账号名，放行
        return True
    if a == t:
        return True
    # 包含关系：任一方包含另一方（处理全称/简称）
    if a in t or t in a:
        return True
    # 字符重叠比例 >= 0.7（处理轻微差异）
    a_set = set(a)
    t_set = set(t)
    if a_set and t_set:
        overlap = len(a_set & t_set) / max(len(a_set), len(t_set))
        if overlap >= 0.75 and min(len(a), len(t)) >= 3:
            return True
    return False


# ── 主爬取逻辑 ────────────────────────────────────────────────────────────────

def _load_seen_keys() -> tuple[set[str], set[str]]:
    """
    从已保存的 JSON 文件中加载所有曾爬取过的 URL 和标题，用于跨会话去重。
    返回 (seen_urls, seen_titles)。
    同一篇文章可能有多个 Sogou 时间戳 URL，需要标题去重兜底。
    """
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    for fpath in SAVE_DIR.glob('*.json'):
        try:
            data = json.loads(fpath.read_text(encoding='utf-8'))
            url = data.get('url', '')
            title = data.get('title', '').strip()
            if url:
                seen_urls.add(url)
            if title:
                seen_titles.add(title)
        except Exception:
            pass
    return seen_urls, seen_titles


def crawl_account(account_name: str, count: int = 20) -> int:
    """爬取指定公众号，返回成功保存的文章数。"""
    log.info(f'=== 开始爬取: {account_name}（目标 {count} 篇）===')
    saved = 0
    # 加载跨会话历史 URL + 标题，避免重复下载（同文章多 Sogou URL 场景）
    seen_urls, seen_titles = _load_seen_keys()
    log.debug(f'已有历史去重 URL {len(seen_urls)} 条，标题 {len(seen_titles)} 条')

    # 每个账号使用独立 Session（含独立 Cookie），确保链接 Token 一致
    sess = _make_session()

    # ── biz 精确搜索：先用 type=1 查目标账号的唯一 biz，避免混入同品牌账号 ──
    biz = _lookup_account_biz(sess, account_name)
    query_override = f'__biz={biz}' if biz else None
    if query_override:
        log.info(f'使用 biz 精确模式搜索: {query_override[:30]}')
    else:
        log.info('未找到 biz，使用关键词搜索（可能有同品牌账号混入）')

    consecutive_empty = 0
    for page in range(1, 10):
        if saved >= count:
            break

        articles = search_and_resolve_articles(sess, account_name, page, query_override)
        if not articles:
            consecutive_empty += 1
            log.warning(f'第{page}页无可用文章（连续空页 {consecutive_empty}/2）')
            if consecutive_empty >= 2:
                log.warning('连续 2 页无结果，停止翻页')
                break
            continue
        consecutive_empty = 0  # 重置计数

        for art in articles:
            if saved >= count:
                break

            real_url = art.get('url', '')
            if not real_url or real_url in seen_urls:
                continue
            # 标题级别去重（同文章不同 Sogou 时间戳 URL）
            art_title = art.get('title', '').strip()
            if art_title and art_title in seen_titles:
                log.debug(f'标题已存在，跳过: {art_title[:40]}')
                continue
            seen_urls.add(real_url)

            # 下载全文
            data = fetch_article(sess, real_url)
            if not data:
                log.warning(f'下载失败或内容受限: {real_url[:70]}')
                time.sleep(random.uniform(2, 4))
                continue

            # 补充来源信息（Sogou 搜索结果可能比页面内提取更准）
            if not data.get('account'):
                data['account'] = art.get('account', account_name)
            if not data.get('publish_time'):
                data['publish_time'] = art.get('pub_time', '')

            # ── 账号过滤：拒绝非目标账号的文章 ────────────────
            actual_account = data.get('account', '')
            if not _account_matches(actual_account, account_name):
                log.warning(f'账号不符（目标={account_name!r} 实际={actual_account!r}），跳过')
                time.sleep(random.uniform(1, 2))
                continue

            # ── Bug7 过滤：技术内容低质文章 ─────────────────────
            ok, reason = _is_tech_relevant(data)
            if not ok:
                log.info(f'过滤低价值文章 [{reason}]: {data["title"][:45]}')
                time.sleep(random.uniform(1, 2))
                continue

            # 保存
            fpath = save_article(data)
            saved += 1
            seen_titles.add(data.get('title', '').strip())  # 本次会话内也去重标题
            log.info(f'[{saved}/{count}] ✓ 已保存: {data["title"][:50]}')
            log.debug(f'  -> {fpath.name}')

            # 随机间隔，防封
            time.sleep(random.uniform(3, 7))

        # 翻页停顿
        time.sleep(random.uniform(5, 10))

    log.info(f'=== {account_name} 完成，共保存 {saved} 篇 ===')
    return saved


def load_seed_accounts() -> list[str]:
    """从 seed_accounts.yaml 加载账号名称列表。"""
    if not SEED_FILE.exists():
        return []
    try:
        import yaml
        data = yaml.safe_load(SEED_FILE.read_text(encoding='utf-8'))
        names = []
        for cat, items in (data.get('categories') or {}).items():
            for item in (items or []):
                if isinstance(item, dict):
                    names.append(item.get('name', ''))
                elif isinstance(item, str):
                    names.append(item)
        return [n for n in names if n]
    except Exception as e:
        log.warning(f'加载 seed_accounts.yaml 失败: {e}')
        return []


# ── CLI 入口 ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='微信公众号文章爬虫（搜狗接口）')
    parser.add_argument('--accounts', nargs='+', help='公众号名称（可多个）')
    parser.add_argument('--seed', action='store_true', help='爬取 seed_accounts.yaml 全部账号')
    parser.add_argument('--count', type=int, default=20, help='每账号文章数（默认20）')
    args = parser.parse_args()

    if args.seed:
        accounts = load_seed_accounts()
        if not accounts:
            print('seed_accounts.yaml 为空或找不到，请用 --accounts 指定账号')
            sys.exit(1)
        print(f'从 seed_accounts.yaml 加载了 {len(accounts)} 个账号')
    elif args.accounts:
        accounts = args.accounts
    else:
        parser.print_help()
        sys.exit(1)

    total = 0
    for acct in accounts:
        n = crawl_account(acct, args.count)
        total += n
        time.sleep(random.uniform(10, 20))  # 账号间随机冷却

    print(f'\n全部完成！共保存 {total} 篇文章到 {SAVE_DIR}')
    files = list(SAVE_DIR.glob('*.json'))
    print(f'raw_data/wechat/ 现有 {len(files)} 个 JSON 文件')

    # ── 爬取完成后自动运行通道 B（引用挖掘），发现新账号 ─────────────────────
    if total > 0:
        print('\n[自动] 爬取完成，启动通道 B（文章引用挖掘）...')
        try:
            sys.path.insert(0, str(_HERE))
            from discovery.citation_extractor import run_channel_b
            new_cands = run_channel_b(verbose=True)
            if new_cands:
                print(f'[通道B] 发现 {len(new_cands)} 个候选账号，详见 raw_data/discovery/channel_b_candidates.json')
                print('[提示] 运行 python run_discovery.py --auto-add 可自动追加到 seed_accounts.yaml')
        except Exception as e:
            log.warning(f'[通道B] 自动触发失败（不影响爬取结果）: {e}')

