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
import os as _os
import random
import re
import socket
import sys
import time
from datetime import datetime, timedelta
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

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from runtime_settings import get_effective_sogou_settings

# ── 日志 ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('wechat_crawl')

# ── HTTP Session ──────────────────────────────────────────────────────────────
# 代理模式显式可配置：默认直连，避免每次请求都先撞本地 7890。
_SOGOU_SETTINGS = get_effective_sogou_settings(env=_os.environ)
_PROXY_MODE = str(_SOGOU_SETTINGS['proxy_mode']).strip().lower()
_PROXY_HOST = str(_SOGOU_SETTINGS['proxy_host'])
_PROXY_PORT = str(_SOGOU_SETTINGS['proxy_port'])
_PROXY_URL = str(_SOGOU_SETTINGS['proxy_url'])
_SEARCH_DELAY_MIN = float(_SOGOU_SETTINGS['search_delay_min'])
_SEARCH_DELAY_MAX = float(_SOGOU_SETTINGS['search_delay_max'])
_ANTISPIDER_WAIT_MIN = int(_SOGOU_SETTINGS['antispider_wait_min'])
_ANTISPIDER_WAIT_MAX = int(_SOGOU_SETTINGS['antispider_wait_max'])

if _PROXY_MODE not in {'direct', 'auto', 'proxy'}:
    log.warning(f'未知 LORE_SOGOU_PROXY_MODE={_PROXY_MODE!r}，回退为 direct')
    _PROXY_MODE = 'direct'

PROXY = {
    'http': _PROXY_URL,
    'https': _PROXY_URL,
}

_PROXY_AVAILABLE: Optional[bool] = None
_TRANSPORT_LOGGED = False

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
]

HEADERS = {
    'User-Agent': random.choice(_USER_AGENTS),
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Referer': 'https://weixin.sogou.com/',
}


def _refresh_headers(sess: requests.Session, referer: str = 'https://weixin.sogou.com/') -> None:
    """轮换 UA，并维持更像浏览器的请求头。"""
    sess.headers.update({
        'User-Agent': random.choice(_USER_AGENTS),
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Cache-Control': 'max-age=0',
        'Referer': referer,
    })


def _sleep_jitter(low: float, high: float, reason: str = '') -> None:
    secs = random.uniform(low, high)
    if reason:
        log.debug(f'{reason}，等待 {secs:.1f}s')
    time.sleep(secs)


def _probe_proxy_once() -> bool:
    """仅在 auto 模式下探测一次本地代理是否可用。"""
    global _PROXY_AVAILABLE
    if _PROXY_AVAILABLE is not None:
        return _PROXY_AVAILABLE
    try:
        with socket.create_connection((_PROXY_HOST, int(_PROXY_PORT)), timeout=1.5):
            _PROXY_AVAILABLE = True
    except OSError:
        _PROXY_AVAILABLE = False
    return _PROXY_AVAILABLE


def _iter_transports() -> list[tuple[str, Optional[dict[str, str]]]]:
    if _PROXY_MODE == 'direct':
        return [('直连', None)]
    if _PROXY_MODE == 'proxy':
        return [('代理', PROXY)]
    if _probe_proxy_once():
        return [('代理', PROXY), ('直连', None)]
    return [('直连', None)]


def _log_transport_once() -> None:
    global _TRANSPORT_LOGGED
    if _TRANSPORT_LOGGED:
        return
    _TRANSPORT_LOGGED = True
    if _PROXY_MODE == 'proxy':
        log.info(f'[Transport] 搜狗请求固定走代理: {_PROXY_URL}')
    elif _PROXY_MODE == 'auto':
        if _probe_proxy_once():
            log.info(f'[Transport] 搜狗请求优先代理，失败回退直连: {_PROXY_URL}')
        else:
            log.info('[Transport] 未探测到可用本地代理，搜狗请求改为直连')
    else:
        log.info('[Transport] 搜狗请求默认直连；如需代理请设置 LORE_SOGOU_PROXY_MODE=auto|proxy')


def _is_antispider_response(resp: requests.Response) -> bool:
    preview = resp.text[:600] if resp.text else ''
    return 'antispider' in resp.url or 'antispider' in preview


def _make_session() -> requests.Session:
    """创建新的 requests Session 并设置通用 Headers。"""
    s = requests.Session()
    s.trust_env = False
    s.headers.update(HEADERS)
    return s


def _get(sess: requests.Session, url: str, **kwargs) -> Optional[requests.Response]:
    """带重试的 GET，支持 direct / auto / proxy 三种代理模式。"""
    _log_transport_once()
    max_attempts = int(kwargs.pop('_max_attempts', 3))
    skip_delay = bool(kwargs.pop('_skip_delay', False))

    if not skip_delay and 'weixin.sogou.com' in url:
        _refresh_headers(sess)
        _sleep_jitter(_SEARCH_DELAY_MIN, _SEARCH_DELAY_MAX, 'Sogou 搜索限速')

    for attempt in range(max_attempts):
        for transport_name, proxies in _iter_transports():
            try:
                resp = sess.get(url, proxies=proxies, timeout=20, **kwargs)
                if resp.status_code == 200:
                    return resp
                if resp.status_code in (403, 429):
                    log.warning(f'HTTP {resp.status_code} ({transport_name}): {url[:80]}')
                else:
                    log.warning(f'{transport_name} HTTP {resp.status_code}: {url[:80]}')
            except requests.RequestException as req_err:
                if proxies and _PROXY_MODE == 'auto':
                    global _PROXY_AVAILABLE
                    _PROXY_AVAILABLE = False
                log.warning(f'{transport_name}请求失败 (尝试 {attempt+1}/{max_attempts}): {req_err}')
        if attempt < max_attempts - 1:
            _sleep_jitter(1.5 * (attempt + 1), 3.0 * (attempt + 1), '请求退避')
    return None


def _warmup_sogou_session(sess: requests.Session) -> None:
    """先访问首页获取 cookie，再发搜索请求，降低首次即触发验证的概率。"""
    _refresh_headers(sess)
    resp = _get(sess, 'https://weixin.sogou.com/', _skip_delay=True, _max_attempts=1)
    if resp is not None:
        _sleep_jitter(1.0, 2.2, 'Sogou 会话预热完成')


def _get_sogou_search_page(sess: requests.Session, search_url: str, label: str) -> Optional[requests.Response]:
    """对搜狗搜索页面增加预热和更保守的验证码退避。"""
    resp = _get(sess, search_url)
    if not resp:
        return None
    if not _is_antispider_response(resp):
        return resp

    wait_sec = random.randint(_ANTISPIDER_WAIT_MIN, _ANTISPIDER_WAIT_MAX)
    log.warning(f'[{label}] 被搜狗验证码拦截，等待 {wait_sec}s 后重试')
    time.sleep(wait_sec)
    _warmup_sogou_session(sess)

    resp2 = _get(sess, search_url, _max_attempts=2)
    if resp2 and not _is_antispider_response(resp2):
        log.info(f'[{label}] 验证页解除，继续解析')
        return resp2

    log.warning(f'[{label}] 重试仍被拦截，本页放弃')
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

    resp = _get_sogou_search_page(sess, search_url, f'文章搜索:{account_name}:p{page}')
    if not resp:
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
        sogou_href = str(h3_a.get('href', '') or '')
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
                ts_raw = str(ts_el.get('data-ts', '') or '')
                pub_time = _dt.datetime.fromtimestamp(int(ts_raw)).strftime('%Y-%m-%d')
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
    resp = _get_sogou_search_page(sess, url, f'biz搜索:{account_name}')
    if not resp:
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
            href = str(a.get('href', '') or '')
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

_STRONG_TECH_PATTERNS = [
    r'cve-\d{4}-\d{4,7}',
    r'漏洞|漏洞复现|漏洞分析|利用链|补丁分析',
    r'远程代码执行|任意代码执行|命令执行|提权|越权|越界|目录遍历|反序列化',
    r'sql注入|xss|ssrf|xxe|rce|lfi|rfi|ssti',
    r'poc\b|\bexp\b|exploit|payload|getshell|shellcode',
    r'渗透测试|内网渗透|横向移动|红队|蓝队|应急响应|威胁狩猎',
]

_TECH_HINT_KEYWORDS = [
    '渗透', '漏洞', '利用', '提权', '内网', '绕过', 'web安全', '0day', '0-day',
    'cnnvd', 'cnvd', '高危漏洞', '严重漏洞', '威胁情报', '恶意软件', '勒索', '木马',
    '后门', 'apt', 'c2', 'ctf', '逆向', '二进制', '代码审计', 'nmap', 'burp',
    'metasploit', 'mimikatz', 'sqlmap', '免杀', '攻击链', '复盘', '通告', '预警',
]

_NOISE_TITLE_HINTS = [
    '战略合作', '签署合作', '达成合作', '签约仪式', '发布会', '峰会', '论坛', '大会', '研讨会',
    '招聘', '校招', '内推', '获奖', '荣誉', '周年', '生态合作', '联合声明', '活动报名',
    '直播预告', '课程报名', '产品发布', '品牌升级',
]

_NOISE_CONTENT_HINTS = [
    '签署战略合作协议', '双方经营班子成员', '出席并见证签约仪式', '市场需求的迎合', '业务团队代表',
    '合作伙伴', '品牌影响力', '市场拓展', '生态共建',
]

MIN_CONTENT_LEN = 260


def _normalize_text_for_match(text: str) -> str:
    s = str(text or '').lower().strip()
    if not s:
        return ''
    s = re.sub(r'[\s\u3000]+', '', s)
    s = re.sub(r'[·•,，.。:：;；\-_/\\|()（）\[\]{}<>《》【】\"\'“”‘’`~!！?？]', '', s)
    return s


def _is_tech_relevant(data: dict) -> tuple[bool, str]:
    """
    判断文章是否具备渗透测试/信息安全的技术价值。
    返回 (True, '') 表示通过，返回 (False, 原因) 表示过滤。
    """
    title_raw = str(data.get('title', '') or '')
    content_raw = str(data.get('content', '') or '')
    title = _normalize_text_for_match(title_raw)
    content = _normalize_text_for_match(content_raw)
    full_raw = f'{title_raw}\n{content_raw}'
    clen = len(content_raw)

    # 1. 内容过短
    if clen < MIN_CONTENT_LEN:
        return False, f'正文过短({clen}字<{MIN_CONTENT_LEN})'

    strong_hits = sum(1 for p in _STRONG_TECH_PATTERNS if re.search(p, full_raw, re.IGNORECASE))
    title_strong_hits = sum(1 for p in _STRONG_TECH_PATTERNS if re.search(p, title_raw, re.IGNORECASE))
    hint_hits = sum(1 for kw in _TECH_HINT_KEYWORDS if kw in title or kw in content)

    noise_title_hits = [kw for kw in _NOISE_TITLE_HINTS if kw in title]
    if noise_title_hits and title_strong_hits == 0 and hint_hits < 3:
        return False, f'标题偏宣传({"/".join(noise_title_hits[:2])})'

    noise_content_hits = sum(1 for kw in _NOISE_CONTENT_HINTS if kw in content_raw)
    if noise_content_hits >= 2 and strong_hits == 0 and hint_hits < 4:
        return False, '正文偏商务宣传'

    if title_strong_hits >= 1:
        return True, ''

    if strong_hits >= 1 and hint_hits >= 2:
        return True, ''

    if hint_hits >= 6:
        return True, ''

    return False, f'技术信号不足(强匹配={strong_hits},提示词={hint_hits})'


def _account_matches(actual: str, target: str) -> bool:
    """
    判断文章实际账号名是否与目标搜索账号名匹配。
    支持以下几种情形：
      · 完全一致 / 大小写不同
      · 包含关系（绿盟科技 ∈ 绿盟科技研究院 → 匹配）
      · 英文账号去括号（nu1l team vs nu1l）
    """
    a = _normalize_text_for_match(actual)
    t = _normalize_text_for_match(target)
    if not a:  # 文章页未提取到账号名，放行
        return True
    if a == t:
        return True

    # 去除常见后缀后再做匹配，降低“研究院/实验室/官方号”差异影响。
    suffix_re = r'(官方公众号|公众号|官方|研究院|研究中心|实验室|安全实验室|安全研究院)$'
    a_core = re.sub(suffix_re, '', a)
    t_core = re.sub(suffix_re, '', t)
    if a_core and t_core and a_core == t_core:
        return True

    if min(len(a_core), len(t_core)) >= 3 and (a_core in t_core or t_core in a_core):
        return True

    return False


def _parse_pub_date(raw: str) -> Optional[datetime]:
    """尽量容错地解析公众号发布时间，支持 YYYY-MM-DD / YYYY年MM月DD日 等格式。"""
    s = str(raw or '').strip()
    if not s:
        return None
    s = s.replace('年', '-').replace('月', '-').replace('日', '')
    s = s.replace('/', '-').replace('.', '-')

    m = re.search(r'(\d{4})-(\d{1,2})-(\d{1,2})', s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None

    # 兼容少数页面仅给出 MM-DD 的情况
    m2 = re.search(r'(\d{1,2})-(\d{1,2})', s)
    if m2:
        now = datetime.now()
        try:
            dt = datetime(now.year, int(m2.group(1)), int(m2.group(2)))
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
            return dt
        except ValueError:
            return None

    return None


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


def crawl_account(account_name: str, count: int = 20, days: Optional[int] = None) -> int:
    """爬取指定公众号，返回成功保存的文章数。"""
    day_scope = f'，最近 {days} 天' if days and days > 0 else ''
    log.info(f'=== 开始爬取: {account_name}（目标 {count} 篇{day_scope}）===')
    saved = 0
    cutoff = datetime.now() - timedelta(days=days) if days and days > 0 else None
    # 加载跨会话历史 URL + 标题，避免重复下载（同文章多 Sogou URL 场景）
    seen_urls, seen_titles = _load_seen_keys()
    log.debug(f'已有历史去重 URL {len(seen_urls)} 条，标题 {len(seen_titles)} 条')

    # 每个账号使用独立 Session（含独立 Cookie），确保链接 Token 一致
    sess = _make_session()
    _warmup_sogou_session(sess)

    # ── biz 精确搜索：先用 type=1 查目标账号的唯一 biz，避免混入同品牌账号 ──
    biz = _lookup_account_biz(sess, account_name)
    query_override = f'__biz={biz}' if biz else None
    if query_override:
        log.info(f'使用 biz 精确模式搜索: {query_override[:30]}')
    else:
        log.info('未找到 biz，使用关键词搜索（可能有同品牌账号混入）')

    consecutive_empty = 0
    consecutive_old_pages = 0
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
        page_has_recent = False

        for art in articles:
            if saved >= count:
                break

            if cutoff is not None:
                art_dt = _parse_pub_date(art.get('pub_time', ''))
                if art_dt is not None and art_dt < cutoff:
                    continue
                page_has_recent = True

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

            if cutoff is not None:
                data_dt = _parse_pub_date(data.get('publish_time', ''))
                if data_dt is not None and data_dt < cutoff:
                    log.debug(f'超出时间范围，跳过: {data.get("title", "")[:40]}')
                    time.sleep(random.uniform(1, 2))
                    continue
                if data_dt is None:
                    page_has_recent = True

            # ── 账号过滤：拒绝非目标账号的文章 ────────────────
            actual_account = data.get('account', '')
            if not _account_matches(actual_account, account_name):
                log.warning(f'账号不符（目标={account_name!r} 实际={actual_account!r}），跳过')
                time.sleep(random.uniform(1, 2))
                continue

            # 统一归一到目标账号名，避免别名差异导致 Dashboard 计数与预览不一致。
            data['account_raw'] = actual_account
            data['account'] = account_name

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
        if cutoff is not None:
            if not page_has_recent:
                consecutive_old_pages += 1
            else:
                consecutive_old_pages = 0
            if consecutive_old_pages >= 2:
                log.info('连续 2 页未命中时间范围，提前停止翻页')
                break

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
    parser.add_argument('--days', type=int, default=0, help='仅抓取最近 N 天内容（0 表示不限）')
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
    days = args.days if args.days > 0 else None
    for acct in accounts:
        n = crawl_account(acct, args.count, days=days)
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

