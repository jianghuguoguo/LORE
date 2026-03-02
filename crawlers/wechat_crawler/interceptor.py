"""
wechat_article_crawler/interceptor.py
======================================
mitmproxy 流量拦截插件（"大脑"）

用法（从任意目录）：
    mitmdump -s path/to/interceptor.py
    # 或在 wechat_article_crawler/ 目录下：
    mitmdump -s interceptor.py

职责：
  - 监听 mp.weixin.qq.com/s 的 HTTPS 响应
  - 提取文章标题、作者、公众号名、正文、发布时间、URL
  - 写入队列文件（captured_queue.jsonl）供 crawler.py / ui_bot.py 消费
  - 同时存入 raw_data/wechat/ 目录，与爬虫输出格式对齐
  - 基于 URL 去重，避免重复保存
Phase 1 增强（工业化）：
  ★ 风控检测 —— _is_rate_limited() 识别 403 / 环境异常 / verify 页
  ★ 完整性评分 —— _check_completeness() 返回 0–1 分数
  ★ 冷却通知 —— _notify_cooldown() 写入 cooldown.flag 文件，供 scheduler.py 检测"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup
from mitmproxy import http

# ── 路径配置（interceptor 在 mitmproxy 进程中运行，需要自己定位配置）────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE.parent.parent))  # RefPenTest/ 入 sys.path，使 crawlers.* 可导入
sys.path.insert(0, str(_HERE))               # wechat_article_crawler/ 自身，用于直接 import config

from config import MITM_CONFIG  # 直接从同目录导入，避免触发 crawlers/__init__.py 的连锁导入

# ── 日志 ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('wechat_interceptor')

# ── 目录与文件初始化 ─────────────────────────────────────────────────────────
SAVE_DIR       = Path(MITM_CONFIG['SAVE_DIR'])
QUEUE_FILE     = Path(MITM_CONFIG['QUEUE_FILE'])
SEEN_URLS_FILE = Path(MITM_CONFIG['SEEN_URLS_FILE'])

SAVE_DIR.mkdir(parents=True, exist_ok=True)
QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── 内存级 URL 去重集合（启动时从文件加载历史记录）────────────────────────
_seen_lock: threading.Lock = threading.Lock()
_seen_urls: set[str] = set()

if SEEN_URLS_FILE.exists():
    _seen_urls = set(SEEN_URLS_FILE.read_text(encoding='utf-8').splitlines())
    log.info(f'已加载 {len(_seen_urls)} 条历史 URL 去重记录')


# ── 工具函数 ─────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """提取 URL 中稳定的文章标识部分（__biz + mid + idx + sn），用于去重。"""
    parts = {}
    for key in ('__biz', 'mid', 'idx', 'sn'):
        m = re.search(rf'[?&]{key}=([^&]+)', url)
        if m:
            parts[key] = m.group(1)
    if parts:
        return '|'.join(f"{k}={v}" for k, v in sorted(parts.items()))
    return url.split('?')[0]


def _safe_filename(title: str, max_len: int = 80) -> str:
    """将标题净化为合法文件名。"""
    name = re.sub(r'[\\/:*?"<>|\r\n\t]', '_', title).strip()
    return name[:max_len] or 'untitled'


def _extract_publish_time(html: str) -> str:
    """从微信文章 HTML 提取发布时间（多策略兜底）。"""
    # 策略 1：var ct = "Unix 时间戳"
    m = re.search(r'var\s+ct\s*=\s*["\'](\d{10})["\']', html)
    if m:
        return datetime.fromtimestamp(int(m.group(1))).strftime('%Y-%m-%d %H:%M:%S')
    # 策略 2：var modify_time = "Unix 时间戳"
    m = re.search(r'var\s+modify_time\s*=\s*["\'](\d{10})["\']', html)
    if m:
        return datetime.fromtimestamp(int(m.group(1))).strftime('%Y-%m-%d %H:%M:%S')
    # 策略 3：publish_time 字符串
    m = re.search(r'var\s+publish_time\s*=\s*["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
    # 策略 4：<em id="publish_time">
    m = re.search(r'<em[^>]*id=["\']publish_time["\'][^>]*>([^<]+)</em>', html)
    if m:
        return m.group(1).strip()
    return ''


def _extract_account_name(soup: BeautifulSoup, html: str) -> str:
    """提取公众号名称（多策略兜底）。"""
    # 策略 1：<strong class="profile_nickname">
    tag = soup.find('strong', class_='profile_nickname')
    if tag:
        return tag.get_text(strip=True)
    # 策略 2：nickname JS 变量
    m = re.search(r'var\s+nickname\s*=\s*["\']([^"\']+)["\']', html)
    if m:
        return m.group(1)
    # 策略 3：<span class="wx_follow_nickname">
    tag = soup.find('span', class_='wx_follow_nickname')
    if tag:
        return tag.get_text(strip=True)
    return ''


def _extract_content_markdown(content_div) -> str:
    """
    将 rich_media_content 转为可读文本，尽量保留代码块结构
    （对渗透测试 RAG 语料尤其重要）。
    """
    if content_div is None:
        return ''

    lines: list[str] = []
    for elem in content_div.descendants:
        # 代码块：<pre> 或 <code>
        if elem.name in ('pre', 'code') and not elem.find_parent(['pre', 'code'], recursive=False):
            code_text = elem.get_text('\n', strip=False).rstrip()
            if code_text.strip():
                lines.append('```')
                lines.append(code_text)
                lines.append('```')
        # 段落 / 标题
        elif elem.name in ('p', 'h1', 'h2', 'h3', 'h4', 'li'):
            # Bug3 修复：li 包含 <p> 子元素时跳过自身，内容由子级 <p> 负责输出，避免重复
            if elem.name == 'li' and elem.find('p'):
                continue
            text = elem.get_text(' ', strip=True)
            if text:
                lines.append(text)
        # Bug4 修复：section/div 直接包裹文本时（不含任何块级子元素）进行兼容
        elif elem.name in ('section', 'div'):
            _BLOCK = ('p', 'h1', 'h2', 'h3', 'h4', 'li', 'section', 'div', 'pre', 'code', 'table')
            if not elem.find(_BLOCK):
                text = elem.get_text(' ', strip=True)
                if text:
                    lines.append(text)
        # 图片 alt 文本（保留图片描述）
        elif elem.name == 'img':
            alt = elem.get('alt', '').strip()
            if alt:
                lines.append(f'[图片: {alt}]')

    # 去除连续空行
    result_lines: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        result_lines.append(line)
        prev_blank = is_blank

    return '\n'.join(result_lines).strip()


def _parse_wechat_article(url: str, html: str) -> Optional[dict]:
    """
    解析微信文章 HTML，返回结构化数据字典。
    失败时返回 None。
    """
    try:
        soup = BeautifulSoup(html, 'html.parser')

        # ── 标题 ──
        title_tag = (
            soup.find('h1', id='activity-name')
            or soup.find('h1', class_='rich_media_title')
            or soup.find('h1')
        )
        title = title_tag.get_text(strip=True) if title_tag else ''
        if not title:
            # 从 JS 变量兜底
            m = re.search(r'var\s+msg_title\s*=\s*["\']([^"\']+)["\']', html)
            title = m.group(1) if m else 'Untitled'

        # ── 作者 ──
        author_tag = soup.find('span', class_='rich_media_meta_text')
        author = author_tag.get_text(strip=True) if author_tag else ''

        # ── 公众号名称 ──
        account = _extract_account_name(soup, html)

        # ── 发布时间 ──
        publish_time = _extract_publish_time(html)

        # ── 正文 ──
        content_div = (
            soup.find('div', id='js_content')
            or soup.find('div', class_='rich_media_content')
        )
        content = _extract_content_markdown(content_div)

        if not content:
            log.warning(f'正文为空，跳过: {url[:80]}')
            return None

        return {
            'title':        title,
            'author':       author,
            'account':      account,
            'publish_time': publish_time,
            'url':          url,
            'content':      content,
            'site':         'wechat',
            'captured_at':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    except Exception as e:
        log.error(f'解析文章异常：{e}  url={url[:80]}')
        return None


def _save_article(article: dict) -> None:
    """
    将文章写入：
    1. raw_data/wechat/<safe_title>.json（与其他爬虫格式对齐）
    2. captured_queue.jsonl（供 crawler.py 消费）
    """
    safe = _safe_filename(article['title'])
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = SAVE_DIR / f'wechat_{safe}_{ts}.json'

    try:
        out_path.write_text(json.dumps(article, ensure_ascii=False, indent=2), encoding='utf-8')
        log.info(f'[SAVED] {out_path.name}')
    except OSError as e:
        log.error(f'文件写入失败: {e}')

    # 追加到队列文件（ui_bot / crawler 轮询读取）
    try:
        with open(QUEUE_FILE, 'a', encoding='utf-8') as fq:
            fq.write(json.dumps(article, ensure_ascii=False) + '\n')
    except OSError as e:
        log.error(f'队列写入失败: {e}')


def _mark_seen(url_key: str) -> None:
    """更新内存去重集合并持久化到文件。"""
    with _seen_lock:
        _seen_urls.add(url_key)
        try:
            with open(SEEN_URLS_FILE, 'a', encoding='utf-8') as f:
                f.write(url_key + '\n')
        except OSError:
            pass


# ── mitmproxy Addon 类 ───────────────────────────────────────────────────────

class WeChatInterceptor:
    """
    mitmproxy 插件主类。每个 HTTP 响应都会触发 response() 方法。

    Phase 1 新增能力：
      ● 风控检测：识别 403 / 环境异常 / verify 页面，触发冷却
      ● 完整性评分：为每篇文章计算 0-1 的质量分，写入 JSON
      ● Redis pub/sub：冷却事件广播给所有订阅了 wechat:cooldown 的 Celery Worker
    """

    # ── 风控关键词 ────────────────────────────────────────────────────────────
    _RATE_LIMIT_KEYWORDS = [
        '环境异常',
        'verify',
        '访问受限',
        '请完成验证',
        '操作太频繁',
        'RetCode:-1',          # 微信 JSON 错误码
        'RetCode:-2',
        # 注意：'该内容已被发布者删除' 已移出，改为在 response() 单独处理（Bug5 修复）
    ]

    # 文章已删除标识（内容状态，不是风控）
    _DELETED_KEYWORD = '该内容已被发布者删除'

    # cooldown.flag 路径（与 scheduler.py 中的 _COOLDOWN_FLAG 一致）
    _COOLDOWN_FLAG: Path = Path(__file__).parent / 'cooldown.flag'

    def __init__(self) -> None:
        pass  # 无需初始化任何外部连接

    # ── 核心响应处理 ──────────────────────────────────────────────────────────

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url

        # ── 过滤条件：只处理微信公众号文章正文请求 ──────────────────────────
        # 典型 URL：https://mp.weixin.qq.com/s?__biz=...&mid=...
        # 或短链：  https://mp.weixin.qq.com/s/xxxxxxx
        if 'mp.weixin.qq.com' not in url:
            return
        if '/s?' not in url and '/s/' not in url:
            return
        # 排除非 HTML 响应（图片、CSS 等）
        ct = flow.response.headers.get('content-type', '')
        if 'text/html' not in ct:
            return

        # ── ★ Phase 1 新增：风控检测（在去重之前，对所有命中 URL 检测）────────
        if self._is_rate_limited(flow):
            log.warning(f'[RATE_LIMIT] 检测到频率限制或异常响应，触发冷却通知')
            self._notify_cooldown()
            return

        # Bug5 修复：文章已删除属于内容状态，不是风控，单独记录后跳过
        try:
            body_preview = flow.response.get_text(strict=False)[:300]
        except Exception:
            body_preview = ''
        if self._DELETED_KEYWORD in body_preview:
            log.info(f'[内容已删除] 作者已删除该文章，跳过: {url[:80]}')
            return

        # 排除错误页面（非风控场景）
        if flow.response.status_code != 200:
            return

        # ── 去重检查 ────────────────────────────────────────────────────────
        url_key = _normalize_url(url)
        with _seen_lock:
            if url_key in _seen_urls:
                log.debug(f'[DUP] 已爬取，跳过: {url[:60]}')
                return

        log.info(f'[+] 捕获: {url[:80]}')

        # ── 解码响应正文 ────────────────────────────────────────────────────
        try:
            html = flow.response.get_text(strict=False)
        except Exception as e:
            log.error(f'解码响应失败: {e}')
            return

        # 快速检测是否为有效文章页面（避免解析错误页、验证页等）
        if 'rich_media_title' not in html and 'js_content' not in html:
            log.debug(f'[SKIP] 非文章正文页: {url[:60]}')
            return

        # ── 解析 ────────────────────────────────────────────────────────────
        article = _parse_wechat_article(url, html)
        if article is None:
            return

        # ── ★ Phase 1 新增：完整性评分 ───────────────────────────────────────
        completeness = self._check_completeness(article)
        article['completeness_score'] = round(completeness, 3)
        if completeness < 0.3:
            log.warning(f'[LOW_QUALITY] 完整性得分过低 ({completeness:.2f})，'
                        f'仍保存但已标记: {article["title"][:50]}')

        # ── 保存 + 记录已见 ─────────────────────────────────────────────────
        _save_article(article)
        _mark_seen(url_key)
        print(f'[SUCCESS] 已保存 (score={completeness:.2f}): {article["title"][:60]}')

    # ── ★ Phase 1 新增方法 ─────────────────────────────────────────────────────

    def _is_rate_limited(self, flow: http.HTTPFlow) -> bool:
        """
        检测微信返回的频率限制或风控标志。

        检测维度：
          1. HTTP 403 状态码
          2. 响应体中的风控关键词
          3. 重定向目标含 /mp/verify 等验证路径
        """
        # 维度 1：HTTP 状态码
        if flow.response.status_code == 403:
            return True

        # 维度 2：响应体关键词（取前 2000 字节，避免全文扫描）
        try:
            body_snippet = flow.response.get_text(strict=False)[:2000]
        except Exception:
            return False

        if any(kw in body_snippet for kw in self._RATE_LIMIT_KEYWORDS):
            return True

        # 维度 3：重定向含 verify
        location = flow.response.headers.get('location', '')
        if 'verify' in location.lower() or 'security/captcha' in location.lower():
            return True

        return False

    def _check_completeness(self, article: dict) -> float:
        """
        评估文章完整性得分（0.0 ~ 1.0）。

        评分权重（总计 1.0）：
          标题存在      +0.20
          正文存在      +0.30
          发布时间存在  +0.10
          账号名存在    +0.10
          正文 > 500字  +0.15
          正文 > 2000字 +0.15
        """
        score = 0.0
        if article.get('title'):
            score += 0.20
        if article.get('content'):
            score += 0.30
        if article.get('publish_time'):
            score += 0.10
        if article.get('account'):
            score += 0.10
        content_len = len(article.get('content', ''))
        if content_len > 500:
            score += 0.15
        if content_len > 2000:
            score += 0.15
        return min(score, 1.0)

    def _notify_cooldown(self) -> None:
        """
        写入 cooldown.flag 文件通知 scheduler.py 暂停爬取。
        scheduler.py 检测到该文件后会删除并等待冷却时间。
        （取代原 Redis pub/sub 方案，零外部依赖）
        """
        try:
            self._COOLDOWN_FLAG.parent.mkdir(parents=True, exist_ok=True)
            self._COOLDOWN_FLAG.write_text(
                json.dumps({'timestamp': time.time()}), encoding='utf-8'
            )
            log.info(f'[COOLDOWN] 已写入冷却标志: {self._COOLDOWN_FLAG}')
        except Exception as e:
            log.error(f'[COOLDOWN] 写入冷却标志失败: {e}')


# ── mitmproxy addon 入口（必须）────────────────────────────────────────────
addons = [WeChatInterceptor()]
