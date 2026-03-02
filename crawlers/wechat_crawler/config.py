# wechat_article_crawler/config.py
#
# 微信公众号爬虫支持两种模式：
# ── 工业化扩展（Phase 1-2）──────────────────────────────────────────
#   配置了 Redis 连接、风控限速参数、Worker 标识，供 Celery 任务与
#   interceptor 风控增强模块读取。可通过环境变量覆盖。
#
# ── 模式 A：直接 HTTP API（需要有效 Cookie/Key）──────────────────────────
# 获取方法：
#   1. 在电脑端登录微信，打开某公众号历史消息列表。
#   2. 用抓包工具捕获 mp.weixin.qq.com/mp/profile_ext?action=getmsg 请求。
#   3. 从 Header 和 URL 参数提取下方字段。
# 缺点：Cookie/Key 有效期短（约 2 天），需要频繁手动更新。
#
# ── 模式 B：MITM 代理 + UI 自动化（推荐，免 Cookie 维护）───────────────
# 原理："让 UI 自动化做苦力（点文章），让 mitmproxy 做大脑（截获数据）"
# 使用方法：
#   1. 配置系统代理为 127.0.0.1:8080（见 SETUP.md）
#   2. mitmdump -s interceptor.py          # 启动拦截器
#   3. python ui_bot.py                    # 启动 UI 自动化
# 优点：流量原生，永不失效，无需维护 Cookie。

import os
from pathlib import Path
# sqlite3 是 Python 内置模块，无需 pip install

# ── 模式 A 配置 ────────────────────────────────────────────────────────────
WECHAT_CONFIG = {
    'COOKIE': '',        # 从 Header 中获取完整的 Cookie 字符串
    'X_WECHAT_KEY': '',  # 从 Header 中获取 x-wechat-key
    'X_WECHAT_UIN': '',  # 从 Header 中获取 x-wechat-uin
    'EXPORTKEY': '',     # 从 Header 中获取 exportkey
    'USER_AGENT': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'PASS_TICKET': '',   # 从 URL 参数中获取 pass_ticket
    'BIZ': ''            # 从 URL 参数中获取 __biz (公众号唯一标识)
}

# 模式 A 爬取参数
WECHAT_MAX_PAGES   = 5    # 默认爬取页数（每页 10 篇）
WECHAT_CRAWL_DELAY = 5    # 文章请求间隔（秒）

# ── 模式 B 配置（MITM + UI 自动化）────────────────────────────────────────
# 注意：此版本不依赖 Redis / Docker，冷却通知通过本地文件实现。
_BASE = Path(__file__).parent

MITM_CONFIG = {
    # ── 代理设置 ──
    'PROXY_HOST': '127.0.0.1',
    'PROXY_PORT': 8080,

    # ── 数据落地目录（与 raw_data/wechat/ 保持一致）──
    'SAVE_DIR': str(_BASE.parent.parent.parent / 'raw_data' / 'wechat'),

    # ── 拦截器与 UI Bot 通信的队列文件 ──
    # interceptor.py 写入，crawler.py / ui_bot.py 读取。
    'QUEUE_FILE': str(_BASE / 'captured_queue.jsonl'),

    # ── 去重记录文件 ──
    'SEEN_URLS_FILE': str(_BASE / 'seen_urls.txt'),

    # ── 需要自动浏览的公众号名称列表 ──
    # 留空则只浏览当前已打开的订阅号消息流（"订阅号消息"入口）。
    'TARGET_ACCOUNTS': [
        # 示例，按需填写：
        # '嘶吼',
        # '安全内参',
        # '绿盟科技',
        # 'FreeBuf',
    ],

    # ── 每个公众号的目标抓取文章数 ──
    'ARTICLES_PER_ACCOUNT': 30,

    # ── 点击文章后等待 mitmproxy 捕获完整响应的秒数 ──
    'CLICK_WAIT_SECONDS': 5,

    # ── 批次间隔（秒），避免过快操作被检测 ──
    # 注意：ui_bot.py 在运行时会使用 random.uniform(3, 7) 替代此固定值
    'BATCH_SLEEP_SECONDS': 2,

    # ── 风控限速参数 ─────────────────────────────────────────────────────────
    'RATE_LIMIT': {
        'MAX_PER_DAY':                  120,   # 单 Session 安全日上限
        'MAX_PER_DAY_WARNING':          150,   # 超出此值进入黄色预警区间
        'MAX_PER_HOUR':                 30,    # 单小时峰值，超出自动进入冷却
        'MAX_CONSECUTIVE_SAME_ACCOUNT': 20,    # 同一账号连续爬取篇数上限
        'COOLDOWN_SECONDS':             300,   # 触发风控后冷却时间（秒）
    },

    # ── 活跃时间窗口（仅在此区间内调度爬取，模拟人工使用习惯）────────────
    'ACTIVE_HOURS': (0, 24),  # 全天活跃（个人手动运行，不限时间段）

    # ── 冷却标志文件路径（由 interceptor.py 写入，scheduler.py 读取）──────
    # 无需 Redis，直接用文件信号跨进程通信
    'COOLDOWN_FLAG': str(_BASE / 'cooldown.flag'),
}
