# wechat_article_crawler/config.py

# 微信公众号爬虫配置
# 获取方法：
# 1. 在电脑端登录微信。
# 2. 使用抓包工具（如 Fiddler、Charles 或 Wireshark）或者通过开发者模式。
# 3. 点击进入某个公众号的历史消息列表。
# 4. 在抓包工具中找到请求：mp.weixin.qq.com/mp/profile_ext?action=getmsg...
# 5. 从该请求的 Header 和 URL 参数中提取以下信息。

WECHAT_CONFIG = {
    'COOKIE': '',        # 从 Header 中获取完整的 Cookie 字符串
    'X_WECHAT_KEY': '',  # 从 Header 中获取 x-wechat-key
    'X_WECHAT_UIN': '',  # 从 Header 中获取 x-wechat-uin
    'EXPORTKEY': '',     # 从 Header 中获取 exportkey
    'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'PASS_TICKET': '',   # 从 URL 参数中获取 pass_ticket
    'BIZ': ''            # 从 URL 参数中获取 __biz (公众号唯一标识)
}

# 爬取设置
WECHAT_MAX_PAGES = 5      # 默认爬取页数
WECHAT_CRAWL_DELAY = 5    # 文章爬取间隔（秒）
