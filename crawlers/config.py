# crawlers/config.py

# =======通用配置=====================================================================================

# 启用/禁用数据源
ENABLED_SOURCES = {
    'csdn': True,
    'github': True,
    'qianxin': True,  # 奇安信攻防社区
    'xianzhi': True,   # 先知安全技术社区
    'wechat': True,   # 微信公众号（搜狗模式）
    'rss': True,      # RSS Feed 轻量级增量爬虫
}

# =======CSDNVIP爬虫配置=====================================================================================
USE_VIP = True  # 改为True启用VIP模式

# Cookie方式（推荐）
# 获取方法：
# 1. 登录CSDN -> F12开发者工具 -> Application -> Cookies
# 2. 复制完整cookie字符串
CSDN_COOKIE = os.environ.get('CSDN_COOKIE', 'xxx')  # 已脱敏：请使用环境变量或本地 secrets 文件注入真实 cookie，勿提交仓库

# 用户名密码方式
CSDN_USERNAME = "2401_83492391"  # 你的CSDN用户名
CSDN_PASSWORD = ""  # 你的CSDN密码

REQUEST_TIMEOUT = 15 # 请求超时时间（秒）

CRAWL_DELAY = 3 # 文章间爬取延时（秒）

MAX_RETRIES = 3 # 最大重试次数

# 自定义User-Agent
CUSTOM_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# VIP内容检测关键词（微调：添加登录墙提示）
VIP_KEYWORDS = [
    'vip专享', '会员专享', '付费内容', 
    '仅限会员', 'vip用户', '订阅用户',
    '高级会员', '付费用户',
    '前往CSDN APP', '登录即可继续', 'APP阅读全文'  # 新增：覆盖登录墙
]

# VIP内容CSS选择器（微调：添加登录提示选择器）
VIP_SELECTORS = [
    '.vip-article',
    '.paid-article', 
    '.member-article',
    '[data-type="vip"]',
    '.article-bar-vip',
    '.vip-tag',
    '.app-login-prompt', '.paywall-notice'  # 新增
]

# 内容提取CSS选择器优先级
CONTENT_SELECTORS = [
    '#article_content',        # 主要内容区域
    '.article-content',        # 备选内容区域  
    '.markdown_views',         # Markdown文章
    '.htmledit_views',         # HTML编辑器文章
    'article',                 # 通用文章标签
    '.blog-content-box',       # 博客内容盒子
    '.content',                # 通用内容
    '.post-content',           # 文章内容
    '.entry-content'           # 条目内容
]

# 需要清理的HTML元素
UNWANTED_SELECTORS = [
    'script', 'style', 'nav', 'aside', 
    '.recommend-box', '.comment-box', 
    '.ad-container', '.sidebar',
    '.footer', '.header-nav'
]

OUTPUT_BASE_DIR = 'raw_data'

GITHUB_ENTERPRISE_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
ATTCK_BASE_URL = 'https://attack.mitre.org'
ATTCK_CRAWL_LIMIT = 20
ATTCK_REQUEST_DELAY = 2
ENABLE_PDF_DOWNLOAD = True
PDF_MAX_SIZE_MB = 50
GITHUB_TOKEN = ''
GITHUB_MAX_ISSUES = 50
GITHUB_MAX_REPOS = 30
GITHUB_REQUEST_DELAY = 1

# =======奇安信攻防社区配置=====================================================================================
QIANXIN_RSS_URL = 'https://forum.butian.net/Rss'
QIANXIN_TIME_RANGE_HOURS = 24  # 默认获取最近24小时的文章

# =======先知安全技术社区配置=====================================================================================
XIANZHI_RSS_URL = 'https://xz.aliyun.com/feed'

# =======RAGFlow 联动配置=====================================================================================
# RAGFlow 配置：优先从环境变量读取，避免在仓库中出现明文凭据
RAGFLOW_API_KEY = os.environ.get('RAGFLOW_API_KEY', 'xxx')
RAGFLOW_BASE_URL = os.environ.get('RAGFLOW_BASE_URL', 'http://60.205.197.71')
RAGFLOW_DATASET_ID = os.environ.get('RAGFLOW_DATASET_ID', 'xxx')
# 建议：在生产环境使用环境变量注入 `RAGFLOW_API_KEY`/`RAGFLOW_DATASET_ID`，避免明文出现在仓库中。
# RAGFlow 暂不可用，数据保存到 raw_data/
PUSH_TO_RAGFLOW = False
RAGFLOW_ONLY = False

# =======RSS Feed 配置=============================================================================
# 各安全社区的 RSS/Atom Feed URL
# key = feed 短名（同时作为 raw_data/ 下的存储子目录名）
# 注意：xianzhi/qianxin 已有独立的深度爬虫类，这里是统一的轻量级 RSS-only 入口
RSS_FEEDS: dict[str, str] = {
    "xianzhi":   "https://xz.aliyun.com/feed",        # 先知安全技术社区
    "butian":    "https://forum.butian.net/Rss",       # 奇安信攻防社区
}

# RSS 轮询间隔（小时）
RSS_POLL_INTERVAL_HOURS: float = 2.0

# 单次最多返回条目数
RSS_MAX_ITEMS_PER_FEED: int = 50
