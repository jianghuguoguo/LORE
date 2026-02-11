# crawlers/config.py

# =======通用配置=====================================================================================

# 启用/禁用数据源
ENABLED_SOURCES = {
    'csdn': True,
    'attack': True,
    'github': True,
    'qianxin': True,  # 奇安信攻防社区
    'xianzhi': True,   # 先知安全技术社区
    'wechat': True    # 微信公众号
}

# =======CSDNVIP爬虫配置=====================================================================================
USE_VIP = True  # 改为True启用VIP模式

# Cookie方式（推荐）
# 获取方法：
# 1. 登录CSDN -> F12开发者工具 -> Application -> Cookies
# 2. 复制完整cookie字符串
CSDN_COOKIE = 'UN=2401_83492391; fid=20_22541528309-1725602930753-605223; Hm_lvt_ec8a58cd84a81850bcbd95ef89524721=1731914214,1732167556,1732502243,1732769678; uuid_tt_dd=10_37234250780-1736165333582-211579; Hm_ct_6bcd52f51e9b3dce32bec4a3997715ac=6525*1*10_37234250780-1736165333582-211579!5744*1*2401_83492391; ssxmod_itna=eqfx9DgDuiGQwxBPGIrCDUO+xBnQke7D0QPEGCx0HreGzDAxn40iDtPoN2=KcQ9G0Yt7WoW2PbP5QR0ReYWhA+fraXex0aDbqGk38Cr4GGjxBYDQxAYDGDDPDocPD1D3qDkD7h6CMy1qGWDm4sDYyFDQHGe4DFc2IOP4i7DD5Qkx07Y/9YDGyYGtR77Q9Ye4Drka717tv4vt0DjxG1Y40He7MYjrg6gtRzv/8j4f+ODl92DC91N35IDBRkZhvG/Qh3=7bN=0ree0+4q02WwADYHQhxCCtMePxoKnDKsW4FZ72YDDp4zwXDD=; ssxmod_itna2=eqfx9DgDuiGQwxBPGIrCDUO+xBnQke7D0QPEGDnFSG+4Ds3wCDLiQriy4yQrqnbwrSRQSP+8V0AiHwHK8DWhx17zcwgXxTKFBcGrOo0eRyr7DUr5+7YD4r5hHTlEp8gxUV1y8dGrdTXxf3K8SRfhYuGH/25/7eU6Yl54RgwovBty3L2h9nfKOSUPc3vqhlXBRDRmUr5tGe6KZhudVhq8oaYxynDg8Qf5Ax9siE31QS5eCL+HOmG8mr5b5lnxxCrIvtIhDn3bzLIa5A5EYLNQma62hLBUKoPDKuYDFqD2KrD=; tfstk=gx5xxt4c_uqcg_5vrZyoInw__J4uq8bqNi7IshxmCgIRYgoDIGAD6FKRbjfGSN6t6w-PsnccSPIOjMtjo-7iXRTM5hi6GK_SPFLtCAt16TlO8N50uC42gZRw1kq3tCQVuClvrgm8qaa67CLjY9rBnZRw1uDsV4oCui--Vhs61zdWWFm61K9XFzLHJCGXCjMSV3-W1j96ha9WuelX5js1PzLwVhO61GO7yFlrmPxSQhGOLzr0nx0BMfG1wEp7EZtSvKfJkItClsHnKvTvHH_X2kVFrGp57dCZ7fpGl9SwRiibXh5RPs6CAuDDc9LO-OIQSx8kBsRJfsNEJ31AW_pVEmMXJIKvdssS8ybJCTCJisZZLabJcpdlE8rDIIIALHJbUuSOynj1MLiYqhXhrs9RAucRbdB1iQ1bVWIzg6fdxfmHvFDbyzHZQKTyLUj6PBqn5lLJxreiQAJudUK3yzHZQKTyyH4l9AkwEJ1..; UserName=2401_83492391; UserNick=2401_83492391; AU=89F; BT=1753348524051; p_uid=U010000; csdn_newcert_2401_83492391=1; c_ab_test=1; Hm_lvt_e5ef47b9f471504959267fd614d579cd=1758423522; historyList-new=%5B%5D; _tea_utm_cache_20010639={%22utm_medium%22:%22distribute.pc_search_result.none-task-blog-2~all~top_click~default-1-143143793-null-null.142^v102^pc_search_result_base7%22%2C%22utm_term%22:%22resource%20hacker%22}; c_dl_prid=1759115411006_682557; c_dl_rid=1759291690367_260354; c_dl_fref=https://blog.csdn.net/abel_big_xu/article/details/125381650; c_dl_fpage=/download/sd_wfwk/10895550; c_dl_um=-; __gads=ID=48aa52ac718885c2:T=1730723115:RT=1759383754:S=ALNI_MZYaIBxec261WIiUaX8tyLFtr8BZg; __gpi=UID=00000f5740c75700:T=1730723115:RT=1759383754:S=ALNI_MY_o99qx4JUGY-VIByQ68X6uaouXg; __eoi=ID=d700b80ddd2e7e07:T=1757564835:RT=1759383754:S=AA-AfjYIWcETOFGZWTP0Xn6dMNWJ; FCNEC=%5B%5B%22AKsRol-DADSORYCoHTTdOTETdZEMQ9zir9S9-PuQFGKZE4yR3TXGDUcijwSxeAVmblRUE5CQ33zsgYWLWkLLUW5dcKT4Aw89d18AxP9l5KQT0n6f29yQfBPm3sDWY9wAcVfqMB4Ko6-PJGYKsimi0RW6_DOuuS3uRg%3D%3D%22%5D%5D; c_segment=11; dc_sid=bae4a2811437a376ec6a20eaac26d3af; Hm_lvt_6bcd52f51e9b3dce32bec4a3997715ac=1759305644,1759369333,1759383619,1759462663; HMACCOUNT=AE9D3D659B760ED3; _clck=11jh1gi%5E2%5Efzu%5E0%5E1548; c_first_ref=www.bing.com; creative_btn_mp=3; dc_session_id=10_1759468750051.728562; c_utm_source=cknow_so_nontop_query; fe_request_id=1759468763330_9275_8715801; c_first_page=https%3A//blog.csdn.net/cxk19980802/article/details/144970953; c_dsid=11_1759471023697.758469; log_Id_click=25; c_pref=https%3A//blog.csdn.net/2401_83492391%3Ftype%3Dblog; c_ref=https%3A//blog.csdn.net/cxk19980802/article/details/144970953; c_page_id=default; log_Id_pv=17; bc_bot_session=17594725932fcc109f5ff76843; Hm_lpvt_6bcd52f51e9b3dce32bec4a3997715ac=1759472600; bc_bot_token=10017594725932fcc109f5ff76843bac117; bc_bot_rules=-; bc_bot_score=100; bc_bot_fp=b322f1b8540039b20c875a32f071a7d4; log_Id_view=352; _clsk=1sv2up5%5E1759472600793%5E4%5E0%5Ei.clarity.ms%2Fcollect; dc_tos=t3jlrs'

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
RAGFLOW_API_KEY = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
RAGFLOW_BASE_URL = "http://60.205.197.71"
RAGFLOW_DATASET_ID = "1144627c05c911f197890242ac140003"
# 是否推送到 RAGFlow
PUSH_TO_RAGFLOW = True
# 是否在推送到 RAGFlow 后不保存本地文件 (设置为 True 符合用户 "而不是 raw_data" 的要求)
RAGFLOW_ONLY = True
