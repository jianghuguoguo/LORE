# RefPenTest 中文渗透语料核心爬虫框架
> 文档版本：v1.0.0 · 适用对象：开发与维护人员、数据分析师

RefPenTest 提供了一套高可用、可扩展、分布式的多源语料采集系统。整个爬虫模块完全模块化拆分，以适应多变的反爬策略和异构网页结构。本框架支持 **“三大核心来源”** 以及工业级 **“微信原生数据收集矩阵”**。

---

## 1. 爬虫模块架构设计（工业化标准）

本爬虫系统基于标准的**高可用爬虫设计模式**，所有数据源统一受控于调度中心，保证了高健壮性和极强的水平扩展性。

### 1.1 核心特性
- **面向接口编程抽象 (`BaseCrawler`)**：对核心功能（如 `crawl`、HTTP 会话维持、随机 UserAgent 伪装、请求回退）进行抽象，保证新增任何数据源只需继承基类实现 `crawl()` 与 `get_source_name()` 函数即可。
- **并发调度器引擎 (`crawler_manager.py`)**：统一管理并发、容错及插件加载，内部维护了状态与异常计数。
- **进度与状态持久化**：不依赖庞大的 Redis，采用轻量级 SQLite (`crawl_state.db`) 或状态文件 (`rss_state.json`, `seed_accounts.yaml`) 等方式存储增量拉取断点与进度，避免爬虫异常宕机产生大量重复及脏数据。
- **动态代理与限速**：支持动态梯子节点（全局 `7890` 托管），并内置请求退避（Exponential Backoff，`time.sleep(2 ** attempt)`），降低封禁频次。
- **非侵入式去重设计**：爬取时即通过 `id` 或持久化的链接记录进行 O(1) 速查去重，节省计算资源。

---

## 2. 爬虫系统的三大数据核心来源

数据收集系统覆盖了渗透测试中能够汲取安全见解的三大核心媒介。

### 来源一：安全技术社区 与 技术论坛 论坛
技术社区是首杀或者高质量技术剖析的首发地。
- **CSDN VIP 爬虫 (`csdn_crawler.py`)**：基于完整 Cookie 接管或者内部账号越权。突破 VIP 和登录墙墙限制，精准使用正则及 CSS 选择器清洗代码块及付费内容区域。
- **奇安信攻防社区 (`qianxin_crawler.py`) & 先知技术社区 (`xianzhi_crawler.py`)**：以 RSS 触发与深度 HTML 清洗组合拉取模式获取最近 24 小时或全周期的攻防分享。
- **泛阅读同步 (`rss_crawler.py` & `rss_scheduler.py`)**：配合 APScheduler 实现阻塞增量同步。涵盖 FreeBuf、安全客、绿盟科技、嘶吼等主流平台的最新动态。

### 来源二：代码托管与开源情报平台 (GitHub Issue & Repos)
渗透漏洞经常以代码或 Issue 形式存在于各类开源代码管理平台。
- **GitHub Crawler (`github_crawler.py`)**：基于 GitHub REST API 进行精准调用与 Token 认证（大幅提升 Rate Limit）。可自动通过 `vulnerability`, `exploit`, `security` 等组合后缀拉取 CVE 代码复现以及 issue 冲突。
- 动态获取 11 项内置外部重大知识库同步机制 (`sync_data_light.py`) 补充开源情报与标准基础定义资源（涵盖 MITRE ATT&CK、CVE, NVD 等数据），实现结构化漏洞图谱建设。

### 来源三：微信生态高质量沉淀（安全圈私域生态）
绝大多数红队实战技术与 0day 均以微信公众文章进行病毒式传递，这也是 RefPenTest 最重型的语料爬虫堡垒。详见第 3 章节。

---

## 3. 护城河：微信公众号文章爬取闭环系统

为了解决微信平台极其严苛的反机器人策略，微信模块 (`wechat_crawler`) 采用**“双轨爬取”+“三路发现”**模式。

### 3.1 微信爬虫的数据获取轨道（双引擎模式）

- **轻量即时轨道：搜狗微信直搜架构 (`sogou_crawler.py`)**
  - **原理**：绕开复杂的模拟登录流程，利用搜狗提供的微信全网索引能力，使用同一 Session 劫持突破 URL 时效性。
  - **优势**：轻快、稳定、零依赖。并配合休眠（90s 等待跳过搜狗的反作弊封禁），适合短频快的指定账号或关键字检索。
  
- **工业沉浸轨道：模拟人工 + 流量劫持框架 (`ui_bot.py` + `interceptor.py`)**
  - **原理**：打破常规网页获取，使用 PyAutoGUI + win32gui 操作 PC 端微信应用打开公众号历史文章列表进行滚屏；同时底层采用 `mitmproxy`（中间人攻击原理）嗅探 `mp.weixin.qq.com` 流量，提取 JSON/HTML 响应直接落盘至 `captured_queue.jsonl` 分离处理。
  - **优势**：真正能防一切协议层的特征签名检测，流量完全为原生真实流量。

### 3.2 账号发现的多通道融合（Discovery 模块）

如何在不知道去爬哪些公众号时自动裂变出无限的高质文章？我们实现了行业最先进的公众号自动发现三级跳：

- **通道 A：零成本高频直搜发现（`sogou_discovery.py`）**  
  通过内置约 30 个高精准渗透对抗相关的关键词池（如 *"内网渗透", "bypass WAF", "CobaltStrike使用"*），在搜狗进行泛量模糊匹配，通过文章发布频率定位活跃的技术号，注入种子库列表 (`seed_accounts.yaml`)。

- **通道 B：图谱扩散式引用挖掘（`citation_extractor.py`）**  
  通过正则与 NLP 分析手段，从现已成功爬取的微信长文底侧提取其引用账号。（如匹配正则 *"转载自 【.*?】", "首发：.*?", "作者 | .*"*）。因高质量公众号往往会同类互引，该通道发掘到的安全号大多带有极高的技术纯度。

- **通道 C：开源项目交叉验证（`community_sync.py`）**  
  抓取并在 GitHub 安全知识整合合辑（Awesome 列表项目等，例如 Threekiii/Awesome-Redteam 等），借助大模型 (DeepSeek) 或离线正则识别列表里归档的公众号名单并将其合并作为精选的高可信目标库。

### 3.3 审核门控机制
并非所有被发现到的账号都会被系统收录，采集到的所有名单进入 `discovery_scheduler.py` 调度并通过 `AccountQualityScorer` 算法打分：
- 评分 `>= 40`：直接进入白名单 `seed_accounts.yaml`；
- `25 - 39` 分：进入等待区进行人工微调；
- ` < 25 `分：舍弃不收录。

---

## 4. 日常维护指引

1. **增量触发微信队列**：
   ```bash
   python crawlers/main_crawler.py --sources wechat --all
   ```
2. **强制清理与同步 GitHub/社区/RSS 等传统通道**：
   ```bash
   python crawlers/main_crawler.py --sources csdn,github,qianxin,xianzhi,rss
   ```
3. **主动激活公众账号图谱发掘**：
   ```bash
   python -m discovery.discovery_scheduler
   ```