# RefPenTest · 渗透测试知识蒸馏系统

<div align="center">
**Penetration Testing Experience Distillation & Knowledge Base**

*多层级渗透测试经验蒸馏 · 缺口感知自适应爬取 · 多源安全数据聚合 · Web 可视化管理*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)](https://github.com)
[![Layers: 0-4](https://img.shields.io/badge/Pipeline-Layer%200~4-orange.svg)](#系统架构)

</div>

---

## 目录

- [项目简介](#项目简介)
- [系统架构](#系统架构)
- [目录结构](#目录结构)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
  - [Layer 1 LLM 会话标注](#layer-1-llm-会话标注)
  - [Layer 2 经验蒸馏](#layer-2-经验蒸馏)
  - [Layer 3 XPEC 经验融合](#layer-3-xpec-经验融合)
  - [Layer 4 缺口感知爬取](#layer-4-缺口感知爬取)
  - [外部知识库同步](#外部知识库同步)
  - [实时爬虫](#实时爬虫)
  - [运行测试](#运行测试)
- [数据源总览](#数据源总览)
- [Dashboard 功能](#dashboard-功能)
- [知识层次体系](#知识层次体系)
- [缺口感知机制](#缺口感知机制)
- [文档索引](#文档索引)
- [许可证](#许可证)

---

## 项目简介

**RefPenTest**（Reflective Penetration Testing）是一个面向渗透测试场景的多层级知识蒸馏系统。系统从真实渗透测试会话日志出发，通过五层流水线自动提炼五类结构化经验，并创新性地引入 **Layer 4 缺口感知机制**——实时分析 Layer 1 失败标注，对知识盲区自动触发定向爬取，形成"发现缺口 → 补充知识 → 提升 Agent 能力"的闭环。

### 核心能力

- **五层经验蒸馏流水线**：Layer 0（原始日志） → Layer 1（LLM 会话标注） → Layer 2（经验提炼） → Layer 3（跨会话融合） → Layer 4（缺口修复）
- **五类知识层次**：FACTUAL / PROCEDURAL_POS / PROCEDURAL_NEG / METACOGNITIVE / CONCEPTUAL
- **缺口感知自适应爬取（Layer 4）**：分析 Layer 1 失败事件（171 条 / 9 sessions），生成 P0/P1 优先级缺口信号，自动触发定向爬取填补知识盲区
- **双轨数据采集**：关键词驱动的实时爬虫（CSDN / GitHub / 奇安信 / 先知 / 微信公众号）+ 11 个外部安全数据库一键同步
- **Web 可视化管理**：经验库浏览、会话分析、爬虫管理、同步状态监控，一套 Dashboard 全集成

---

## 系统架构

```
    原始渗透测试日志 (logs/)  ← CAI / LangChain / OpenAI Assistants / 任意 JSONL
             │
             ▼  Layer 0 格式适配子层：AdapterRegistry.auto_detect()
             │  自动嗅探格式 → CanonicalAgentTurn 序列
             │
             ▼  Layer 0：日志解析
        layer0_output/        ← 按会话拆分的原始对话
             │
             ▼  Layer 1：LLM 会话标注
        layer1_output/        ← 结构化标注（outcome / CVE / failure_root_cause）
             │                   当前：15 份日志，415 事件，171 次失败
             │
     ┌───────┴──────────────────────────────┐
     │                                      │
     ▼  Layer 2：经验蒸馏 (规则 + LLM)       ▼  Layer 4：缺口感知爬取
layer2_output/   ← 五类结构化经验          Dashboard「经验缺口分析」卡 / POST /api/gap/crawl
  FACTUAL                                  │  识别七类知识盲区
  PROCEDURAL_POS                           │    INT/INCOMPLETE_RECON → P0（立即爬取）
  PROCEDURAL_NEG                           │    DEF/PATCHED 等       → P1（每日调度）
  METACOGNITIVE                            ▼
  CONCEPTUAL                        queues/gap_queue.jsonl
     │                                     │
     ▼  Layer 3：XPEC 跨会话融合            ▼  src/layer4/dispatcher.py
layer3_output/                       raw_data/layer4/  ← 定向爬取语料
  phase5_klm_registry.jsonl          （CSDN / GitHub / 奇安信 / 先知）
  CROSS_SESSION_RULE
  ANTIPATTERN_DIGEST
  KG_NODE

                         外部知识库同步
                    crawlers/sync_data_light.py
                      raw_data/*-database/   ← 11 个外部数据库

                         Dashboard
                    dashboard/app.py
                    http://localhost:5000
```

---

## 目录结构

```
RefPenTest/
├── src/
│   ├── layer0/                       # 日志标准化层（含格式适配子层）
│   │   ├── canonical_types.py        # 内部规范格式 CanonicalAgentTurn
│   │   ├── log_adapter.py            # LogAdapter 抽象基类 + AdapterRegistry
│   │   ├── adapters/                 # 内置适配器（CAI/LangChain/OpenAI/Generic）
│   │   ├── parser.py                 # CAI 三段式 Turn 重建（CaiAdapter 内部）
│   │   ├── extractor.py              # AtomicEvent 提取
│   │   └── assembler.py              # TurnSequence 组装
│   ├── layer1/                       # LLM 会话标注
│   ├── layer2/                       # 经验蒸馏
│   │   ├── pipeline.py               # 主流程编排
│   │   ├── experience_models.py      # 5 类经验数据模型
│   │   └── extractors/               # 各类提取器
│   │       ├── factual.py / factual_llm.py
│   │       ├── procedural.py         # POS / NEG
│   │       ├── metacognitive.py
│   │       └── conceptual.py
│   ├── layer3/                       # XPEC 跨会话融合
│   └── layer4/                       # 缺口感知爬取（⭐ 新增）
│       ├── models.py                 # GapSignal / GapPriority / CrawlResult
│       ├── gap_queue.py              # 线程安全 JSONL 优先级队列
│       ├── quality_filter.py         # PoC / 命令内容质量评分
│       ├── crawler.py                # CrawlWorker → CrawlerManager 适配
│       ├── dispatcher.py             # P0 立即处理 / P1 每日 / P2 每周
│       └── scheduler.py             # APScheduler 定时任务入口
│
├── crawlers/                         # 爬虫框架
│   ├── main_crawler.py               # ★ 多源爬虫 CLI
│   ├── sync_data_light.py            # ★ 外部 KB 一键同步
│   ├── crawler_manager.py            # 多源爬虫调度器（csdn/github/qianxin/xianzhi）
│   ├── config.py                     # Cookie / Token / 延迟配置
│   ├── attack_crawler.py             # MITRE ATT&CK 爬虫
│   ├── wechat_article_crawler/       # 微信公众号爬虫（mitmproxy 代理）
│   └── example_crawler.py            # 新爬虫模板
│
├── dashboard/                        # Web 可视化界面
│   ├── app.py                        # Flask 应用入口（port 5000）
│   ├── templates/index.html
│   └── static/
│
├── scripts/
│   └── run_layer0.py                 # Layer 0 命令行入口
│
├── data/
│   ├── layer0_output/                # 拆分后的原始对话
│   ├── layer1_output/                # Layer 1 标注（15 份 / 415 事件）
│   ├── layer2_output/                # 五类结构化经验
│   └── layer3_output/                # XPEC 融合知识条目
│
├── queues/
│   └── gap_queue.jsonl               # ⭐ Layer 4 缺口信号队列（优先级 P0/P1/P2）
│
├── raw_data/
│   ├── csdn/  github/  QIANXIN/  XIANZHI/  wechat/   # 实时爬虫输出
│   ├── layer4/                       # ⭐ Layer 4 定向爬取输出
│   ├── attack-database/  cve-database/  nvd-database/ # 外部知识库
│   └── … (共 11 个外部数据库目录)
│
├── logs/                             # 原始渗透测试会话日志 (.jsonl)
├── configs/config.yaml               # 全局配置（含 layer4 参数）
├── run_layer1_llm_batch.py           # Layer 1 批处理入口
├── run_layer2_analysis.py            # Layer 2 入口脚本
├── run_layer3_phase12.py             # Layer 3 Phase 1+2
├── run_layer3_phase34.py             # Layer 3 Phase 3+4
├── run_layer3_phase5.py              # Layer 3 Phase 5（KLM 注册）
├── run_discovery.py                  # 发现扫描入口
├── crawl_wechat.py                   # 微信公众号爬取 CLI（shim）
├── main_crawler.py                   # 多源爬虫 CLI（shim 转发 crawlers/main_crawler.py）
├── scheduler.py                      # 定时任务统一入口
└── requirements.txt
```

---

## 快速开始

### 系统要求

- Python 3.10+
- 8 GB+ RAM
- 20 GB+ 磁盘空间（含外部数据库）

### 安装

```bash
# 克隆项目
git clone <repository-url>
cd 语料

# 创建虚拟环境
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

# 安装依赖
pip install -r requirements.txt
pip install -r RefPenTest/requirements.txt
```

### 启动 Dashboard

```bash
cd RefPenTest/dashboard
python app.py
# 浏览器访问 http://localhost:5000
```

---

## 使用指南

### 多框架日志接入

在运行任何分析流水线前，需确保日志文件格式受支持。系统内置四种适配器，并自动检测格式：

```python
from pathlib import Path
from src.layer0 import AdapterRegistry

# 自动嗅探格式（支持 CAI / LangChain / OpenAI Assistants / 任意 JSONL）
adapter = AdapterRegistry.auto_detect(Path("logs/my_run.jsonl"))
print(adapter.adapter_name)   # 'cai' / 'langchain' / 'openai_assistant' / 'generic'

meta, turns = adapter.parse(Path("logs/my_run.jsonl"))
```

**若使用非 CAI 框架**（LangChain / OpenAI Assistants / 自定义 JSONL），参阅 [Log Adapter 接入指南](./docs/04_RefPenTest%20·%20格式适配层设计.md)。

---

### Layer 1 LLM 会话标注

从 `logs/` 中的原始渗透测试日志生成结构化标注：

```bash
cd RefPenTest
python run_layer1_llm_batch.py
# 输出至 data/layer1_output/layer1_<session_id>.jsonl
```

每份 Layer 1 输出为单个 JSON 对象，包含 `annotated_events` 数组，每个事件附带：
- `failure_root_cause`：`{dimension, sub_dimension, evidence}`（七大失败维度）
- `outcome_label`：`success / failure`
- `base.call.tool_name` / `base.call.arguments`：实际调用的工具与参数

### Layer 2 经验蒸馏

从 Layer 1 标注文件提炼五类结构化经验：

```bash
python run_layer2_analysis.py
# 输出至 data/layer2_output/
```

每次运行会自动清除旧的 `experience_raw.jsonl` 再全量重算，避免重复追加。

### Layer 3 XPEC 经验融合

跨会话聚合同类失败模式、提炼高置信决策规则，生成可被 RAG 检索的通用 KLM 知识条目：

```bash
# 分阶段运行（推荐）
python run_layer3_phase12.py   # Phase 1+2：SEC 等价集聚类 + 规则提炼
python run_layer3_phase34.py   # Phase 3+4：RME 融合 + 冲突解决
python run_layer3_phase5.py    # Phase 5：KLM 注册
# 输出至 data/layer3_output/
#   phase5_klm_registry.jsonl  ← 136 条 KLM 条目（6 条已 reflux 至 RAGFlow）
#   phase34_consolidated.jsonl
#   conflict_report.jsonl / conflict_summary.json
```

融合结果包含三类高价值知识条目：

| 类型 | 说明 |
|:-----|:----|
| `CROSS_SESSION_RULE` | 多场景反复命中的决策规律，如 `RECON_BEFORE_EXPLOIT` |
| `ANTIPATTERN_DIGEST` | 高频失败根因聚合，辅助规避已知陷阱 |
| `KG_NODE` | 技战术级别的原子知识，供 RAG 精准召回 |

### Layer 4 缺口感知爬取

Layer 4 是本系统的自适应知识补全模块。它分析 Layer 1 失败事件，识别"Agent 缺少哪类经验导致失败"，支持三种方式触发定向爬取填补盲区。

#### 方式一：Dashboard 图形界面（推荐）

1. 打开 `http://localhost:5000`，导航至 **融合经验库**
2. 查看底部 **经验缺口分析** 卡片，每行显示缺口名称及 Gap Score 横向评分条
3. 点击任意行自动填入关键词，调整 `最大页数`，点击 **启动缺口爬取**
4. 进度在按钮右侧实时更新，语料保存至 `raw_data/layer4/`

顶栏 **开启反思**（紫色脉冲按钮）可一键串行执行全流水线：
Layer 1 → Layer 2 → Layer 3 Phase1+2 → Phase3+4 → Phase5

亦可调用 REST API：

```bash
curl -X POST http://localhost:5000/api/gap/crawl \
  -H "Content-Type: application/json" \
  -d '{"query":"CVE-2017-10271 exploit","max_pages":5,"sources":["csdn","github","qianxin","xianzhi"]}'
```

#### 方式二：命令行直接爬取

```bash
python crawlers/main_crawler.py --sources csdn,github,qianxin,xianzhi \
    --query "CVE-2017-10271 exploit PoC" --max-pages 5 --yes
```

#### 方式三：定时自动调度

```bash
# 作为后台服务启动（P1 每日 02:00 / P2 每周一 03:00）
python scheduler.py
```

#### 七大失败维度与缺口类型

| 维度 | 子类型 | 含义 | 优先级 | 典型搜索关键词示例 |
|:-----|:------|:----|:------:|:----------------|
| `INT` | `INCOMPLETE_RECON` | 情报认知缺口 | **P0** | `Oracle WebLogic enumeration reconnaissance` |
| `INT` | `WRONG_ASSUMPTION` | 假设错误 | P0 | `{service} common misconfigurations exploit` |
| `DEF` | `PATCHED` | 漏洞已修补 | P1 | `CVE-xxxx patch bypass alternative exploit` |
| `DEF` | `AUTHENTICATION` | 认证拦截 | P1 | `{service} authentication bypass exploit` |
| `DEF` | `ACTIVE_BLOCKING` | 主动防御 | P1 | `{service} WAF bypass technique pentest` |
| `INV` | `WRONG_ARGS` | 参数错误 | P1 | `{tool} command line arguments tutorial` |
| `ENV` | `BINARY_MISSING` | 工具缺失 | P1 | `{tool} install configure linux pentest` |

### 外部知识库同步

一键同步全部 11 个外部安全数据库至 `raw_data/`：

```bash
python crawlers/sync_data_light.py

# 同步指定仓库
python crawlers/sync_data_light.py --repos attack,cisa-kev,cve
```

支持的仓库 ID：

| ID | 数据库 | 说明 |
|:---|:------|:----|
| `attack` | MITRE ATT&CK | Enterprise / ICS / Mobile STIX 2.1 |
| `cisa-kev` | CISA KEV | 已知利用漏洞目录 |
| `cwe` | MITRE CWE | 常见弱点列表 |
| `capec` | MITRE CAPEC | 攻击模式库 |
| `d3fend` | MITRE D3FEND | 防御知识图谱 |
| `github-advisory` | GitHub Advisory | GitHub 安全公告 |
| `zdi` | ZDI Advisories | Zero Day Initiative |
| `cve` | CVE cvelistV5 | CVE.org 官方（体积较大） |
| `nvd` | NVD Feeds | fkie-cad/nvd-data-feeds |
| `exploit-db` | Exploit-DB | 漏洞利用代码库 |
| `linux-vulns` | Linux Kernel Vulns | Linux 内核安全漏洞 |

### 实时爬虫

```bash
# 多源通用爬虫（交互式）
python crawlers/main_crawler.py

# 命令行参数
python crawlers/main_crawler.py --sources csdn,github --query "CVE-2024-23897" --max-pages 5

# 微信公众号文章爬取（需本地代理）
python crawl_wechat.py --accounts "FreeBuf" "安全客" "绿盟科技" --count 10
```

爬虫配置（`crawlers/config.py`）：

```python
CSDN_COOKIE    = 'your_csdn_cookie'     # 解锁 CSDN VIP 内容（可选）
GITHUB_TOKEN   = 'ghp_your_token'       # 提高 GitHub API 速率（可选）
REQUEST_DELAY  = (2, 4)                 # 请求间隔（秒）
```

### 运行测试

```bash
cd RefPenTest
python -m pytest tests/ -v
# 276 个测试用例
```

---

## 数据源总览

### 实时爬虫（关键词驱动）

| 数据源 | 说明 | 特性 |
|:------|:-----|:-----|
| **CSDN** | 中文技术博客平台 | 支持 Cookie 解锁 VIP 内容 |
| **GitHub** | 代码仓库 / Issues / PoC | Token 提高 API 速率 |
| **奇安信攻防社区** | 中文安全研究文章 | 支持关键词搜索 |
| **先知社区** | 中文安全技术分享 | 支持关键词搜索 |
| **微信公众号** | 安全类公众号文章 | mitmproxy 代理拦截，需配置账号 |

### 外部知识库（一键同步）

| `--repos` ID | 数据库 | 格式 |
|:------------|:------|:-----|
| `attack` | MITRE ATT&CK | STIX 2.1 JSON |
| `cisa-kev` | CISA KEV | JSON |
| `cwe` | MITRE CWE | XML |
| `capec` | MITRE CAPEC | XML |
| `d3fend` | MITRE D3FEND | JSON-LD |
| `github-advisory` | GitHub Advisory DB | JSON |
| `zdi` | ZDI Advisories | HTML/JSON |
| `cve` | CVE cvelistV5 | JSON |
| `nvd` | NVD Feeds | JSON |
| `exploit-db` | Exploit-DB | SQL / CSV |
| `linux-vulns` | Linux Kernel Vulns | JSON |

### Layer 4 定向爬取（缺口驱动）

由 Dashboard「经验缺口分析」卡片或 `POST /api/gap/crawl` 触发，自动生成搜索关键词并定向爬取：

| 触发缺口类型 | 关键词生成策略 | 示例关键词 |
|:------------|:------------|:---------|
| `INT/INCOMPLETE_RECON` + WebLogic | 服务名 + 侦察/枚举 | `Oracle WebLogic enumeration reconnaissance technique` |
| `INT/INCOMPLETE_RECON` + CouchDB | 服务名 + 漏洞/攻击面 | `Apache CouchDB vulnerability exploit 2024 2025` |
| `DEF/PATCHED` + CVE | CVE ID + PoC | `CVE-2017-10271 exploit PoC python` |
| `DEF/AUTHENTICATION` | 服务名 + 认证绕过 | `{service} authentication bypass exploit 2024` |
| `INV/WRONG_ARGS` | 工具名 + 正确用法 | `gobuster command line arguments tutorial` |
| `ENV/BINARY_MISSING` | 工具名 + 安装配置 | `dirb install configure linux pentest` |

---

## Dashboard 功能

访问 `http://localhost:5000`，左侧导航包含以下页面：

| 菜单项 | 功能说明 |
|:------|:--------|
| **总览看板** | 经验库统计卡片、五类知识数量分布、数据质量指标 |
| **事实知识** | FACTUAL 经验浏览、CVE ID / CVSS / 受影响版本详情 |
| **成功经验** | PROCEDURAL_POS 步骤浏览、成功指标、置信度过滤 |
| **避坑指南** | PROCEDURAL_NEG 失败命令与原因分类、约束条件 |
| **元认知规则** | METACOGNITIVE 策略经验、关键教训、适用场景 |
| **概念知识** | CONCEPTUAL 条目浏览、技术概念与漏洞原理 |
| **会话浏览** | Layer 1 会话详情、操作序列时间线、成功率统计 |
| **流水线日志** | 「开启反思」全流水线一键运行、实时日志、运行历史 |
| **爬虫管理** | 实时爬虫启动 · 外部知识库同步 · 原始数据 RAG 管理 |
| **融合经验库** | KLM 条目浏览 · 知识健康状态（生命周期/冲突）· 经验缺口定向爬取 |

---

## 知识层次体系

```
┌─────────────────────────────────────────────────────────┐
│  Layer 0  原始渗透测试会话日志                            │
│  工具调用序列 · stdout/stderr · return_code              │
├─────────────────────────────────────────────────────────┤
│  Layer 1  LLM 会话标注                                   │
│  outcome_label · failure_root_cause（维度/子类/证据）    │
│  attack_phase · rag_adoption · cve_ids                  │
├─────────────────────────────────────────────────────────┤
│  Layer 2  五类结构化经验                                  │
│  FACTUAL        漏洞事实（CVE / CVSS / 版本）             │
│  PROCEDURAL_POS 成功操作步骤序列                          │
│  PROCEDURAL_NEG 失败负例（命令 + 根因 + 约束）            │
│  METACOGNITIVE  元认知策略（教训 + 决策规则）             │
│  CONCEPTUAL     概念性知识（技术原理 + 工具说明）          │
├─────────────────────────────────────────────────────────┤
│  Layer 3  XPEC 跨会话融合                                │
│  CROSS_SESSION_RULE  多会话通用决策规律                   │
│  ANTIPATTERN_DIGEST  高频失败根因摘要                     │
│  KG_NODE             知识图谱原子节点                     │
├─────────────────────────────────────────────────────────┤
│  Layer 4  缺口感知自适应爬取（⭐ 新增）                   │
│  GapSignal（P0/P1/P2）→ 定向搜索关键词 → 外部语料        │
│  填补 Agent 因知识盲区导致的重复失败                      │
└─────────────────────────────────────────────────────────┘
```

每条经验（Layer 2）包含统一元数据：`session_id`、`target_service`、`target_version`、`cve_ids`、`confidence`、`source_layer`。

---

## 缺口感知机制

Layer 4 的核心设计理念：**渗透测试 Agent 的反复失败 = 知识缺口的直接信号**。

### 缺口信号生成流程

```
Layer 1 失败事件（171 条 / 9 sessions）
       │
       ▼ src/layer4/gap_queue.py
  提取 failure_root_cause.dimension / sub_dimension
  提取 base.call.tool_name（工具名）
  提取 base.call.arguments（目标 URL / 端口 → 服务名）
       │
       ▼ extract_service() + extract_tool()
  生成 2-3 条英文搜索关键词（纯英文，无中文污染）
       │
       ▼ GapSignal
  gap_id / session_id / priority(P0/P1/P2)
  root_cause_dim / root_cause_sub
  target_service / cve_ids / search_queries
       │
       ├─ P0 → dispatcher.handle_p0()      立即执行
       ├─ P1 → scheduler APScheduler       每日 02:00
       └─ Dashboard /api/gap/crawl          手动触发（前端卡片）
```

### 已发现缺口统计（当前数据集）

| Session | 失败数 | 主要缺口 |
|:--------|------:|:--------|
| `8cb881bb` | 33 | WRONG_ARGS×6 / PATCHED×6 / ACTIVE_BLOCKING×6 |
| `5db69512` | 29 | PATCHED×20（大量打已修补漏洞）|
| `64227b8f` | 22 | PATCHED×6 / WRONG_ARGS×4 |
| `f9af8981` | 18 | INCOMPLETE_RECON×12（最严重情报缺口）|
| `7d4c1a6a` | 19 | INCOMPLETE_RECON×5 / WRONG_ARGS×3 |
| `d1bd6e0b` | 19 | AUTHENTICATION×5 / WRONG_ARGS×4 |
| `85cd2e37` | 12 | BLIND_EXECUTION×4 / INCOMPLETE_RECON×2 |
| `b88633db` | 10 | INCOMPLETE_RECON×3 / BINARY_MISSING×2 |
| `b3ab5c15` | 9 | BINARY_MISSING×4 / WRONG_ARGS×2 |
| **合计** | **171** | P0: 37条 / P1: 134条 |

---

## 文档索引

| 文档 | 说明 |
|:----|:-----|
| [docs/01_OVERVIEW.md](./docs/01_OVERVIEW.md) | 项目背景与技术栈 |
| [docs/02_ARCHITECTURE.md](./docs/02_ARCHITECTURE.md) | 详细架构与模块设计 |
| [docs/03_USAGE_GUIDE.md](./docs/03_USAGE_GUIDE.md) | 安装配置与使用示例 |
| [docs/04_RefPenTest · 格式适配层设计.md](./docs/04_RefPenTest%20·%20格式适配层设计.md) | 多框架日志接入指南（Log Adapter）|
| [dashboard/README.md](./dashboard/README.md) | Dashboard 功能说明 |
| [项目技术方案.md](./项目技术方案.md) | 完整技术方案（含 Layer 4）|
| [XPEC Layer3 融合框架分析.md](./XPEC%20Layer3%20融合框架分析.md) | XPEC 融合机制原理 |

---

## 许可证

本项目采用 [MIT License](./LICENSE)。

**免责声明**：本项目仅供安全研究与学习用途，请勿用于未授权的渗透测试或其他非法活动。使用者须遵守当地及目标系统所在地的法律法规。

---

<div align="center">

**版本**: v0.5.0 | **Python**: 3.10+ | **状态**: Active Development

*Layer 0 → 1 → 2 → 3 → 4 全流水线已就绪 · 「开启反思」一键运行 · KLM 136 条已注册*

</div>
