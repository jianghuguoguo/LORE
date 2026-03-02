# RefPenTest · 使用指南

> 文档版本：v0.5.0 · 更新日期：2026-03-01

---

## 1. 系统要求

| 项目 | 要求 |
|:----|:----|
| 操作系统 | Windows 10/11 · Linux · macOS |
| Python | 3.10+ |
| 内存 | 8 GB 以上 |
| 磁盘空间 | 20 GB 以上（含外部数据库） |
| 网络 | 稳定互联网连接（LLM API + 爬虫） |

---

## 2. 安装

```bash
# 克隆项目
git clone <repository-url>
cd 语料/RefPenTest

# 创建虚拟环境（推荐）
python -m venv ../.venv
..\.venv\Scripts\activate        # Windows
# source ../.venv/bin/activate   # Linux / macOS

# 安装依赖
pip install -r requirements.txt
```

---

## 3. 初始配置

### 3.1 LLM API Key

编辑 `configs/config.yaml`：

```yaml
llm:
  api_key_literal: "sk-your-deepseek-key"   # 必填
  base_url: "https://api.deepseek.com"
  model: "deepseek-chat"
```

### 3.2 RAGFlow 连接

同样在 `configs/config.yaml`（或直接修改 `src/ragflow_uploader.py` 中的 `RAGFLOW_CONFIG`）：

```yaml
ragflow:
  host: "http://your-ragflow-host"
  email: "your@email.com"
  password: "your-password"
  experience_dataset: "your-dataset-id"
```

### 3.3 爬虫认证（可选，提升速率/内容）

编辑 `crawlers/config.py`：

```python
CSDN_COOKIE    = "your_csdn_cookie"    # 解锁 CSDN VIP 内容
GITHUB_TOKEN   = "ghp_your_token"      # GitHub API 速率 5000→ →/h
REQUEST_DELAY  = (2, 4)               # 请求间隔（秒），避免限流
```

---

## 4. 运行全流程流水线

### 4.1 一键运行（推荐）

```bash
cd RefPenTest

# 完整流水线（Layer 0 → Layer 1 → Layer 2 → Layer 3 → Layer 4 → Upload）
python run_full_pipeline.py

# 查看各阶段状态
python run_full_pipeline.py --status

# 跳过末尾 RAGFlow 上传（离线调试）
python run_full_pipeline.py --no-ragflow

# 从头重置状态再执行
python run_full_pipeline.py --reset-state
```

> **注意**：首次运行 Layer 1 需调用 DeepSeek API，15 个 session 约需 1–2 小时。

### 4.2 交互式主入口

```bash
python refpentest.py
```

提供菜单选择单阶段运行、查看状态、手动上传等操作。

### 4.3 分阶段单独运行

```bash
# Layer 0：日志标准化
python scripts/run_layer0.py --log-dir logs --output-dir data/layer0_output

# Layer 1：LLM 标注
python run_layer1_llm_batch.py

# Layer 2：经验蒸馏（不上传）
python run_layer2_analysis.py --no-ragflow

# Layer 3：XPEC 融合
python run_layer3_phase12.py   # Phase 1+2：SEC + EWC
python run_layer3_phase34.py   # Phase 3+4：RME + BCC
python run_layer3_phase5.py    # Phase 5：KLM 注册

# Layer 4：缺口感知
python run_layer4_gap_dispatch.py --no-crawl   # 仅分析，不触发爬取

# 统一上传至 RAGFlow
python src/ragflow_uploader.py

# 重传指定 session
python src/ragflow_uploader.py --session <session_id>

# 预演（不实际上传）
python src/ragflow_uploader.py --dry-run
```

---

## 5. 数据采集

### 5.1 多源实时爬虫

```bash
# 交互式（引导选择数据源、关键词、页数）
python crawlers/main_crawler.py

# 命令行参数（推荐 CI/自动化场景）
python crawlers/main_crawler.py --all -q "CVE-2024-23897" --yes
python crawlers/main_crawler.py --sources csdn,github -q "WebLogic 反序列化" --max-pages 10

# 一次 RSS 增量同步
python crawlers/main_crawler.py --rss-sync
python crawlers/main_crawler.py --rss-sync -q "内网渗透"

# RSS 定时调度（每 2h 后台运行）
python crawlers/rss_scheduler.py
```

**支持的爬虫数据源**：

| 源 ID | 平台 | 说明 |
|:------|:----|:----|
| `csdn` | CSDN | 中文技术博客，支持 Cookie 解锁 VIP |
| `github` | GitHub | 仓库 / Issues / PoC，Token 提升速率 |
| `qianxin` | 奇安信攻防社区 | 中文安全研究 |
| `xianzhi` | 先知社区 | 中文安全技术分享 |
| `attack` | MITRE ATT&CK | 企业/ICS/Mobile 知识库 |

**微信公众号**（mitmproxy 代理方式）：

```bash
python crawl_wechat.py --accounts "FreeBuf" "安全客" --count 10
# 或
python crawlers/wechat_crawler/sogou_crawler.py [options]
```

### 5.2 外部知识库一键同步

```bash
# 同步全部 11 个外部安全数据库（首次约需数十分钟）
python crawlers/sync_data_light.py

# 只同步指定数据库
python crawlers/sync_data_light.py --repos attack
python crawlers/sync_data_light.py --repos cisa-kev,cwe,nvd
```

**支持的数据库**：

| `--repos` ID | 数据库 | 格式 |
|:------------|:------|:----|
| `attack` | MITRE ATT&CK（Enterprise/ICS/Mobile） | STIX 2.1 JSON |
| `cisa-kev` | CISA 已知利用漏洞（KEV） | JSON |
| `cwe` | MITRE CWE | XML |
| `capec` | MITRE CAPEC | XML |
| `d3fend` | MITRE D3FEND | JSON-LD |
| `github-advisory` | GitHub Advisory DB | JSON |
| `zdi` | ZDI Advisories | HTML/JSON |
| `cve` | CVE cvelistV5（体积大） | JSON |
| `nvd` | NVD Feeds（fkie-cad） | JSON |
| `exploit-db` | Exploit-DB | SQL / CSV |
| `linux-vulns` | Linux Kernel Vulns | JSON |

---

## 6. Web Dashboard

```bash
cd dashboard
python app.py
# 浏览器打开 http://localhost:5000
```

**功能导航**：

| 菜单 | 功能 |
|:----|:----|
| 总览看板 | 经验库统计 · 五类知识分布 · 数据质量指标 |
| 事实知识 | FACTUAL 条目 · CVE / CVSS / 版本详情 |
| 成功经验 | PROCEDURAL_POS · 步骤浏览 · 置信度筛选 |
| 避坑指南 | PROCEDURAL_NEG · 失败命令 + 根因分类 |
| 元认知规则 | METACOGNITIVE · 决策规则 · 适用场景 |
| 概念知识 | CONCEPTUAL · 技术原理 · 工具说明 |
| 会话浏览 | Layer 1 事件时间线 · 成功率统计 |
| 流水线日志 | 「开启反思」一键全流水线 · 实时日志 |
| 爬虫管理 | 实时爬虫 · 外部 KB 同步 · 数据管理 |
| 融合经验库 | KLM 条目 · 知识健康状态 · **经验缺口定向爬取** |

**「开启反思」**（顶栏紫色脉冲按钮）：一键串行运行 Layer 1 → Layer 2 → Layer 3 Phase 1+2 → Phase 3+4 → Phase 5。

---

## 7. Layer 4 缺口感知爬取

### 7.1 Dashboard 图形界面（推荐）

1. 打开 http://localhost:5000 → **融合经验库**
2. 底部「经验缺口分析」卡片查看 Gap Score
3. 点击缺口行自动填入关键词 → 调整页数 → **启动缺口爬取**

### 7.2 REST API

```bash
curl -X POST http://localhost:5000/api/gap/crawl \
  -H "Content-Type: application/json" \
  -d '{"query":"CVE-2017-10271 exploit PoC","max_pages":5,"sources":["csdn","github"]}'
```

### 7.3 命令行

```bash
# 分析缺口 + 触发爬取
python run_layer4_gap_dispatch.py

# 仅分析，不触发爬取
python run_layer4_gap_dispatch.py --no-crawl

# 定时后台调度（P1 每日 02:00 / P2 每周一 03:00）
python scheduler.py
```

### 7.4 七大失败维度与缺口优先级

| 维度 | 子类型 | 含义 | 优先级 |
|:-----|:------|:----|:------:|
| `INT` | `INCOMPLETE_RECON` | 情报不足 | **P0** |
| `INT` | `WRONG_ASSUMPTION` | 假设错误 | **P0** |
| `DEF` | `PATCHED` | 漏洞已修补 | P1 |
| `DEF` | `AUTHENTICATION` | 认证拦截 | P1 |
| `DEF` | `ACTIVE_BLOCKING` | WAF/主动防御 | P1 |
| `INV` | `WRONG_ARGS` | 工具参数错误 | P1 |
| `ENV` | `BINARY_MISSING` | 工具缺失 | P1 |

---

## 8. 多框架日志接入

系统默认支持 4 种日志格式，无需任何配置即可自动识别：

```python
from src.layer0 import AdapterRegistry
from pathlib import Path

adapter = AdapterRegistry.auto_detect(Path("logs/my_run.jsonl"))
print(adapter.adapter_name)   # 'cai' / 'langchain' / 'openai_assistant' / 'generic'

meta, turns = adapter.parse(Path("logs/my_run.jsonl"))
```

使用非 CAI 框架（LangChain / OpenAI Assistants / 自定义 JSONL）？参阅
[docs/04_Log Adapter 多框架日志接入指南.md](./04_Log%20Adapter%20%20多框架日志接入指南.md)。

---

## 9. 常见问题

### 爬虫无数据返回

- CSDN Cookie 是否过期？在 `crawlers/config.py` 更新 `CSDN_COOKIE`
- GitHub Token 是否有效？`GITHUB_TOKEN` 为空时每小时限 60 次请求
- 适当增大 `REQUEST_DELAY = (3, 6)` 避免触发限流

### Layer 1 报错 `openai 包未安装`

```bash
pip install openai>=1.0.0
```

### RAGFlow 上传失败 / 重复条目

清空 RAGFlow 数据集后，执行全量重传：

```bash
python src/ragflow_uploader.py
```

避免重复的正确姿势：始终使用 `run_full_pipeline.py`（末尾统一上传），
**不要**在 Layer 2 蒸馏阶段同时上传（已被固定禁用）。

### Dashboard 端口被占用

```bash
# Windows
netstat -ano | findstr :5000
# 修改端口：dashboard/app.py → app.run(port=5001)
```

### Layer 3 / Layer 4 报空文件错误

Layer 2 未产出足够数据时后续层会返回空列表并记录 WARNING，不会崩溃。
先确认 `data/layer2_output/` 下有 `experiences.jsonl` 文件。

---

## 10. 日常运维

| 频次 | 任务 |
|:-----|:----|
| 每次新增日志 | `python run_full_pipeline.py`（全量重算） |
| 每周 | 更新 CSDN Cookie · 清理 raw_data/ 重复文件 |
| 按需 | `python crawlers/sync_data_light.py --repos attack,cve` |
| 离线调试 | `python run_full_pipeline.py --no-ragflow` |

---

## 11. 运行测试

```bash
cd RefPenTest
python -m pytest tests/ -v
# 276 个测试用例
```

---

**文档版本**：v0.5.0 · **最后更新**：2026-03-01
