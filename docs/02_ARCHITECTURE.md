# LORE · 系统架构

> 文档版本：v0.5.0 · 更新日期：2026-03-18

---

## 1. 整体架构

LORE 采用纵向分层 + 横向模块化设计，五层流水线负责知识蒸馏，横向功能模块（爬虫、Dashboard、外部 KB 同步）为流水线提供数据输入与可视化管理。

```
┌──────────────────────────────────────────────────────────────────────┐
│                       用户接口层                                      │
│  Web Dashboard (dashboard/app.py · Flask · localhost:5000)           │
│  CLI (run/run_full_pipeline.py · lore.py · crawlers/main_crawler.py) │
└──────────────────────────────────────────────────────────────────────┘
                                │
┌──────────────────────────────────────────────────────────────────────┐
│                    五层蒸馏流水线                                      │
│                                                                      │
│  Layer 0 ──► Layer 1 ──► Layer 2 ──► Layer 3 (Phase 1–5) ──► Layer 4 │
│  日志标准化   LLM标注    经验蒸馏    XPEC跨会话融合         缺口感知爬取 │
└──────────────────────────────────────────────────────────────────────┘
                                │
┌──────────────────────────────────────────────────────────────────────┐
│                    数据 · 知识层                                       │
│  data/layer{0-4}_output/  ·  RAGFlow 向量库 (8.140.33.83)             │
│  src/layer4/queues/gap_queue.jsonl · raw_data/ (爬虫 + 外部 KB)       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. 目录结构

```
LORE/
├── src/                           # 核心业务逻辑
│   ├── layer0/                    # 格式适配 + 日志标准化
│   │   ├── log_adapter.py         #   AdapterRegistry · LogAdapter 抽象基类
│   │   ├── canonical_types.py     #   CanonicalAgentTurn / SessionMeta
│   │   ├── adapters/              #   内置适配器（CAI / LangChain / OpenAI / Generic）
│   │   ├── parser.py              #   Turn 重建（CAI 三段式）
│   │   ├── extractor.py           #   AtomicEvent 提取
│   │   └── assembler.py           #   TurnSequence 组装
│   ├── layer1/                    # LLM 会话标注
│   ├── layer2/                    # 五类经验蒸馏
│   │   ├── pipeline.py            #   主流程编排
│   │   ├── experience_models.py   #   5 类经验数据模型
│   │   └── extractors/            #   各类提取器
│   ├── layer3/                    # XPEC 跨会话融合（Phase 1–5）
│   ├── layer4/                    # 缺口感知爬取
│   │   ├── models.py              #   GapSignal / GapPriority / CrawlResult
│   │   ├── gap_queue.py           #   线程安全 JSONL 优先级队列
│   │   ├── quality_filter.py      #   PoC 内容质量评分
│   │   ├── crawler.py             #   CrawlWorker → CrawlerManager 适配
│   │   ├── dispatcher.py          #   P0 立即 / P1 每日 / P2 每周调度
│   │   └── scheduler.py           #   APScheduler 定时任务
│   └── ragflow_uploader.py        # 经验批量上传 RAGFlow
│
├── crawlers/                      # 爬虫框架（含 CLI + 外部 KB 同步）
│   ├── main_crawler.py            # ★ 多源爬虫主入口（CLI）
│   ├── sync_data_light.py         # ★ 11 个外部安全数据库一键同步
│   ├── crawler_manager.py         #   多源调度器
│   ├── base_crawler.py            #   爬虫抽象基类
│   ├── config.py                  #   Cookie / Token / 延迟配置
│   ├── csdn_crawler.py            #   CSDN 爬虫
│   ├── github_crawler.py          #   GitHub 爬虫
│   ├── attack_crawler.py          #   MITRE ATT&CK 爬虫
│   ├── qianxin_crawler.py         #   奇安信爬虫
│   ├── xianzhi_crawler.py         #   先知爬虫
│   ├── rss_crawler.py             #   RSS 聚合爬虫
│   ├── rss_scheduler.py           #   RSS 定时调度（每 2h）
│   ├── wechat_crawler/            #   微信公众号（mitmproxy 代理）
│   ├── attack_core/               #   ATT&CK STIX 核心处理
│   └── example_crawler.py         #   新爬虫开发模板
│
├── dashboard/                     # Web 可视化界面
│   ├── app.py                     #   Flask 应用（port 5000）
│   ├── templates/index.html       #   单页 SPA
│   └── static/                    #   CSS / JS
│
├── run/                           # 轻量运行脚本
│   ├── run_full_pipeline.py       #   全流程 CLI（Layer 0 → Upload）
│   ├── run_layer0.py              #   Layer 0 命令行入口
│   ├── run_layer1_llm_batch.py    #   Layer 1 批处理入口
│   ├── run_layer2_analysis.py     #   Layer 2 入口
│   ├── run_layer3_phase12.py      #   Layer 3 Phase 1+2
│   ├── run_layer3_phase34.py      #   Layer 3 Phase 3+4
│   ├── run_layer3_phase5.py       #   Layer 3 Phase 5
│   └── run_layer4_gap_dispatch.py #   Layer 4 入口
│
├── configs/
│   └── config.yaml                # 全局配置（LLM / RAGFlow / Layer 4）
│
├── data/
│   ├── layer0_output/             # 标准化后的会话 JSONL
│   ├── layer1_output/             # LLM 标注结果（15 sessions / 415 events）
│   ├── layer2_output/             # 五类结构化经验（172 条）
│   │   └── {session_id}/experiences.jsonl
│   ├── layer3_output/
│   │   ├── phase5_klm_registry.jsonl   # KLM 注册表（137 条）
│   │   ├── conflict_report.jsonl       # 冲突报告
│   │   └── phase5_reflux_ready.jsonl   # 已 reflux（6 条）
│   └── layer4_output/
│       └── gap_dispatch_summary.json
│
├── src/layer4/queues/
│   └── gap_queue.jsonl            # Layer 4 缺口信号优先级队列
│
├── raw_data/                      # 所有原始语料
│   ├── csdn/ github/ QIANXIN/ XIANZHI/ wechat/
│   ├── layer4/                    # Layer 4 定向爬取输出
│   └── *-database/                # 11 个外部知识库
│
├── logs/                          # 原始渗透测试会话日志（.jsonl）
│
├── lore.py                  # 交互式主入口
├── main_crawler.py                # 向后兼容 shim → crawlers/main_crawler.py
├── crawl_wechat.py                # 向后兼容 shim → crawlers/wechat_crawler/
├── scheduler.py                   # 定时任务统一入口
├── pyproject.toml
└── requirements.txt
```

> **向后兼容说明**：根目录的 `main_crawler.py` 和 `crawl_wechat.py` 保留为 shim，
> 执行时自动转发至 `crawlers/` 下的实际代码，旧路径调用不受影响。

---

## 3. 五层流水线详解

### Layer 0：日志标准化

**输入**：`logs/*.jsonl`（支持 CAI / LangChain / OpenAI Assistants / 任意 JSONL）  
**输出**：`data/layer0_output/layer0_{session_id}.jsonl`

`AdapterRegistry.auto_detect()` 自动嗅探日志格式，输出统一的 `CanonicalAgentTurn` 序列。

**入口**：`run/run_layer0.py`（由 `run/run_full_pipeline.py` 自动调用）

---

### Layer 1：LLM 会话标注

**输入**：`data/layer0_output/`  
**输出**：`data/layer1_output/layer1_{session_id}.jsonl`

使用 DeepSeek Chat API 批量标注，每条工具调用产出：

| 字段 | 说明 |
|:-----|:----|
| `outcome_label` | `success / failure` |
| `failure_root_cause` | `{dimension, sub_dimension, evidence}` |
| `attack_phase` | ATT&CK 技战术阶段 |
| `cve_ids` | 关联 CVE |
| `rag_adoption` | 是否使用了 RAG 检索结果 |

**当前数据量**：15 sessions · 415 事件 · 171 次失败  
**入口**：`run/run_layer1_llm_batch.py`

---

### Layer 2：经验蒸馏

**输入**：`data/layer1_output/`  
**输出**：`data/layer2_output/{session_id}/experiences.jsonl`

| 类型 | 说明 |
|:-----|:----|
| `FACTUAL` | CVE / CVSS / 受影响版本 / 利用前置条件 |
| `PROCEDURAL_POS` | 成功命令序列 + 成功指标 |
| `PROCEDURAL_NEG` | 失败命令 + 错误信息 + 根因 + 约束 |
| `METACOGNITIVE` | 关键教训 + 适用场景 + 决策规则 |
| `CONCEPTUAL` | 技术原理 + 工具用法 |

**当前产出**：172 条经验  
**入口**：`run/run_layer2_analysis.py`（固定 `--no-ragflow`，蒸馏阶段不上传）

---

### Layer 3：XPEC 跨会话融合

| Phase | 脚本 | 功能 | 输出 |
|:------|:----|:----|:----|
| 1+2 | `run/run_layer3_phase12.py` | SEC 等价集聚类 + EWC 证据权重 | `phase12_result.jsonl` |
| 3+4 | `run/run_layer3_phase34.py` | RME 融合引擎 + BCC 贝叶斯校准 | `phase34_consolidated.jsonl` |
| 5   | `run/run_layer3_phase5.py`  | KLM 生命周期注册 | `phase5_klm_registry.jsonl` |

融合与冲突判定规则：

- 融合阈值按知识层生效：`CONCEPTUAL >= 2`，其他层保持 `>= 3`。
- `conflicted` 仅在“矛盾度超过层级阈值且 maturity 非 consolidated”时标记。
- 层级冲突阈值：`CONCEPTUAL/METACOGNITIVE = 0.30`，其他层为 `0.60`。

**当前产出**：137 条 KLM · 6 条 reflux-ready · 55 条冲突已标记

---

### Layer 4：缺口感知爬取

```
Layer 1 失败事件 (171 条)
        │
        ▼
src/layer4/gap_queue.py
  → GapSignal{dimension, sub_dim, target_service, search_queries}
        │
        ├─ P0 → dispatcher.handle_p0()  立即触发
        ├─ P1 → APScheduler 每日 02:00
        └─ 手动 → Dashboard /api/gap/crawl
        │
        ▼
CrawlWorker → CrawlerManager → csdn/github/qianxin/xianzhi
  → raw_data/layer4/
```

**入口**：`run/run_layer4_gap_dispatch.py`

---

## 4. 爬虫框架

所有爬虫相关代码（含 CLI 主入口和外部 KB 同步工具）统一位于 `crawlers/`：

```
crawlers/
├── main_crawler.py      # ★ 多源爬虫 CLI（交互式 + 命令行）
├── sync_data_light.py   # ★ 11 个外部安全数据库同步
├── crawler_manager.py   # 统一调度器
├── base_crawler.py      # BaseCrawler（所有爬虫基类）
└── [各数据源爬虫].py
```

### 4.1 类继承关系

```
BaseCrawler (抽象基类)
    │
    ├── CSDNVIPCrawler
    ├── GitHubCrawler
    ├── MITREAttackCrawler
    ├── QianXinCrawler
    ├── XianZhiCrawler
    └── [自定义爬虫]
```

### 4.2 扩展新爬虫

```python
# 1. 继承 BaseCrawler（参考 crawlers/example_crawler.py）
from crawlers.base_crawler import BaseCrawler

class MyNewCrawler(BaseCrawler):
    def crawl(self, query: str, max_pages: int = 5, **kwargs):
        # 实现爬取逻辑，返回字典列表
        return [{"title": ..., "content": ..., "link": ...}]

# 2. 注册到 CrawlerManager（crawlers/crawler_manager.py）
_CRAWLERS["mynew"] = lambda: MyNewCrawler()
```

---

## 5. RAGFlow 上传链路

```
Layer 2 (仅蒸馏，不上传)
    │
Layer 3 (融合)
    │
Layer 4 (缺口检测)
    │
Upload: src/ragflow_uploader.py
    │
RAGFlow 经验库 (http://8.140.33.83)
```

**上传规则**：
- `RAG_EVALUATION` 层排除（无检索价值）
- `run/run_full_pipeline.py` 末尾统一执行 `upload` 阶段
- `--no-ragflow` 跳过末尾上传（离线调试用，不影响蒸馏）

手动重新上传：

```bash
# 全量上传
python src/ragflow_uploader.py

# 重传指定 session
python src/ragflow_uploader.py --session <session_id>
```

---

## 6. 数据流全局视图

```
logs/*.jsonl
    │
    ▼ Layer 0
data/layer0_output/
    │
    ▼ Layer 1 (DeepSeek API)
data/layer1_output/
    │                    │
    ▼ Layer 2            ▼ Layer 4 GapQueue
data/layer2_output/   src/layer4/queues/gap_queue.jsonl
    │                         │
    ▼ Layer 3 XPEC            ▼ CrawlWorker
data/layer3_output/        raw_data/layer4/
    │
    ▼ Upload
RAGFlow 经验库（153 条已上传）
```

---

## 7. 配置系统

| 文件 | 用途 |
|:----|:----|
| `configs/config.yaml` | LLM API Key · RAGFlow 连接 · Layer 4 调度参数 |
| `crawlers/config.py` | 爬虫 Cookie / Token / 请求延迟 / 代理 |

---

## 8. 测试

```bash
cd LORE
python -m pytest tests/ -v   # 276 个用例
```

测试类型：单元测试（各层 src 模块）· 集成测试（端到端流程）· 爬虫测试（可选网络）

---

**文档版本**：v0.5.0 · **最后更新**：2026-03-18

