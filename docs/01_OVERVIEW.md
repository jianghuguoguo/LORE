# LORE · 项目概述

## 项目简介

**LORE**（Reflective Penetration Testing）是一个面向渗透测试场景的多层级知识蒸馏与自适应补全系统。系统以真实渗透测试会话日志为原始输入，通过 **五层流水线**（Layer 0–4）自动提炼五类结构化经验，并创新性地引入 **Layer 4 缺口感知机制**——持续分析 Layer 1 失败标注，向知识盲区自动触发定向爬取，形成 **"发现缺口 → 补充知识 → 提升 Agent 能力"** 的闭环。

蒸馏产生的高置信知识条目（KLM）可通过 **RAGFlow reflux** 同步至向量数据库（`http://8.140.33.83`），直接服务于下游 RAG 检索，无需人工干预。

### 核心定位

不同于传统数据库或知识图谱，LORE 关注的是**从实际攻防对抗过程中提炼可复用的操作经验**：成功的漏洞利用步骤、导致失败的错误模式、高层次的决策规则，以及背景性概念知识。这些知识均由 LLM 和规则引擎从真实会话日志中自动抽取，经 Layer 3 XPEC 跨会话融合后注册为 KLM 知识条目，并可 reflux 至 RAGFlow 向量数据库。

---

## 核心特性

### 1. 五层经验蒸馏流水线

| 层次 | 输入 | 处理 | 输出 |
|:----|:----|:----|:----|
| **Layer 0** | `logs/*.jsonl` 原始会话日志 | 按会话拆分、格式标准化 | `data/layer0_output/` |
| **Layer 1** | Layer 0 输出 | LLM 批量标注（outcome / CVE / failure_root_cause） | `data/layer1_output/layer1_*.jsonl` |
| **Layer 2** | Layer 1 输出 | 规则 + LLM 经验提炼（5 类知识） | `data/layer2_output/experience_raw.jsonl` |
| **Layer 3** | Layer 2 输出 | XPEC 跨会话融合（Phase 1–5，KLM 注册） | `data/layer3_output/phase5_klm_registry.jsonl` |
| **Layer 4** | Layer 1/3 输出 | 缺口感知自适应爬取（Gap → GapSignal → 定向爬取） | `raw_data/layer4/` |

### 2. 五类结构化经验

| 知识层 | 枚举值 | 内容说明 |
|:------|:------|:--------|
| 事实性知识 | `FACTUAL` | CVE ID、CVSS 评分、受影响版本、利用前置条件 |
| 成功操作步骤 | `PROCEDURAL_POS` | 命令序列、成功指标、目标服务、置信度 |
| 失败负例 | `PROCEDURAL_NEG` | 失败命令、错误信息、失败原因分类、约束条件 |
| 元认知策略 | `METACOGNITIVE` | 关键教训、适用场景、决策规则 |
| 概念性知识 | `CONCEPTUAL` | 技术概念、漏洞原理、工具用法说明 |

### 3. Layer 3 XPEC 跨会话融合框架

Layer 3 是知识蒸馏的最终收口，执行五个连续阶段：

| Phase | 脚本 | 功能 |
|:------|:----|:----|
| Phase 1+2 | `run/run_layer3_phase12.py` | SEC 等价集聚类：将不同会话的相似失败模式归并，生成初级规则 |
| Phase 3+4 | `run/run_layer3_phase34.py` | RME 融合：冲突检测与消解，输出 `conflict_report.jsonl` |
| Phase 5   | `run/run_layer3_phase5.py`  | KLM 注册：写入 `phase5_klm_registry.jsonl` |

三类 KLM 知识节点：

| 类型 | 说明 |
|:----|:----|
| `CROSS_SESSION_RULE` | 多场景反复命中的决策规律，如 `RECON_BEFORE_EXPLOIT` |
| `ANTIPATTERN_DIGEST` | 高频失败根因聚合，辅助规避已知陷阱 |
| `KG_NODE` | 技战术级别的原子知识，供 RAG 精准召回 |

当前融合与冲突判定规则：

- 融合阈值按知识层生效：`CONCEPTUAL >= 2`，其余层保持 `>= 3`。
- `conflicted` 仅在“矛盾度超过层级阈值且 maturity 非 consolidated”时成立。
- 矛盾阈值分层：`CONCEPTUAL/METACOGNITIVE = 0.30`，其他层为 `0.60`。

### 4. Layer 4 缺口感知自适应爬取

**核心设计理念**：渗透测试 Agent 的反复失败 = 知识缺口的直接信号。

| 触发缺口维度 | 优先级 | 含义 |
|:-----------|:-----:|:----|
| `INT/INCOMPLETE_RECON` | **P0** 立即 | 情报认知缺口，对目标服务了解不足 |
| `INT/WRONG_ASSUMPTION` | P0 | 假设错误 |
| `DEF/PATCHED` | P1 每日 | 漏洞已修补，需绕过/替代方案 |
| `DEF/AUTHENTICATION` | P1 | 认证拦截 |
| `DEF/ACTIVE_BLOCKING` | P1 | 主动防御/WAF 拦截 |
| `INV/WRONG_ARGS` | P1 | 工具参数错误 |
| `ENV/BINARY_MISSING` | P1 | 工具缺失 |

缺口爬取可通过 Dashboard「经验缺口分析」卡片或 `POST /api/gap/crawl` API 触发。

### 5. RAGFlow Reflux

Layer 3 高置信 KLM 条目通过 `src/ragflow_uploader.py` 回流至 RAGFlow 向量数据库，可被 RAG Agent 直接检索。

### 6. 双轨数据采集

- **实时爬虫**（关键词驱动）：覆盖 CSDN / GitHub / 奇安信 / 先知 / 微信公众号 5 个安全数据源
- **外部知识库同步**：`crawlers/sync_data_light.py` 一键同步 11 个外部安全数据库
  （ATT&CK / CISA KEV / CWE / CAPEC / D3FEND / GitHub Advisory / ZDI / CVE / NVD / Exploit-DB / Linux Vulns）

### 7. Web 可视化管理 Dashboard

单页 Dashboard（`http://localhost:5000`）提供完整知识库管理能力：

| 功能 | 说明 |
|:----|:----|
| 五类经验浏览 | FACTUAL / PROCEDURAL / METACOGNITIVE / CONCEPTUAL 分类检索 |
| 会话浏览 | Layer 1 操作序列时间线、成功率统计 |
| 「开启反思」全流水线 | 顶栏紫色脉冲按钮，一键串行运行 Layer1 → Layer2 → Layer3 Phase1-5 |
| 融合经验库 | KLM 条目浏览 + **知识健康状态**（生命周期 + 冲突折叠表）+ **经验缺口分析**（Gap Score 横向条 + 内嵌爬取） |
| 爬虫管理 | 实时爬虫启动 · 外部知识库同步 · 原始数据 RAG 源管理 |

---

## 技术栈

### 蒸馏流水线

| 组件 | 技术 |
|:----|:----|
| 日志解析 | Python + JSONL |
| 规则提取器 | 纯 Python（正则 / 关键字匹配） |
| LLM 提取器 | DeepSeek（通过 OpenAI-compatible API） |
| LLM 客户端 | 自研 `src/llm_client.py`（支持 DeepSeek / OpenAI / Kimi / 通义千问） |
| 知识数据模型 | Pydantic dataclass（`src/models.py`） |
| XPEC 融合 | `src/layer3/`（SEC 聚类 + RME 融合 + KLM 注册） |
| RAGFlow 回流 | `src/ragflow_uploader.py` |
| 测试框架 | pytest（276 个测试用例，位于 `tests/`） |

### 数据采集

| 组件 | 技术 |
|:----|:----|
| 爬虫框架 | Requests + BeautifulSoup（`crawlers/`） |
| 外部 KB 同步 | Requests + ZIP/TAR 解压（`crawlers/sync_data_light.py`） |
| 数据存储 | JSON / JSONL 本地文件 |

### Dashboard

| 组件 | 技术 |
|:----|:----|
| 后端 | Flask 3.0 + Flask-CORS |
| 前端 | 原生 JS + Chart.js + Font Awesome |
| 实时通信 | Flask SSE（流水线日志推流） |
| 配置 | `configs/config.yaml` |

---

## 适用场景

- **安全研究**：从历史渗透测试日志中自动积累可复用的攻击经验
- **渗透测试 Agent 训练语料建设**：为 LLM Agent 提供结构化的 PROCEDURAL_POS / NEG 训练样本
- **RAG 知识库建设**：KLM 条目 reflux 至 RAGFlow，直接增强 Agent 检索能力
- **安全知识库管理**：聚合多源外部安全数据库（11 个），统一管理和浏览
- **攻防演练复盘**：通过 Dashboard 回溯会话操作序列、成功/失败原因

---

## 项目现状

### 已实现 ✅

- Layer 0 日志解析（按会话拆分）
- Layer 1 LLM 批量标注（15 份日志，415 事件，171 次失败）
- Layer 2 经验蒸馏（规则 + LLM，5 类经验，全量输出至 `experience_raw.jsonl`）
- Layer 3 XPEC 融合（Phase 1–5，KLM 注册 136 条，55 条冲突已记录）
- Layer 4 缺口感知爬取框架（`src/layer4/`，7 类缺口维度映射）
- RAGFlow Reflux（6 条高置信 KLM 已同步，`refluxed=True`）
- 实时爬虫框架（5 个数据源：CSDN / GitHub / 奇安信 / 先知 / 微信）
- 外部知识库同步（11 个数据库）
- Web Dashboard（融合全流水线触发 · 知识健康状态 · 经验缺口分析）
- pytest 测试套件（276 个用例）

### 进行中 🔄

- RAGFlow reflux 批量同步（目标：将全部 136 条 KLM 同步至 RAGFlow）
- Layer 4 自动调度稳定性优化

---

## 文档索引

- [01_OVERVIEW.md](./01_OVERVIEW.md) — 当前文档
- [02_ARCHITECTURE.md](./02_ARCHITECTURE.md) — 系统架构与模块设计
- [03_USAGE_GUIDE.md](./03_USAGE_GUIDE.md) — 安装配置与使用指南
- [../README.md](../README.md) — 项目主文档（快速参考）
- [../dashboard/README.md](../dashboard/README.md) — Dashboard 功能说明

---

**版本**: v0.5.0
**最后更新**: 2026年3月18日
**状态**: Active Development

