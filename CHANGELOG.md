# Changelog

All notable changes to RefPenTest will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `run_full_pipeline.py` — 8 阶段全流程 CLI（Layer 0→1→2→3 Phase1+2→Phase3+4→Phase5→Layer4→Upload），末尾统一上传 RAGFlow
- `refpentest.py` — 交互式主入口（菜单选择单阶段运行 / 状态查看 / 手动上传）
- `crawlers/main_crawler.py` — 多源爬虫 CLI 迁入 `crawlers/` 包（原根目录版本保留为 shim）
- `crawlers/sync_data_light.py` — 外部 KB 同步工具从 `scripts/` 迁入 `crawlers/`，与爬虫代码统一管理
- `src/ragflow_uploader.py` — Layer 2 经验批量上传 RAGFlow，支持 `--session` 单 session 重传、`--dry-run` 预演
- `run_layer4_gap_dispatch.py` — Layer 4 独立运行脚本，含 `LocalKLMBackend` 集成冲突检测
- `CONTRIBUTING.md` — 贡献者指南（适配器开发 / 代码规范 / PR 流程）
- `SECURITY.md` — 安全策略与负责任披露流程

### Changed
- **Layer 2 不再在蒸馏阶段直接上传 RAGFlow**（固定 `--no-ragflow`），统一由 `upload` 阶段集中处理，避免重复条目
- **`--no-ragflow`** 含义变更：原控制 Layer 2 上传 → 现控制末尾 upload 阶段是否跳过
- `run_full_pipeline.py` 增加 `upload` 阶段（第 8 阶段），完整流水线为 7 个处理阶段 + 1 个上传阶段
- `src/log_adapter/` 保留为向后兼容 shim，规范位置为 `src/layer0/adapters/`

### Fixed
- `run_layer1_llm_batch.py` 缺少 `layer1_output/` 目录自动创建，运行首次报 `FileNotFoundError`
- `run_layer4_gap_dispatch.py` `ConflictDetector` 错误接收列表参数，改为正确使用 `LocalKLMBackend`
- Layer 3 / Layer 4 在上游输出文件为空时崩溃，改为返回空列表 + WARNING 日志

---

## [0.3.0] — 2026-02-06

### Added
- **Layer 0 格式适配层**：`AdapterRegistry`、`LogAdapter` 基类、4 个内置适配器（CAI / LangChain / OpenAI Assistants / Generic JSONL）
  - `AdapterRegistry.auto_detect()` 自动嗅探日志格式
  - `GenericJsonlAdapter` 支持自定义字段映射（`field_map` + `rag_tool_names`）
- `CanonicalAgentTurn` / `SessionMeta` / `RagQueryInfo` 统一数据模型
- `docs/04_Log Adapter  多框架日志接入指南.md` 用户文档
- Dashboard「格式适配器」状态卡（显示已注册适配器列表）

### Changed
- `src/layer0/__init__.py` 现在同时导出 Layer 0 核心 API 和适配层 API
- `src/log_adapter/` 改为向后兼容的 shim（转发到 `src.layer0`），不影响现有代码

### Fixed
- CAI 适配器对 `LogParser` 的循环导入问题（改用函数内懒导入）

---

## [0.2.0] — 2026-02-04

### Added
- **Layer 3 XPEC 跨会话融合框架**（Phase 1–5 完整实现）
  - Phase 1: Semantic Equivalence Clustering (SEC)
  - Phase 2: Evidence Weight Calculation (EWC)
  - Phase 3: Rule Merge Engine (RME)
  - Phase 4: Bayesian Confidence Calibration (BCC)
  - Phase 5: Knowledge Lifecycle Management (KLM) — 写入 `phase5_klm_registry.jsonl`
- `run_layer3_phase12.py` / `run_layer3_phase34.py` / `run_layer3_phase5.py` 独立运行脚本
- Layer 3 冲突报告：`data/layer3_output/conflict_report.jsonl`（当前 55 条冲突）
- KLM 知识节点类型：`CROSS_SESSION_RULE` / `ANTIPATTERN_DIGEST` / `KG_NODE`

### Changed
- Layer 2 `experience_raw.jsonl` 写入策略改为「全量覆盖」（修复追加重复 Bug）

---

## [0.1.0] — 2026-01-15

### Added
- **Layer 0**：日志解析流水线（`LogParser` → `EventExtractor` → `TurnSequenceAssembler`）
- **Layer 1**：语义标注层
  - 规则层（Phase 2）：RC-127 / RC-126 / TOUT 等确定性规则
  - LLM 语义层（Phase 3）：`attack_phase` / `failure_root_cause` / `session_outcome` / RAG 因果标注
  - `run_layer1_llm_batch()` 批量并发标注，支持会话续跑
- **Layer 2**：5 类知识经验提炼
  - `FACTUAL` / `PROCEDURAL_POS` / `PROCEDURAL_NEG` / `METACOGNITIVE` / `CONCEPTUAL`
  - `ExperienceBundle` 数据模型，支持 JSONL 持久化
- **Layer 4**：缺口感知自适应爬取
  - `GapSignalAnalyzer`：7 类缺口维度（INT/INCOMPLETE_RECON/DEF/PATCHED 等）
  - P0/P1 优先级调度，`queues/gap_queue.jsonl`
- **RAGFlow reflux**：`ragflow_uploader.py`，经验条目上传至向量数据库（经验库 / 完整语料库）
- **Dashboard**：Flask Web UI，`http://localhost:5000`
  - 卡片视图：Layer 1 统计、Layer 2 统计、Layer 4 缺口分析、RAGFlow 上传状态
- `scripts/sync_data_light.py` 已移至 `crawlers/sync_data_light.py`，外部 KB 同步与爬虫代码统一居住 `crawlers/`
- 爬虫：CSDN / GitHub / 奇安信 / 先知 / 微信公众号（WeChatArticleCrawler）

### Data Snapshot (v0.1.0)
- 处理日志：15 份 CAI 会话，分布于 2025-01 ~ 2025-12
- Layer 1 事件：415 条（171 次失败）
- Layer 2 经验：已提炼5类知识条目
- Layer 3 KLM：136 条，含 55 条待解决冲突

---

[Unreleased]: https://github.com/your-org/RefPenTest/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/your-org/RefPenTest/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/your-org/RefPenTest/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/RefPenTest/releases/tag/v0.1.0
