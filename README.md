# Evo-PentestRAG

<div align="center">

**Evolutionary Penetration Testing with Retrieval-Augmented Generation**

*一个创新的渗透测试知识库系统，结合多源数据爬取、RAG和自适应学习机制*

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)](https://github.com)

[English](./README_EN.md) | [中文](./README.md)

</div>

---

## 📖 目录

- [项目简介](#-项目简介)
- [核心特性](#-核心特性)
- [快速开始](#-快速开始)
- [系统架构](#-系统架构)
- [使用指南](#-使用指南)
- [高级功能](#-高级功能)
- [文档](#-文档)
- [贡献指南](#-贡献指南)
- [许可证](#-许可证)

---

## 🎯 项目简介

**Evo-PentestRAG** 是一个面向渗透测试场景的智能知识库系统，突破了传统RAG系统"只看语义相关性"的局限，引入了 **功能对齐（Functional Alignment）** 的创新理念——评估知识的价值不是看它与查询是否相关，而是看它能否帮助Agent **真正攻陷目标系统**。

### 核心创新

🧠 **System 2 Reflection** - 让RAG系统能够反思检索失败的原因并自动调整策略  
🎯 **HER-based Labeling** - 从攻击日志中自动提取训练数据，无需人工标注  
🔄 **Adaptive Query Rewriting** - 多维度诊断 + 智能查询改写  
🏆 **Hard Negative Mining** - 专门训练模型识别"看似有用实则无用"的过时知识

---

## ✨ 核心特性

### 1. 🕷️ 多源知识爬取

- **10+ 公开安全数据源**: CSDN、GitHub、MITRE ATT&CK、CVE、NVD、Exploit-DB等
- **动态爬虫 + 静态数据库**: 双轨并行，覆盖动态内容和历史数据
- **可扩展框架**: 插件化设计，5分钟添加新数据源

### 2. 🧠 智能RAG系统

- **自适应检索**: 基于攻击上下文动态调整检索策略
- **价值重排序**: Cross-Encoder模型按"实战价值"重新排序
- **失败反思**: System 2思考机制，从失败中学习并自动改写查询

### 3. 🔄 知识自进化

- **HER标注器**: 从攻击日志中自动提取训练样本
- **后果驱动**: 基于攻击成功与否自动打标签
- **经验积累**: 成功的攻击经验自动沉淀到知识库

### 4. 📊 可视化管理

- **Web Dashboard**: 实时监控爬取进度和系统状态
- **攻击轨迹**: 可视化展示检索-执行-反思全流程
- **模型训练**: 图形化展示训练进度和指标

---

## 🚀 快速开始

### 系统要求

- Python 3.8+
- 8GB+ RAM
- 20GB+ 磁盘空间

### 5分钟上手

```bash
# 1. 克隆项目
git clone <repository-url>
cd 语料

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置系统（编辑配置文件）
# processors/evo_config.py - RAGFlow和LLM配置
# crawlers/config.py - 爬虫配置

# 4. 启动Web Dashboard
cd dashboard
python app.py

# 5. 访问界面
# 打开浏览器: http://localhost:5000
```

### 快速测试

```bash
# 测试爬虫
python main_crawler.py --sources csdn --query "SQL注入" --max-pages 3

# 测试RAG检索
cd processors
python step3_usage_example.py

# 测试HER标注
python auto_labeler_v2.py
```

---

## 🏗️ 系统架构

### 总体架构

```
┌─────────────────────────────────────────────────────┐
│              应用层 (Application)                    │
│  Web Dashboard  │  CLI Interface  │  API Service   │
└─────────────────────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────┐
│              业务层 (Business)                       │
│  爬虫管理  │  RAG引擎  │  反思诊断  │  模型训练    │
└─────────────────────────────────────────────────────┘
                         │
┌─────────────────────────────────────────────────────┐
│              数据层 (Data)                           │
│  原始数据  │  向量库  │  日志  │  模型权重         │
└─────────────────────────────────────────────────────┘
```

### 核心工作流

```
数据获取 → 向量化 → 智能检索 → 反思优化 → 经验积累
    ↓         ↓          ↓          ↓         ↓
  爬虫     RAGFlow   AdaptiveRAG  诊断器    训练器
```

### 目录结构

```
语料/
├── crawlers/              # 爬虫模块
│   ├── base_crawler.py
│   ├── crawler_manager.py
│   ├── csdn_crawler.py
│   ├── github_crawler.py
│   └── ...
├── processors/            # RAG与训练模块⭐
│   ├── adaptive_retriever.py    # 自适应检索器
│   ├── failure_detector.py      # 失败检测器
│   ├── reflection_diagnoser.py  # 反思诊断器
│   ├── query_rewriter.py        # 查询改写器
│   ├── auto_labeler_v2.py       # HER标注器
│   ├── trainer.py               # 模型训练器
│   └── ...
├── dashboard/             # Web可视化界面
│   ├── app.py
│   ├── templates/
│   └── static/
├── raw_data/              # 原始数据存储
├── logs/                  # 攻击日志（用于HER）
├── docs/                  # 详细文档
│   ├── 01_OVERVIEW.md
│   ├── 02_ARCHITECTURE.md
│   ├── 03_USAGE_GUIDE.md
│   ├── 04_ADVANCED_FEATURES.md
│   └── REFLECTION_EXPERIENCE.md
└── requirements.txt
```

详细架构请参阅：[架构文档](./docs/02_ARCHITECTURE.md)

---

## 📚 使用指南

### 1. 数据爬取

#### 使用Web Dashboard（推荐）

```bash
cd dashboard
python app.py
# 访问 http://localhost:5000
```

#### 使用命令行

```bash
# 交互式
python main_crawler.py

# 命令行参数
python main_crawler.py --sources csdn,github --query "RCE漏洞" --max-pages 5

# 同步静态数据库
python sync_data_light.py
```

### 2. RAG检索

```python
from processors.adaptive_retriever import AdaptiveRetriever

# 初始化检索器
retriever = AdaptiveRetriever()

# 执行自适应检索
results = retriever.retrieve(
    query="如何利用WebLogic反序列化漏洞",
    context={
        'target': 'WebLogic 14.1.1.0',
        'os': 'Linux',
        'previous_attempts': []
    }
)

# 查看结果
for doc in results['documents']:
    print(f"{doc['title']} (相似度: {doc['similarity']:.3f})")
```

### 3. 模型训练

```bash
# Step 1: 从攻击日志提取训练数据
cd processors
python auto_labeler_v2.py

# Step 2: 训练Cross-Encoder模型
python trainer.py

# Step 3: 评估模型
python evaluator.py
```

详细使用指南请参阅：[使用文档](./docs/03_USAGE_GUIDE.md)

---

## 🔬 高级功能

### System 2 反思机制

**失败检测 → 反思诊断 → 查询改写 → 重新检索**

```python
# 1. 失败检测
detector = FailureDetector()
is_failed = detector.detect(query, documents)

# 2. 反思诊断
if is_failed:
    diagnoser = ReflectionDiagnoser()
    diagnosis = diagnoser.diagnose(query, documents)
    # 诊断类型: query_drift, granularity_mismatch, version_conflict...

# 3. 查询改写
rewriter = QueryRewriter()
new_queries = rewriter.rewrite(query, diagnosis)
# 生成3个不同维度的变体查询

# 4. 重新检索
for new_query in new_queries:
    results = retrieve(new_query)
```

### HER（Hindsight Experience Replay）标注

**从攻击后果反推知识价值**：

```
时间线：
10:01 - 检索文档A "WebLogic CVE-2017-10271"
10:02 - 执行文档A中的Payload
10:03 - 成功获得Shell ✅

标注结果：
文档A → Label = 1.0 (非常有用！)
```

### Cross-Encoder 重排序

**不只看相似度，更看实战价值**：

```
原始排序 (向量检索):
1. WebLogic 10.3.6 漏洞分析  (相似度 0.95)
2. WebLogic 14.1 RCE利用     (相似度 0.88)
3. WebLogic配置指南          (相似度 0.82)

重排序后 (Cross-Encoder):
1. WebLogic 14.1 RCE利用     (价值分 0.92) ← 版本匹配！
2. WebLogic 10.3.6 漏洞分析  (价值分 0.45) ← 版本不对
3. WebLogic配置指南          (价值分 0.18) ← 无Payload
```

详细高级功能请参阅：[高级功能文档](./docs/04_ADVANCED_FEATURES.md)

---

## 📊 数据源总览

### 动态爬虫数据源

| 数据源 | 说明 | 支持功能 |
|:------|:-----|:---------|
| **CSDN** | 中文技术博客 | VIP内容、评论抓取 |
| **GitHub** | 代码仓库和Issues | API Token支持 |
| **MITRE ATT&CK** | 攻击战术知识库 | STIX 2.1格式 |
| **先知/奇安信** | 中文安全社区 | 全站爬取 |

### 静态数据库源

| 数据库 | 说明 | 格式 |
|:------|:-----|:-----|
| **CVE List** | CVE漏洞列表 | JSON |
| **NVD** | 国家漏洞数据库 | JSON |
| **CISA KEV** | 已知被利用漏洞 | JSON |
| **Exploit-DB** | 漏洞利用代码 | Mixed |
| **CWE/CAPEC** | 漏洞分类/攻击模式 | XML |

---

## 📖 文档

### 核心文档

- 📘 [项目概述](./docs/01_OVERVIEW.md) - 项目背景、创新点、技术栈
- 📗 [系统架构](./docs/02_ARCHITECTURE.md) - 详细架构、模块设计、数据流
- 📙 [使用指南](./docs/03_USAGE_GUIDE.md) - 安装配置、基础使用、常见问题
- 📕 [高级功能](./docs/04_ADVANCED_FEATURES.md) - RAG深度优化、HER标注、模型训练
- 📔 [反思经验](./docs/REFLECTION_EXPERIENCE.md) - 系统演进、优化策略、最佳实践

### Dashboard文档

- [Dashboard README](./dashboard/README.md)
- [可视化指南](./dashboard/VISUALIZATION_GUIDE.md)
- [UI展示](./dashboard/UI_SHOWCASE.md)
- [功能对比](./dashboard/FEATURE_COMPARISON.md)

---

## 🔧 配置说明

### 爬虫配置 (crawlers/config.py)

```python
# CSDN配置（可选）
CSDN_COOKIE = 'your_cookie_here'

# GitHub配置（可选）
GITHUB_TOKEN = 'ghp_your_token_here'

# 数据源开关
ENABLED_SOURCES = {
    'csdn': True,
    'attack': True,
    'github': True,
    'qianxin': True,
    'xianzhi': True
}
```

### RAG配置 (processors/evo_config.py)

```python
class EvoConfig:
    # RAGFlow配置
    RAGFLOW_BASE_URL = "http://127.0.0.1:9380"
    RAGFLOW_API_KEY = "your_api_key"
    RAGFLOW_DATASET_ID = "语料库ID"
    RAGFLOW_EXPR_ID = "经验库ID"
    
    # LLM配置
    LLM_API_BASE = "https://api.deepseek.com/v1"
    LLM_API_KEY = "your_llm_key"
    LLM_MODEL = "deepseek-chat"
    
    # 检索配置
    TOP_K = 50
    RERANK_TOP_K = 3
    MAX_RETRY = 3
```

---

## ⚠️ 常见问题

### Q: 爬虫无法获取数据？

**检查清单**：
- [ ] Cookie和Token是否有效？
- [ ] 网络连接是否正常？
- [ ] 是否被目标网站限流？

**解决方法**：
```python
# crawlers/config.py
REQUEST_DELAY = (3, 5)  # 增加延迟
PROXIES = {  # 使用代理
    'http': 'http://127.0.0.1:7890',
    'https': 'http://127.0.0.1:7890'
}
```

### Q: RAGFlow推送失败？

```bash
# 测试连接
curl -X GET "http://127.0.0.1:9380/v1/datasets" \
  -H "Authorization: Bearer your_api_key"
```

### Q: 模型训练报错？

- `CUDA out of memory` → 减小 `BATCH_SIZE = 8`
- `数据集为空` → 确保 `logs/`目录有日志文件
- 缺少依赖 → `pip install sentence-transformers`

更多问题请查看：[使用指南 - 常见问题](./docs/03_USAGE_GUIDE.md#常见问题)

---

## 🎓 适用场景

### 学术研究
- ✅ 渗透测试Agent智能化研究
- ✅ RAG在垂直领域的应用
- ✅ 强化学习与知识检索结合

### 实战应用
- ✅ 自动化渗透测试工具链
- ✅ 安全知识库建设
- ✅ CTF辅助系统

### 教育培训
- ✅ 网络安全技能培训
- ✅ 漏洞利用知识库
- ✅ 攻防演练平台

---

## 🤝 贡献指南

我们欢迎所有形式的贡献！

### 如何贡献

1. **Fork 项目**
2. **创建特性分支** (`git checkout -b feature/AmazingFeature`)
3. **提交更改** (`git commit -m 'Add some AmazingFeature'`)
4. **推送到分支** (`git push origin feature/AmazingFeature`)
5. **提交Pull Request**

### 贡献类型

- 🐛 报告Bug
- 💡 提出新功能
- 📝 改进文档
- 🔧 提交代码
- 🌐 翻译文档

---

## 📊 项目现状

### 已实现 ✅

- ✅ 多源数据爬取（5+动态，10+静态）
- ✅ RAGFlow集成与推送
- ✅ 自适应检索系统
- ✅ System 2反思机制
- ✅ HER数据标注器
- ✅ Cross-Encoder训练框架
- ✅ Web可视化Dashboard

### 开发中 🚧

- 🚧 在线学习机制
- 🚧 多模态知识提取（VLM）
- 🚧 知识图谱构建
- 🚧 多Agent协作

### 计划中 📋

- 📋 自动化漏洞验证
- 📋 攻击链路推理
- 📋 对抗样本生成

---

## 📜 许可证

本项目采用 [MIT License](./LICENSE)

**⚠️ 免责声明**：本项目仅供学习和研究使用，请勿用于非法用途。使用者应遵守当地法律法规。

---

## 🌟 致谢

感谢以下开源项目：

- [RAGFlow](https://github.com/infiniflow/ragflow) - RAG框架
- [Sentence-Transformers](https://www.sbert.net/) - 语义模型
- [MITRE ATT&CK](https://attack.mitre.org/) - 攻击知识库
- [Flask](https://flask.palletsprojects.com/) - Web框架

---

## 📞 联系方式

- **项目主页**: [GitHub Repository](#)
- **问题反馈**: [Issues](#)
- **讨论交流**: [Discussions](#)

---

<div align="center">

**如果这个项目对你有帮助，请给个⭐️ Star支持一下！**

Made with ❤️ by Evo-PentestRAG Team

**版本**: v3.0 | **最后更新**: 2026年2月11日 | **状态**: 🚀 Active Development

</div>
