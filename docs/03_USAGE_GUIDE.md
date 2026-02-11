# Evo-PentestRAG - 使用指南

## 🚀 快速开始

### 环境要求

- **操作系统**: Windows 10/11, Linux, macOS
- **Python**: 3.8 或更高版本
- **内存**: 建议 8GB 或以上
- **磁盘空间**: 至少 20GB（用于存储数据）
- **网络**: 稳定的互联网连接

### 安装步骤

#### 1. 克隆项目

```bash
git clone <repository-url>
cd 语料
```

#### 2. 创建虚拟环境（推荐）

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

#### 3. 安装依赖

```bash
pip install -r requirements.txt
```

#### 4. 配置系统

##### 4.1 爬虫配置

编辑 `crawlers/config.py`：

```python
# CSDN 配置（可选，用于访问VIP内容）
CSDN_COOKIE = 'your_csdn_cookie_here'

# GitHub 配置（可选，提高API限制）
GITHUB_TOKEN = 'ghp_your_github_token_here'

# 数据源开关
ENABLED_SOURCES = {
    'csdn': True,
    'attack': True,
    'github': True,
    'qianxin': True,
    'xianzhi': True
}
```

##### 4.2 RAG配置

编辑 `processors/evo_config.py`：

```python
class EvoConfig:
    # RAGFlow 配置
    RAGFLOW_BASE_URL = "http://127.0.0.1:9380"
    RAGFLOW_API_KEY = "your_ragflow_api_key"
    RAGFLOW_DATASET_ID = "your_dataset_id"
    RAGFLOW_EXPR_ID = "your_experience_dataset_id"
    
    # LLM 配置
    LLM_API_BASE = "https://api.deepseek.com/v1"
    LLM_API_KEY = "your_llm_api_key"
    LLM_MODEL = "deepseek-chat"
```

---

## 📚 基础功能

### 1. 数据爬取

#### 1.1 使用 Web Dashboard（推荐）

最简单的方式是使用 Web 界面：

```bash
cd dashboard
python app.py
```

然后打开浏览器访问 `http://localhost:5000`

**操作步骤**：
1. 在左侧面板勾选要使用的数据源
2. 输入搜索关键词（例如：`CVE-2024-23897`）
3. 设置最大爬取页数（建议 1-10）
4. 点击"开始爬取"按钮
5. 在"进度监控"标签页查看实时进度
6. 爬取完成后，在"爬取结果"标签页查看数据

#### 1.2 使用命令行（交互式）

```bash
python main_crawler.py
```

**交互流程**：
```
🔍 可用数据源:
1. csdn - CSDN技术博客
2. github - GitHub仓库和Issues
3. attack - MITRE ATT&CK知识库
4. qianxin - 奇安信攻防社区
5. xianzhi - 先知安全技术社区

请选择要爬取的数据源 (输入数字,多个用逗号分隔,或输入 'all'): 1,2
请输入搜索关键词 (直接回车表示爬取全部): SQL注入
请输入最大爬取页数 [默认: 10]: 5

开始爬取...
```

#### 1.3 使用命令行参数

```bash
# 爬取所有数据源
python main_crawler.py --all

# 指定数据源和关键词
python main_crawler.py --sources csdn,github --query "RCE漏洞"

# 指定爬取页数
python main_crawler.py --sources csdn --query "WebLogic" --max-pages 20

# 组合使用
python main_crawler.py --sources csdn,attack,xianzhi --query "反序列化" --max-pages 5
```

**参数说明**：
- `--all`: 爬取所有已启用的数据源
- `--sources <sources>`: 指定数据源（逗号分隔）
- `--query <keyword>`: 搜索关键词
- `--max-pages <num>`: 最大爬取页数

#### 1.4 同步静态数据库

除了动态爬虫，还可以同步公开的安全数据库：

```bash
python sync_data_light.py
```

这会下载以下数据库：
- CISA KEV（已知被利用漏洞）
- CVE List V5
- NVD Feeds
- CWE Database
- CAPEC Database
- D3FEND
- GitHub Advisory
- ZDI Advisories
- Exploit-DB
- Linux Vulns

**注意**：首次运行可能需要较长时间（取决于网络速度）。

---

### 2. 数据推送到 RAGFlow

爬取的数据需要推送到 RAGFlow 向量数据库才能被 RAG 系统使用。

#### 2.1 通过 Web Dashboard 推送

在爬取完成后，Dashboard 会自动提示是否推送到 RAGFlow。

#### 2.2 手动推送

```python
# 示例代码
from processors.ragflow_client import RAGFlowClient
import json

client = RAGFlowClient()

# 读取爬取的数据
with open('raw_data/csdn/csdn_SQL注入_20260211.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 推送到 RAGFlow
for item in data:
    client.upload_single_document(
        dataset_id="your_dataset_id",
        title=item['title'],
        content=item['content']
    )
```

---

### 3. RAG 检索测试

#### 3.1 通过 Web Dashboard

1. 访问 Dashboard 的"自适应检索"标签页
2. 输入查询内容（例如：`如何利用Weblogic反序列化漏洞`）
3. 点击"开始检索"
4. 查看检索结果和诊断信息
5. 如果结果满意，点击"总结经验并推送至 RAGFlow"

#### 3.2 通过 Python API

```python
from processors.adaptive_retriever import AdaptiveRetriever

# 初始化检索器
retriever = AdaptiveRetriever()

# 执行检索
results = retriever.retrieve(
    query="如何利用Weblogic反序列化漏洞",
    context={
        'target': 'WebLogic 12.2.1.3',
        'os': 'Linux',
        'previous_attempts': []
    }
)

# 查看结果
for idx, doc in enumerate(results['documents'], 1):
    print(f"{idx}. {doc['title']}")
    print(f"   相似度: {doc['similarity']:.3f}")
    print(f"   来源: {doc['source']}")
```

---

### 4. 模型训练

#### 4.1 从攻击日志提取训练数据

```bash
cd processors
python auto_labeler_v2.py
```

这会从 `logs/` 目录读取攻击日志，并生成训练数据集。

#### 4.2 训练 Cross-Encoder 模型

```bash
cd processors
python trainer.py
```

或使用平衡训练：

```bash
python train_balanced.py
```

#### 4.3 通过 Web Dashboard 训练

1. 访问 Dashboard 的"模型训练"标签页
2. 点击"提取HER经验"按钮
3. 等待数据提取完成
4. 点击"开始训练模型"
5. 实时查看训练进度和Loss曲线

---

## 📊 数据管理

### 查看爬取结果

#### 方式1: 文件浏览器

爬取的数据保存在 `raw_data/` 目录：

```
raw_data/
├── csdn/
│   └── csdn_SQL注入_20260211.json
├── github/
│   └── github_CVE-2024_20260211.json
├── QIANXIN/
│   └── qianxin_RCE_20260211.json
└── ...
```

#### 方式2: Web Dashboard

在 Dashboard 的"文件管理"标签页可以：
- 浏览所有数据文件
- 查看文件详情（大小、创建时间）
- 在线预览内容
- 下载文件

### 数据格式

爬取的数据统一为 JSON 格式：

```json
{
  "title": "WebLogic反序列化漏洞分析",
  "link": "https://blog.csdn.com/...",
  "date": "2024-01-15",
  "summary": "本文详细分析了WebLogic的反序列化漏洞...",
  "content": "完整文章内容...",
  "comments": "评论内容...",
  "is_vip": false,
  "site": "csdn",
  "scraped_time": "2026-02-11 10:30:00"
}
```

---

## 🔧 高级配置

### 自定义爬虫参数

在 `crawlers/config.py` 中可以调整：

```python
# 请求配置
REQUEST_TIMEOUT = 30  # 请求超时时间（秒）
REQUEST_DELAY = (1, 3)  # 请求延迟范围（秒）
MAX_RETRIES = 3  # 最大重试次数

# User-Agent 配置
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...',
]

# 代理配置（可选）
PROXIES = {
    'http': 'http://127.0.0.1:7890',
    'https': 'http://127.0.0.1:7890'
}
```

### RAG 检索参数调优

在 `processors/evo_config.py` 中：

```python
class EvoConfig:
    # 检索参数
    TOP_K = 50                    # 初次检索数量
    RERANK_TOP_K = 3              # 重排序后返回数量
    MAX_RETRY = 3                 # 最大重试次数
    SIMILARITY_THRESHOLD = 0.6    # 相似度阈值
    
    # 失败检测阈值
    MIN_DOCS_COUNT = 3            # 最少文档数量
    MIN_AVG_SIMILARITY = 0.5      # 最低平均相似度
    
    # 查询改写配置
    REWRITE_STRATEGIES = ['expand', 'focus', 'replace']
    MAX_REWRITES_PER_STRATEGY = 1
```

---

## ⚠️ 常见问题

### Q1: 爬虫无法获取数据？

**可能原因**：
- Cookie 过期（CSDN）
- API Token 无效（GitHub）
- 网络连接问题
- 被目标网站限流

**解决方法**：
1. 更新 Cookie 和 Token
2. 检查网络连接
3. 增加请求延迟： `REQUEST_DELAY = (3, 5)`
4. 使用代理

### Q2: RAGFlow 推送失败？

**检查清单**：
- [ ] RAGFlow 服务是否正在运行？
- [ ] API Key 是否正确？
- [ ] Dataset ID 是否存在？
- [ ] 网络连接是否正常？

**调试命令**：
```bash
curl -X GET "http://127.0.0.1:9380/v1/datasets" \
  -H "Authorization: Bearer your_api_key"
```

### Q3: 模型训练报错？

**常见错误**：

**错误1**: `CUDA out of memory`
```
解决: 减小 BATCH_SIZE
processors/evo_config.py:
BATCH_SIZE = 8  # 从16降到8
```

**错误2**: `数据集为空`
```
解决: 确保 logs/ 目录下有攻击日志
```

**错误3**: `No module named 'sentence_transformers'`
```
解决: pip install sentence-transformers
```

### Q4: Dashboard 无法访问？

**检查**：
```bash
# 查看端口是否被占用
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # Linux/macOS

# 修改端口（编辑 dashboard/app.py）
app.run(host='0.0.0.0', port=5001)
```

---

## 💡 最佳实践

### 1. 爬虫使用建议

- **关键词选择**: 使用具体的技术术语，避免过于宽泛
  - ✅ 好的关键词: `WebLogic XMLDecoder反序列化`
  - ❌ 不好的关键词: `漏洞`

- **爬取频率**: 控制爬取频率，避免被封IP
  - 建议: 每个数据源每天不超过 100 页

- **数据清洗**: 定期清理重复和低质量数据

### 2. RAG 使用建议

- **查询优化**: 提供足够的上下文信息
  ```python
  context = {
      'target': '具体目标系统',
      'version': '版本号',
      'os': '操作系统',
      'previous_attempts': ['已尝试的方法']
  }
  ```

- **结果验证**: 不要盲目信任检索结果，需要人工验证

- **经验积累**: 及时将成功的攻击经验推送到经验库

### 3. 训练建议

- **数据质量 > 数据数量**: 宁可少而精，不要多而杂
- **定期重训**: 每周或每月重新训练一次模型
- **评估监控**: 关注 MRR 和 MAP 指标的变化

---

## 📝 日常工作流

### 典型的一天工作流程

```
09:00 - 启动系统
  ├─ 启动 RAGFlow 服务
  ├─ 启动 Dashboard
  └─ 检查系统状态
  
10:00 - 数据爬取
  ├─ 根据最新安全动态选择关键词
  ├─ 启动爬虫
  └─ 推送数据到 RAGFlow
  
14:00 - RAG 测试
  ├─ 测试新爬取的数据质量
  ├─ 优化检索参数
  └─ 记录问题和改进点
  
16:00 - 模型训练
  ├─ 从日志提取新数据
  ├─ 训练模型
  └─ 评估效果
  
17:00 - 数据整理
  ├─ 清理重复数据
  ├─ 备份重要数据
  └─ 更新文档
```

---

## 🔄 系统维护

### 定期维护任务

**每天**:
- [ ] 检查爬虫运行状态
- [ ] 查看系统日志
- [ ] 备份新数据

**每周**:
- [ ] 更新 CSDN Cookie
- [ ] 清理重复数据
- [ ] 重新训练模型
- [ ] 性能评估

**每月**:
- [ ] 同步静态数据库
- [ ] 系统性能优化
- [ ] 安全审计
- [ ] 版本升级

---

## 📞 获取帮助

如遇到问题，可以：

1. **查阅文档**: 详细阅读 `docs/` 目录下的文档
2. **查看日志**: 检查 `logs/` 和控制台输出
3. **提交 Issue**: 在 GitHub 上提交问题
4. **社区讨论**: 参与项目讨论区

---

**文档版本**: v1.0  
**最后更新**: 2026年2月11日  
**下一篇**: [高级功能](./04_ADVANCED_FEATURES.md)
