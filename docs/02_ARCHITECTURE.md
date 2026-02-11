# Evo-PentestRAG - 系统架构

## 📐 总体架构

Evo-PentestRAG 采用分层架构设计，由四个主要层次组成：

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层 (Application Layer)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Web Dashboard│  │ CLI Interface│  │ API Service  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                      业务层 (Business Layer)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 爬虫管理器   │  │ RAG引擎      │  │ 训练调度器   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 数据处理器   │  │ 反思诊断器   │  │ 经验提取器   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                      数据层 (Data Layer)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 原始数据     │  │ RAGFlow向量库│  │ 训练数据集   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 攻击日志     │  │ 模型权重     │  │ 配置文件     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                      基础设施层 (Infrastructure Layer)       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ 文件系统     │  │ HTTP Client  │  │ LLM API      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ 目录结构详解

```
语料/
├── 📁 crawlers/              # 爬虫模块
│   ├── __init__.py
│   ├── base_crawler.py       # 爬虫基类
│   ├── crawler_manager.py    # 爬虫管理器
│   ├── config.py             # 爬虫配置
│   ├── csdn_crawler.py       # CSDN爬虫
│   ├── github_crawler.py     # GitHub爬虫
│   ├── attack_crawler.py     # ATT&CK爬虫
│   ├── qianxin_crawler.py    # 奇安信爬虫
│   ├── xianzhi_crawler.py    # 先知爬虫
│   ├── example_crawler.py    # 示例爬虫
│   └── attack_core/          # ATT&CK核心处理
│       ├── config.py
│       ├── run_all.py
│       └── stix/             # STIX数据处理
│
├── 📁 processors/            # 数据处理与RAG模块
│   ├── __init__.py
│   ├── evo_config.py         # RAG配置
│   ├── adaptive_retriever.py # 自适应检索器⭐
│   ├── failure_detector.py   # 失败检测器
│   ├── reflection_diagnoser.py # 反思诊断器
│   ├── query_rewriter.py     # 查询改写器
│   ├── auto_labeler_v2.py    # HER数据标注器⭐
│   ├── trainer.py            # 模型训练器⭐
│   ├── evaluator.py          # 模型评估器
│   ├── dataset.py            # 数据集工具
│   ├── ragflow_client.py     # RAGFlow客户端
│   ├── llm_client.py         # LLM客户端
│   ├── vector_store.py       # 向量存储
│   ├── balance_dataset.py    # 数据平衡工具
│   ├── train_balanced.py     # 平衡训练
│   └── test_*.py             # 测试脚本
│
├── 📁 dashboard/             # Web可视化界面
│   ├── app.py                # Flask应用⭐
│   ├── templates/            # HTML模板
│   │   └── index.html
│   ├── static/               # 静态资源
│   │   ├── css/
│   │   └── js/
│   └── *.md                  # Dashboard文档
│
├── 📁 raw_data/              # 原始数据存储
│   ├── csdn/                 # CSDN数据
│   ├── github/               # GitHub数据
│   ├── attack/               # ATT&CK数据
│   ├── QIANXIN/              # 奇安信数据
│   ├── XIANZHI/              # 先知数据
│   ├── cve-database/         # CVE数据库
│   ├── nvd-database/         # NVD数据库
│   └── ...                   # 其他数据源
│
├── 📁 logs/                  # 攻击日志（用于HER）
│   └── cai_*.jsonl           # 攻击轨迹日志
│
├── 📁 docs/                  # 文档目录
│   ├── REFLECTION_EXPERIENCE.md # 反思经验⭐
│   ├── 01_OVERVIEW.md        # 项目概述
│   ├── 02_ARCHITECTURE.md    # 架构文档（本文件）
│   ├── 03_USAGE_GUIDE.md     # 使用指南
│   ├── 04_ADVANCED_FEATURES.md # 高级功能
│   └── ...
│
├── 📄 main_crawler.py        # 爬虫主入口⭐
├── 📄 sync_data_light.py     # 静态数据同步⭐
├── 📄 requirements.txt       # Python依赖
├── 📄 README.md              # 主文档（合并版）
└── 📄 优化方案.md            # 原始优化方案

⭐ = 核心文件
```

---

## 🧩 核心模块详解

### 1. 爬虫模块 (Crawlers)

#### 设计模式
- **基类模式**: 所有爬虫继承 `BaseCrawler`
- **管理器模式**: `CrawlerManager` 统一调度
- **插件化**: 易于扩展新数据源

#### 类图

```
┌─────────────────┐
│  BaseCrawler    │ (抽象基类)
├─────────────────┤
│+ crawl()        │
│+ save()         │
│+ validate()     │
└─────────────────┘
        △
        │ 继承
        │
    ┌───┴────────────────┬──────────────┬───────────┐
    │                    │              │           │
┌───▼────┐     ┌────────▼──┐  ┌────────▼──┐  ┌────▼────┐
│ CSDN   │     │ GitHub    │  │ ATT&CK    │  │ 先知    │
│Crawler │     │ Crawler   │  │ Crawler   │  │ Crawler │
└────────┘     └───────────┘  └───────────┘  └─────────┘
```

#### 工作流程

```
1. 初始化 → 2. 配置检查 → 3. 发起请求 → 4. 解析内容 → 5. 数据清洗 → 6. 保存到文件
```

#### 关键代码

```python
# crawlers/base_crawler.py
class BaseCrawler:
    def crawl(self, query: str, max_pages: int = 10, **kwargs):
        """爬取方法 - 子类必须实现"""
        raise NotImplementedError
    
    def save(self, data: List[Dict], filename: str):
        """统一的保存逻辑"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
```

---

### 2. RAG模块 (Processors)

#### 核心组件

##### 2.1 自适应检索器 (AdaptiveRetriever)

**职责**: 集成所有RAG组件的中枢系统

```python
# processors/adaptive_retriever.py
class AdaptiveRetriever:
    def __init__(self):
        self.failure_detector = FailureDetector()
        self.diagnoser = ReflectionDiagnoser()
        self.rewriter = QueryRewriter()
        self.ragflow_client = RAGFlowClient()
    
    def retrieve(self, query: str, context: Dict) -> List[Dict]:
        """
        自适应检索主流程：
        1. 初次检索
        2. 失败检测
        3. 反思诊断
        4. 查询改写
        5. 重新检索
        6. 经验总结
        """
        pass
```

**工作流程图**:

```
┌─────────┐
│ 初次检索 │
└────┬────┘
     │
     ▼
┌─────────┐     成功      ┌─────────┐
│失败检测  ├──────Yes─────→│ 返回结果 │
└────┬────┘               └─────────┘
     │ No
     ▼
┌─────────┐
│反思诊断  │ (识别问题类型)
└────┬────┘
     │
     ▼
┌─────────┐
│查询改写  │ (生成3个变体)
└────┬────┘
     │
     ▼
┌─────────┐
│重新检索  │ (最多3轮)
└────┬────┘
     │
     ▼
┌─────────┐
│经验总结  │ (推送到经验库)
└─────────┘
```

##### 2.2 失败检测器 (FailureDetector)

**职责**: 判断检索结果是否满足需求

```python
# processors/failure_detector.py
class FailureDetector:
    def detect(self, query: str, documents: List[Dict]) -> Dict:
        """
        检测维度:
        - 文档数量是否充足
        - 相似度分数是否达标
        - 内容完整性是否足够
        - 版本匹配度
        """
        return {
            'is_failed': bool,
            'reason': str,
            'confidence': float
        }
```

##### 2.3 反思诊断器 (ReflectionDiagnoser)

**职责**: 分析失败原因并给出诊断

```python
# processors/reflection_diagnoser.py
class ReflectionDiagnoser:
    def diagnose(self, query: str, documents: List[Dict]) -> Dict:
        """
        诊断类型:
        - query_drift: Query漂移
        - granularity_mismatch: 粒度不匹配
        - version_conflict: 版本冲突
        - domain_shift: 领域偏移
        """
        return {
            'diagnosis_type': str,
            'description': str,
            'suggestions': List[str]
        }
```

##### 2.4 查询改写器 (QueryRewriter)

**职责**: 基于诊断结果生成新查询

```python
# processors/query_rewriter.py
class QueryRewriter:
    def rewrite(self, original_query: str, diagnosis: Dict) -> List[str]:
        """
        改写策略:
        - 扩展: 添加相关术语
        - 聚焦: 缩小范围
        - 替换: 使用同义词
        - 结构化: 改变查询结构
        """
        return [query1, query2, query3]
```

---

### 3. 学习模块 (Training)

#### 3.1 HER数据标注器 (AutoLabelerV2)

**职责**: 从攻击日志中自动提取训练数据

```python
# processors/auto_labeler_v2.py
class AutoLabelerV2:
    def extract_her_samples(self, log_file: str) -> List[Dict]:
        """
        提取逻辑:
        1. 按Trace ID分组日志
        2. 识别检索事件
        3. 追踪后续执行结果
        4. 根据成功/失败打标签
        """
        return [
            {
                'query': str,
                'document': str,
                'label': float,  # 1.0 = 有用, 0.0 = 无用
                'context': Dict
            }
        ]
```

**后见之明标注原理**:

```
时间线: t0 ────────→ t1 ────────→ t2 ────────→ t3
       检索文档A    执行命令    命令成功      拿到Shell
         │                        │             │
         └────────────────────────┴─────────────┘
                  回溯: 文档A是有用的! → Label = 1.0
```

#### 3.2 模型训练器 (Trainer)

**职责**: 训练Cross-Encoder重排序模型

```python
# processors/trainer.py
class Trainer:
    def train(self, dataset_path: str, epochs: int = 3):
        """
        训练流程:
        1. 加载数据集
        2. 划分训练/测试集
        3. 初始化Cross-Encoder
        4. Fine-tuning
        5. 评估与保存
        """
        pass
```

**模型架构**:

```
输入: [Query + Context, Document]
  │
  ▼
┌─────────────────────┐
│ Cross-Encoder       │
│ (MiniLM-L-6-v2)     │
├─────────────────────┤
│ 12层Transformer     │
│ 384维隐藏层         │
└─────────────────────┘
  │
  ▼
输出: Relevance Score (0-1)
```

#### 3.3 模型评估器 (Evaluator)

**职责**: 评估模型性能

```python
# processors/evaluator.py
class Evaluator:
    def evaluate(self, model, test_set) -> Dict:
        """
        评估指标:
        - MRR (Mean Reciprocal Rank)
        - MAP (Mean Average Precision)
        - NDCG@K
        - Precision@K
        """
        return {
            'mrr': float,
            'map': float,
            'ndcg@3': float,
            'ndcg@5': float,
            'precision@3': float
        }
```

---

### 4. Web界面 (Dashboard)

#### 技术栈
- **后端**: Flask 2.0+
- **前端**: Bootstrap 5 + jQuery 3
- **图表**: Chart.js
- **实时通信**: Server-Sent Events (SSE)

#### 功能模块

```
┌─────────────────────────────────────────┐
│         Dashboard 功能模块              │
├─────────────────────────────────────────┤
│ 1. 爬虫控制面板                         │
│    - 数据源选择                         │
│    - 参数配置                           │
│    - 启动/停止                          │
├─────────────────────────────────────────┤
│ 2. 进度监控                             │
│    - 实时进度条                         │
│    - 统计数据                           │
│    - 彩色日志                           │
├─────────────────────────────────────────┤
│ 3. RAG测试                              │
│    - 自适应检索                         │
│    - 经验推送                           │
│    - 轨迹可视化                         │
├─────────────────────────────────────────┤
│ 4. 模型训练                             │
│    - HER数据提取                        │
│    - 模型训练触发                       │
│    - 训练进度监控                       │
├─────────────────────────────────────────┤
│ 5. 数据管理                             │
│    - 文件浏览器                         │
│    - 结果预览                           │
│    - 数据导出                           │
└─────────────────────────────────────────┘
```

#### API路由

```python
# dashboard/app.py
@app.route('/api/crawlers', methods=['GET'])
def get_crawlers():
    """获取所有爬虫信息"""
    pass

@app.route('/api/start', methods=['POST'])
def start_crawling():
    """启动爬取任务"""
    pass

@app.route('/api/adaptive_retrieve', methods=['POST'])
def adaptive_retrieve():
    """自适应检索API"""
    pass

@app.route('/api/train_model', methods=['POST'])
def train_model():
    """触发模型训练"""
    pass
```

---

## 🔄 数据流

### 完整数据流图

```
┌──────────┐
│ 数据源   │ (CSDN, GitHub, CVE...)
└────┬─────┘
     │
     ▼
┌──────────┐
│ 爬虫模块  │ (crawlers/)
└────┬─────┘
     │
     ▼
┌──────────┐
│ raw_data/ │ (JSON文件)
└────┬─────┘
     │
     ▼
┌──────────────┐
│ RAGFlow推送  │ (processors/ragflow_client.py)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ RAGFlow向量库│
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ Agent检索    │ (processors/adaptive_retriever.py)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ 攻击执行     │
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ logs/        │ (攻击日志)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ HER标注      │ (processors/auto_labeler_v2.py)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ 训练数据集   │ (dataset.jsonl)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ 模型训练     │ (processors/trainer.py)
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ Reranker模型 │
└────┬─────────┘
     │
     └──回到检索环节,形成闭环
```

---

## 🔐 配置系统

### 配置文件层级

```
1. crawlers/config.py        # 爬虫配置
2. processors/evo_config.py  # RAG配置
3. dashboard/app.py          # Web配置
```

### 核心配置项

```python
# processors/evo_config.py
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
    TOP_K = 50           # 初次检索数量
    RERANK_TOP_K = 3     # 重排序后返回数量
    MAX_RETRY = 3        # 最大重试次数
    
    # 训练配置
    BATCH_SIZE = 16
    LEARNING_RATE = 2e-5
    EPOCHS = 3
```

---

## 🧪 测试框架

### 测试结构

```
processors/
├── test_framework.py           # 测试框架基类
├── test_step3_complete.py      # Step3完整测试
├── test_llm_integration.py     # LLM集成测试
└── step3_usage_example.py      # 使用示例
```

### 测试覆盖

- ✅ 单元测试: 各模块独立测试
- ✅ 集成测试: 端到端流程测试
- ✅ 性能测试: 检索速度和准确率
- 🚧 回归测试: 持续集成

---

## 📊 性能优化

### 优化策略

1. **缓存机制**
   - LLM响应缓存
   - 向量检索结果缓存
   - 爬虫结果缓存

2. **并行处理**
   - 多线程爬虫
   - 批量RAGFlow推送
   - 异步LLM调用

3. **数据压缩**
   - JSON压缩存储
   - 向量量化

4. **懒加载**
   - 按需加载模型
   - 分页加载数据

---

## 🔒 安全考虑

### 安全措施

1. **API密钥管理**
   - 环境变量存储
   - 配置文件加密

2. **输入验证**
   - SQL注入防护
   - XSS防护
   - CSRF Token

3. **访问控制**
   - Rate Limiting
   - IP白名单
   - 认证授权

4. **日志审计**
   - 敏感信息脱敏
   - 操作日志记录

---

## 📈 扩展性设计

### 扩展点

1. **新数据源扩展**
   - 继承 `BaseCrawler`
   - 注册到 `CrawlerManager`

2. **新诊断类型**
   - 扩展 `ReflectionDiagnoser`
   - 添加自定义诊断逻辑

3. **新评估指标**
   - 扩展 `Evaluator`
   - 实现自定义指标计算

4. **新LLM后端**
   - 实现 `LLMClient` 接口
   - 适配不同API格式

---

**文档版本**: v1.0  
**最后更新**: 2026年2月11日
