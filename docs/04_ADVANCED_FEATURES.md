# Evo-PentestRAG - 高级功能

## 🎯 自适应RAG系统详解

### System 2 反思机制

Evo-PentestRAG 的核心创新之一是引入了 **System 2 Reflection**（系统二反思）机制，让 RAG 系统能够像人类专家一样进行深度思考。

#### 工作原理

```
普通 RAG:
Query → 检索 → 返回结果 → 结束

自适应 RAG (Evo-PentestRAG):
Query → 检索 → 失败检测 → 反思诊断 → 查询改写 → 重新检索 → 经验总结
                    │              │             │
                    └──────────────┴─────────────┘
                          System 2 思考循环
```

#### 失败检测维度

```python
# processors/failure_detector.py

class FailureDetector:
    def detect(self, query, documents):
        """
        检测维度:
        1. 文档数量: 是否足够(通常需要 ≥3 篇)
        2. 相似度: 平均相似度是否达标(≥0.5)
        3. 内容完整性: 是否包含可执行的 Payload
        4. 版本匹配: 目标版本与文档版本是否一致
        """
        criteria = {
            'sufficient_docs': len(documents) >= 3,
            'good_similarity': avg_similarity(documents) >= 0.5,
            'has_payload': any(has_code(doc) for doc in documents),
            'version_match': check_version_consistency(query, documents)
        }
        
        return {
            'is_failed': not all(criteria.values()),
            'failed_criteria': [k for k, v in criteria.items() if not v],
            'confidence': calculate_confidence(criteria)
        }
```

#### 反思诊断类型

**1. Query Drift（查询漂移）**

**场景**: 搜索词与实际需求不匹配

```
原查询: "CVE-2024-12345 exploit"
问题: CVE 编号还未分配或不存在
诊断: Query Drift - 应使用产品名+漏洞特征
建议改写: "Product X version Y remote code execution"
```

**2. Granularity Mismatch（粒度失衡）**

**场景**: 内容过于宽泛或过于具体

```
原查询: "Linux提权"
问题: 太宽泛，结果包含数百种技术
诊断: Granularity - Too Broad
建议改写: 
  - "Linux kernel 4.x dirty cow 提权"
  - "Ubuntu sudo 权限绕过"
  - "Linux SUID 滥用提权"
```

**3. Version Conflict（版本冲突）**

**场景**: 文档版本与目标版本不匹配

```
目标: WebLogic 14.1.1.0
检索结果: 主要是 WebLogic 10.3.6 的漏洞
诊断: Version Conflict
建议改写: "WebLogic 14.1 vulnerability"（明确版本号）
```

**4. Domain Shift（领域偏移）**

**场景**: 搜索内容与目标环境不符

```
目标环境: Windows Server 2019
检索结果: 主要是 Linux 相关的技术
诊断: Domain Shift
建议改写: "Windows Server 2019 vulnerability exploit"
```

#### 查询改写策略

```python
# processors/query_rewriter.py

class QueryRewriter:
    def rewrite(self, original_query, diagnosis):
        strategies = {
            'expand': self._expand_query,      # 扩展查询
            'focus': self._focus_query,        # 聚焦查询
            'replace': self._replace_terms,    # 替换术语
            'struct': self._restructure        # 结构化
        }
        
        # 根据诊断类型选择策略
        if diagnosis['type'] == 'query_drift':
            return self._handle_drift(original_query)
        elif diagnosis['type'] == 'granularity_mismatch':
            return self._handle_granularity(original_query)
        # ...
```

**策略示例**:

```python
# 扩展策略
原查询: "SQL注入"
扩展后: [
    "SQL注入漏洞利用技术",
    "SQL injection bypass WAF",
    "SQL注入 union select payload"
]

# 聚焦策略
原查询: "Web漏洞"
聚焦后: [
    "SQL注入",
    "XSS跨站脚本",
    "CSRF跨站请求伪造"
]

# 替换策略
原查询: "RCE"
替换后: [
    "远程代码执行",
    "remote command execution",
    "arbitrary code execution"
]
```

---

## 🧠 HER（Hindsight Experience Replay）数据标注

### 什么是 HER？

HER 原本是强化学习中的技术，Evo-PentestRAG 将其创新地应用于渗透测试知识评估。

#### 核心思想

**从结果反推价值** - 不是在检索时判断文档是否有用，而是在攻击成功后回溯：哪些知识真正帮助了我？

```
传统标注方法:
人工阅读文档 → 主观判断 → 打标签 (费时费力,主观性强)

HER标注方法:
攻击日志分析 → 追踪因果链 → 自动打标签 (客观,可扩展)
```

### 标注流程

```python
# processors/auto_labeler_v2.py

class AutoLabelerV2:
    def extract_her_samples(self, log_file):
        """
        HER 标注流程:
        
        1. 解析日志: 按 Trace ID 分组
        2. 识别检索事件: 查找 make_kb_search
        3. 追踪执行结果: 检查后续 3 个步骤
        4. 自动打标签:
           - 如果后续成功获得 Shell → Label = 1.0
           - 如果后续失败或重试 → Label = 0.0
           - 如果无法判断 → 丢弃样本
        """
        samples = []
        
        for trace in self.group_by_trace(log_file):
            for event in trace:
                if event['type'] == 'make_kb_search':
                    label = self.evaluate_usefulness(
                        event,
                        trace[event.index + 1 : event.index + 4]
                    )
                    
                    if label is not None:
                        samples.append({
                            'query': event['query'],
                            'document': event['retrieved_doc'],
                            'label': label,
                            'context': event['context']
                        })
        
        return samples
```

### 标注示例

#### 示例 1: 正样本

```
[时间线]
10:01:23 - make_kb_search("WebLogic XMLDecoder")
          → 检索到文档: "CVE-2017-10271 分析与利用"
          
10:02:15 - execute_code(payload_from_doc)
          → 执行文档中的 Payload
          
10:02:30 - generic_linux_command("id")
          → uid=0(root) gid=0(root)  ✅ 成功!

[标注结果]
{
  "query": "WebLogic XML Decoder反序列化",
  "document": "CVE-2017-10271 文档内容...",
  "label": 1.0,  ← 文档确实有用!
  "reason": "该文档提供的Payload在3步内成功获得Shell"
}
```

#### 示例 2: 负样本

```
[时间线]
10:05:10 - make_kb_search("WebLogic 14.1 RCE")
          → 检索到文档: "WebLogic 10.3.6 漏洞分析"
          
10:06:00 - execute_code(payload_from_doc)
          → Error: 版本不匹配, Payload 无效
          
10:06:30 - make_kb_search("WebLogic 14 exploit")
          → 重新搜索 (说明第一次失败了)

[标注结果]
{
  "query": "WebLogic 14.1 RCE",
  "document": "WebLogic 10.3.6 文档内容...",
  "label": 0.0,  ← 文档无用!
  "reason": "版本不匹配导致Payload失效,Agent重新搜索"
}
```

---

## 🎓 Cross-Encoder 重排序模型

### 为什么需要重排序？

**向量检索的局限性**:
- 只看词汇相似度，不看实战价值
- 无法理解版本差异
- 不考虑攻击上下文

**解决方案**:
使用 Cross-Encoder 对 Top-50 结果进行"二次排序"，按照"实战有用性"重新排列。

### 模型架构

```
输入: [Query + Context] + Document
      ↓
┌──────────────────────────────┐
│   Tokenization               │
│   "WebLogic 14.1 RCE" +      │
│   "WebLogic 10.3.6 分析..."  │
└──────────────────────────────┘
      ↓
┌──────────────────────────────┐
│   Cross-Encoder              │
│   (ms-marco-MiniLM-L-6-v2)   │
│   - 12层 Transformer         │
│   - 22M 参数                 │
└──────────────────────────────┘
      ↓
┌──────────────────────────────┐
│   Sigmoid Layer              │
│   输出 Relevance Score       │
│   0.0 (无用) ~ 1.0 (极有用)  │
└──────────────────────────────┘
```

### 训练过程

```python
# processors/trainer.py

from sentence_transformers import CrossEncoder, InputExample
from torch.utils.data import DataLoader

def train_model(dataset_path, epochs=3):
    # 1. 加载数据
    samples = load_dataset(dataset_path)
    train_samples = [
        InputExample(
            texts=[s['query'], s['document']],
            label=s['label']
        )
        for s in samples
    ]
    
    # 2. 初始化模型
    model = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
    
    # 3. 训练
    train_dataloader = DataLoader(train_samples, shuffle=True, batch_size=16)
    model.fit(
        train_dataloader=train_dataloader,
        epochs=epochs,
        warmup_steps=100,
        evaluation_steps=1000
    )
    
    # 4. 保存
    model.save('models/evo_pentest_reranker')
```

### 使用示例

```python
from sentence_transformers import CrossEncoder

# 加载训练好的模型
reranker = CrossEncoder('models/evo_pentest_reranker')

# 原始检索结果 (Top-50)
candidates = ragflow.retrieve(query, top_k=50)

# 重排序
scores = reranker.predict([
    [query, doc['content']] for doc in candidates
])

# 按分数重新排序
reranked = sorted(
    zip(candidates, scores),
    key=lambda x: x[1],
    reverse=True
)[:3]  # 取 Top-3

# 结果
for doc, score in reranked:
    print(f"Score: {score:.3f} - {doc['title']}")
```

---

## 🔬 难负样本挖掘（Hard Negative Mining）

### 什么是难负样本？

**易负样本**: 明显不相关的文档
- 例如: 查询"SQL注入"，返回"机器学习入门"

**难负样本**: 看起来相关但实际无用的文档 ⭐
- 例如: 查询"WebLogic 14.1 RCE"，返回"WebLogic 10.3.6 RCE"
  - 语义非常相似 ✓
  - 但版本不对，Payload 无法使用 ✗

### 为什么重要？

模型需要学会识别"微妙的差异"：
- 版本号差异
- 系统环境差异
- 漏洞补丁状态

### 挖掘策略

```python
# processors/balance_dataset.py

class HardNegativeMiner:
    def mine(self, query, positive_doc):
        """
        挖掘策略:
        1. 版本变异: WebLogic 14.1 → 14.0, 12.2, 10.3
        2. 系统变异: Windows → Linux
        3. 时间过滤: 只保留旧版本的文档
        """
        hard_negatives = []
        
        # 策略 1: 版本邻近但不完全匹配
        if 'version' in query:
            target_ver = extract_version(query)
            similar_vers = get_nearby_versions(target_ver)
            for ver in similar_vers:
                modified_query = query.replace(target_ver, ver)
                neg_docs = retrieve(modified_query)
                hard_negatives.extend(neg_docs)
        
        # 策略 2: 系统环境差异
        if 'Windows' in query:
            linux_query = query.replace('Windows', 'Linux')
            hard_negatives.extend(retrieve(linux_query))
        
        return hard_negatives
```

---

## 📊 模型评估指标详解

### MRR (Mean Reciprocal Rank)

**定义**: 第一个相关文档的排名倒数的平均值

```python
def calculate_mrr(predictions):
    """
    例如:
    Query 1: 相关文档在第1位 → RR = 1/1 = 1.0
    Query 2: 相关文档在第3位 → RR = 1/3 = 0.33
    Query 3: 相关文档在第2位 → RR = 1/2 = 0.5
    
    MRR = (1.0 + 0.33 + 0.5) / 3 = 0.61
    """
    rr_sum = 0
    for pred in predictions:
        for rank, doc in enumerate(pred, 1):
            if doc['is_relevant']:
                rr_sum += 1 / rank
                break
    return rr_sum / len(predictions)
```

**意义**: 评估"第一个答案就命中"的能力

### NDCG@K (Normalized Discounted Cumulative Gain)

**定义**: 考虑排名位置和相关性程度的综合指标

```python
import numpy as np

def calculate_ndcg_at_k(predictions, k=3):
    """
    DCG@K = Σ (rel_i / log2(i+1))
    NDCG@K = DCG@K / IDCG@K
    
    例如 (K=3):
    排名  相关性  权重       贡献
    1     1.0    1/log2(2)  = 1.0
    2     0.8    1/log2(3)  = 0.50
    3     0.3    1/log2(4)  = 0.15
    
    DCG@3 = 1.0 + 0.50 + 0.15 = 1.65
    ```
    pass
```

**意义**: Top-K 结果的整体质量

### MAP (Mean Average Precision)

**定义**: 所有相关文档的平均精确度

```python
def calculate_map(predictions):
    """
    对于每个 Query:
    1. 累计计算每个相关文档位置的 Precision
    2. 取平均值
    3. 最后对所有 Query 取平均
    """
    aps = []
    for pred in predictions:
        precisions = []
        relevant_count = 0
        for rank, doc in enumerate(pred, 1):
            if doc['is_relevant']:
                relevant_count += 1
                precision_at_k = relevant_count / rank
                precisions.append(precision_at_k)
        
        if precisions:
            aps.append(np.mean(precisions))
    
    return np.mean(aps)
```

---

## 🚀 自定义爬虫开发

### 开发模板

```python
# crawlers/custom_crawler.py

from crawlers.base_crawler import BaseCrawler
from typing import List, Dict
import requests
from bs4 import BeautifulSoup

class CustomCrawler(BaseCrawler):
    """
    自定义爬虫模板
    """
    
    def get_source_name(self) -> str:
        """返回数据源名称"""
        return 'custom_source'
    
    def crawl(self, query: str, max_pages: int = 10, **kwargs) -> List[Dict]:
        """
        核心爬取逻辑
        
        Args:
            query: 搜索关键词
            max_pages: 最大爬取页数
            **kwargs: 额外参数
        
        Returns:
            爬取结果列表
        """
        results = []
        
        for page in range(1, max_pages + 1):
            # 1. 构造URL
            url = self._build_url(query, page)
            
            # 2. 发起请求
            response = self.session.get(url, timeout=30)
            if response.status_code != 200:
                self.logger.warning(f"请求失败: {url}")
                continue
            
            # 3. 解析内容
            soup = BeautifulSoup(response.text, 'html.parser')
            articles = soup.find_all('article', class_='post')
            
            for article in articles:
                item = self._parse_article(article)
                if self._validate_item(item):
                    results.append(item)
            
            # 4. 延迟
            self._random_delay()
        
        # 5. 保存
        filename = f"{self.get_source_name()}_{query}_{self._get_timestamp()}.json"
        self.save(results, filename)
        
        return results
    
    def _build_url(self, query: str, page: int) -> str:
        """构造搜索URL"""
        base_url = "https://example.com/search"
        params = {
            'q': query,
            'page': page
        }
        return f"{base_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    
    def _parse_article(self, article) -> Dict:
        """解析单篇文章"""
        return {
            'title': article.find('h2').text.strip(),
            'link': article.find('a')['href'],
            'date': article.find('span', class_='date').text,
            'summary': article.find('p', class_='summary').text.strip(),
            'site': self.get_source_name(),
            'scraped_time': self._get_timestamp()
        }
    
    def _validate_item(self, item: Dict) -> bool:
        """验证数据完整性"""
        required_fields = ['title', 'link', 'content']
        return all(item.get(field) for field in required_fields)
```

### 注册新爬虫

```python
# crawlers/crawler_manager.py

from crawlers.custom_crawler import CustomCrawler

class CrawlerManager:
    def __init__(self):
        # ...existing code...
        
        # 注册自定义爬虫
        self.register_crawler('custom', CustomCrawler(self.session))
```

---

## 🎨 Dashboard 高级定制

### 添加自定义标签页

```html
<!-- dashboard/templates/index.html -->

<ul class="nav nav-tabs">
    <!-- 现有标签页 -->
    <li class="nav-item">
        <a class="nav-link active" data-bs-toggle="tab" href="#control">控制面板</a>
    </li>
    
    <!-- 新增自定义标签页 -->
    <li class="nav-item">
        <a class="nav-link" data-bs-toggle="tab" href="#custom">我的功能</a>
    </li>
</ul>

<div class="tab-content">
    <!-- 新标签页内容 -->
    <div class="tab-pane fade" id="custom">
        <h3>自定义功能</h3>
        <button onclick="myCustomFunction()">执行操作</button>
        <div id="custom-result"></div>
    </div>
</div>
```

### 添加自定义 API

```python
# dashboard/app.py

@app.route('/api/custom_function', methods=['POST'])
def custom_function():
    """自定义功能 API"""
    try:
        data = request.json
        # 处理逻辑
        result = process_custom_logic(data)
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
```

---

## 📈 性能优化技巧

### 1. 缓存机制

```python
from functools import lru_cache
import hashlib

class CachedRetriever:
    def __init__(self):
        self.cache = {}
    
    @lru_cache(maxsize=128)
    def retrieve(self, query: str) -> List[Dict]:
        """带缓存的检索"""
        cache_key = hashlib.md5(query.encode()).hexdigest()
        
        if cache_key in self.cache:
            print("从缓存返回结果")
            return self.cache[cache_key]
        
        # 实际检索
        results = self._do_retrieve(query)
        self.cache[cache_key] = results
        return results
```

### 2. 批量处理

```python
def batch_upload_to_ragflow(documents: List[Dict], batch_size=10):
    """批量上传，减少API调用次数"""
    for i in range(0, len(documents), batch_size):
        batch = documents[i:i+batch_size]
        client.upload_batch(batch)
        time.sleep(1)  # 避免限流
```

### 3. 异步处理

```python
import asyncio
import aiohttp

async def async_crawl(urls: List[str]):
    """异步爬取多个URL"""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, url) for url in urls]
        return await asyncio.gather(*tasks)

async def fetch(session, url):
    async with session.get(url) as response:
        return await response.text()
```

---

## 🔒 安全最佳实践

### 1. API密钥管理

```python
# 使用环境变量
import os

RAGFLOW_API_KEY = os.getenv('RAGFLOW_API_KEY')
LLM_API_KEY = os.getenv('LLM_API_KEY')

# 或使用配置文件 + .gitignore
# config.local.py (不提交到Git)
API_KEYS = {
    'ragflow': 'your_key_here',
    'llm': 'your_llm_key'
}
```

### 2. 输入验证

```python
def validate_query(query: str) -> bool:
    """验证用户输入"""
    # 长度限制
    if len(query) > 500:
        return False
    
    # 危险字符过滤
    dangerous_chars = ['<', '>', '&', '"', "'"]
    if any(char in query for char in dangerous_chars):
        return False
    
    return True
```

### 3. Rate Limiting

```python
from time import time, sleep

class RateLimiter:
    def __init__(self, max_calls=10, period=60):
        self.max_calls = max_calls
        self.period = period
        self.calls = []
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            now = time()
            self.calls = [c for c in self.calls if now - c < self.period]
            
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                print(f"触发限流，等待 {sleep_time:.1f} 秒")
                sleep(sleep_time)
            
            self.calls.append(now)
            return func(*args, **kwargs)
        return wrapper

@RateLimiter(max_calls=5, period=60)
def call_llm_api(prompt):
    """每分钟最多调用5次"""
    pass
```

---

**文档版本**: v1.0  
**最后更新**: 2026年2月11日  
**下一篇**: [完整README](../README.md)
