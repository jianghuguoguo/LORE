# Evo-Pentest: 渗透测试智能体 RAG 优化框架

## 概述

Evo-Pentest 是一个针对渗透测试场景的 RAG（检索增强生成）优化框架，通过**事后诸葛亮式标注 (Hindsight Labeling)** 和**效用驱动重排序 (Utility-Driven Reranking)** 提升知识检索的攻击实战价值。

### 核心创新点（论文亮点）

1. **后果驱动的自动标注 (Consequence-Driven Auto-Labeling)**
   - 从渗透日志中自动提取"导致成功攻击"的知识检索记录
   - 无需人工标注，降低数据获取成本

2. **攻击效用重排序模型 (Attack Utility Reranker)**
   - 训练 Cross-Encoder 评估知识对"拿到Shell"的贡献度
   - 超越语义相关性，聚焦实战价值

3. **学术级评估体系**
   - 实现 MRR, NDCG@K, MAP, Precision@K 等顶会标准指标
   - 提供完整的实验可复现代码

---

## 项目结构

```
processors/
├── evo_config.py          # 全局配置文件
├── auto_labeler.py        # 第一步：自动化标注引擎
├── dataset.py             # 第二步：数据集加载器
├── evaluator.py           # 第二步：评估指标计算
├── trainer.py             # 第二步：重排序模型训练器
└── test_framework.py      # 测试脚本

attack_kb/
├── data/
│   └── utility_dataset.jsonl  # 自动标注生成的训练数据
└── models/
    ├── best_model/            # 最佳模型检查点
    ├── final_model/           # 最终模型检查点
    └── training_history.json  # 训练历史记录

logs/                      # 原始渗透测试日志（JSONL 格式）
```

---

## 快速开始

### 环境要求

```bash
# Python 3.8+
pip install torch transformers sentence-transformers scikit-learn tqdm numpy
```

### 第一步：数据标注

从渗透测试日志中自动提取训练数据：

```bash
python processors/auto_labeler.py
```

**输出：**
- `attack_kb/data/utility_dataset.jsonl` - 包含 (Query, Document, Label) 三元组

**日志示例：**
```
2026-02-06 23:38:30 - INFO - Found 12 log files.
2026-02-06 23:38:30 - INFO - Processed cai_5db69512...jsonl, extracted 63 samples.
2026-02-06 23:39:03 - INFO - Finished! Total samples: 395
```

### 第二步：模型训练

训练 Cross-Encoder 重排序模型：

```bash
python processors/trainer.py
```

**训练过程：**
1. 数据集划分（80% 训练，20% 测试）
2. 使用 `cross-encoder/ms-marco-MiniLM-L-6-v2` 作为基线模型
3. 微调 3 个 Epoch
4. 每个 Epoch 结束评估 MRR, NDCG@K
5. 保存最佳模型到 `attack_kb/models/best_model/`

**预期输出：**
```
Epoch 1/3
Train loss: 0.1234
============================================================
Evaluation Results:
------------------------------------------------------------
  MRR                 : 0.7845
  MAP                 : 0.7321
  NDCG@3              : 0.8012
  NDCG@5              : 0.8234
  Precision@3         : 0.7500
✓ New best model saved! NDCG@5: 0.8234
============================================================
```

### 第三步：测试框架

验证所有模块是否正常工作：

```bash
python processors/test_framework.py
```

---

## 关键配置参数

在 `processors/evo_config.py` 中可调整：

```python
# 模型配置
RANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
MAX_LENGTH = 512

# 训练超参数
TRAIN_BATCH_SIZE = 16
NUM_EPOCHS = 3
LEARNING_RATE = 2e-5
WARMUP_STEPS = 100

# 评估配置
TEST_SPLIT = 0.2
K_VALUES = [3, 5, 10]  # 计算 NDCG@K, Precision@K
```

---

## 评估指标说明

### MRR (Mean Reciprocal Rank)
- **定义：** 第一个相关文档的平均倒数排名
- **取值范围：** 0-1，越高越好
- **意义：** 衡量"最优答案"是否排在前面

### NDCG@K (Normalized Discounted Cumulative Gain)
- **定义：** 考虑排序位置的归一化增益
- **取值范围：** 0-1，越高越好
- **意义：** 综合考虑相关性和排序质量

### MAP (Mean Average Precision)
- **定义：** 所有查询的 Average Precision 平均值
- **取值范围：** 0-1，越高越好
- **意义：** 衡量整体检索质量

### Precision@K
- **定义：** 前 K 个结果中相关文档的比例
- **取值范围：** 0-1，越高越好
- **意义：** 衡量精确率

---

## 使用训练好的模型

### 加载模型进行推理

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# 加载模型
model_path = "attack_kb/models/best_model"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)
model.eval()

# 对候选文档进行评分
query = "WebLogic CVE-2017-10271 exploit"
documents = [
    "WebLogic 反序列化漏洞利用...",
    "Tomcat 配置指南...",
    "Linux 权限提升技巧..."
]

scores = []
for doc in documents:
    inputs = tokenizer(query, doc, return_tensors="pt", max_length=512, truncation=True)
    with torch.no_grad():
        score = model(**inputs).logits.item()
    scores.append(score)

# 按分数排序
ranked_docs = sorted(zip(documents, scores), key=lambda x: x[1], reverse=True)
for doc, score in ranked_docs:
    print(f"[{score:.4f}] {doc[:50]}...")
```

---

## 论文实验建议

### Baseline 对比

推荐设置以下对照组：

1. **Baseline 1: BM25** - 经典 TF-IDF 检索
2. **Baseline 2: Dense Retrieval** - 纯向量检索（无重排序）
3. **Baseline 3: Semantic Reranker** - 通用的 Cross-Encoder（未针对渗透场景微调）
4. **Ours: Evo-Pentest** - 本框架训练的效用驱动重排序器

### 消融实验 (Ablation Study)

验证各模块的贡献：

- **w/o Hindsight Labeling**: 使用人工标注或弱监督标注
- **w/o Context**: 不使用攻击上下文，只用 Query-Document 对
- **w/o Fine-tuning**: 使用预训练模型直接推理

### 数据规模实验

研究数据量对性能的影响：

- 50, 100, 200, 395(full) 样本训练
- 绘制学习曲线

---

## 常见问题

### Q: 数据量太少怎么办？
A: 继续收集渗透测试日志。即使只有 100+ 样本，也能展示方法的有效性。论文中可以讨论"数据效率"（Few-shot Learning）。

### Q: 如何处理负样本不平衡？
A: `dataset.py` 已内置平衡批次采样。可在配置中调整 `TRAIN_BATCH_SIZE` 确保每批正负样本均衡。

### Q: 训练太慢怎么办？
A: 
- 减少 `MAX_LENGTH` 到 256
- 使用更小的模型如 `cross-encoder/ms-marco-TinyBERT-L-2-v2`
- 开启混合精度训练（需修改 `trainer.py` 添加 `torch.cuda.amp`）

### Q: 如何与 RAGFlow 集成？
A: 训练完成后，可将模型包装成 API 服务，作为 RAGFlow 的自定义 Reranker 插件。

---

## 引用

如果本框架对您的研究有帮助，请引用：

```bibtex
@inproceedings{evo-pentest-2026,
  title={Evo-Pentest: Hindsight-Driven Knowledge Reranking for Penetration Testing Agents},
  author={Your Name},
  booktitle={Conference Name},
  year={2026}
}
```

---

## 开发团队

- **核心算法**: 事后诸葛亮式标注 + 效用驱动重排序
- **技术栈**: PyTorch, Transformers, Sentence-Transformers
- **应用场景**: 渗透测试、红队自动化、网络安全

---

## License

MIT License
