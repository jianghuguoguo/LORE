# Evo-Pentest Step 2 训练报告

## 1. 训练基础信息

### 数据集统计
- **总样本数**: 395
- **训练集**: 316 (80%)
- **测试集**: 79 (20%)
- **唯一查询数**: 14
- **正负比例**: 79:316 (20%:80%)

### 模型配置
- **模型**: cross-encoder/ms-marco-MiniLM-L-6-v2
- **参数量**: 22,713,601
- **Batch Size**: 16
- **Learning Rate**: 2e-5
- **Epochs**: 3
- **设备**: CPU

## 2. 训练过程

### Loss下降曲线
| Epoch | Train Loss |
|-------|-----------|
| 1     | 61.4119   |
| 2     | 5.1696    |
| 3     | 0.3795    |

**分析**: Loss从61.4降至0.38,下降99.4%,表明模型成功拟合训练数据。

### 评估指标(测试集)
所有epoch的评估指标均固定为:
| Metric | Score |
|--------|-------|
| MRR    | 0.3000|
| MAP    | 0.3000|
| NDCG@3 | 0.3000|
| NDCG@5 | 0.3000|
| NDCG@10| 0.3000|
| P@3    | 0.3000|
| P@5    | 0.3000|
| P@10   | 0.3000|

## 3. 数据质量问题诊断

### 问题1: 查询-文档分布极度不平衡
```
查询1 (69 docs): 17.4% 正样本  ✓ 合理
查询2 (65 docs): 0.0% 正样本   ✗ 无正例
查询3 (61 docs): 100% 正样本   ✗ 无负例
查询4 (55 docs): 0.0% 正样本   ✗ 无正例
查询5 (45 docs): 0.0% 正样本   ✗ 无正例
...
```

**影响**: 
- 100%正样本的查询导致Precision/NDCG恒为1.0
- 0%正样本的查询导致所有指标为0.0
- 平均后收敛到固定值0.3

### 问题2: Hindsight Labeling策略缺陷
**当前逻辑**: 
```
IF 攻击成功 AND 使用了search_knowledge工具:
    标注该次搜索的所有检索文档为正样本(label=1.0)
```

**缺点**:
- 未区分"使用的文档"vs"仅浏览的文档"
- 未考虑多次搜索的贡献度
- 导致某些查询下所有文档都被标注为正

### 问题3: 评估数据不足
- 只有14个查询,测试集约3-4个查询
- 无法代表真实场景的查询多样性
- 小样本导致指标方差大

## 4. 根本原因分析

auto_labeler.py的hindsight标注缺少**粒度控制**:

```python
# 当前实现(伪代码)
for success_event in trajectory:
    search_events = find_all_search_before(success_event)
    for search in search_events:
        for doc in search.all_docs:
            label(doc) = 1.0  # 全部标注为正
```

**应改为文档级贡献度打分**:
```python
# 推荐实现
for success_event in trajectory:
    last_search = find_nearest_search(success_event)  # 只考虑最近一次
    relevant_docs = extract_actually_used_docs(success_event)  # 从攻击payload中提取
    
    for doc in last_search.all_docs:
        if doc in relevant_docs:
            label(doc) = 1.0  # 真正有用的文档
        else:
            label(doc) = 0.0  # 检索但未使用的文档
```

## 5. 解决方案

### 短期方案(数据清洗)
1. **过滤无效查询**: 移除100%正样本和0%正样本的查询
2. **重新分层采样**: 只用有合理分布的查询(10%-90%正样本)
3. **扩充测试数据**: 从原始logs中提取更多查询

### 中长期方案(改进Labeling)
1. **实现文档级追踪**: 
   - 从success event的context/solution中提取关键信息
   - 计算每个检索文档与解决方案的相似度
   - 使用相似度作为label(0-1连续值)

2. **引入时间衰减**: 
   - 距离成功event越远的搜索,贡献度越低
   - 使用指数衰减: `label = relevance * exp(-λ * time_gap)`

3. **多次标注融合**:
   - 同一查询在不同轨迹中可能有不同结果
   - 使用投票或平均融合标签

## 6. 下一步行动

### 立即执行(数据修复)
```bash
# 1. 重新生成平衡数据集
python processors/auto_labeler_v2.py --balanced

# 2. 重新训练
python processors/trainer.py
```

### 待完成(原6步计划)
- [x] Step 1: Auto-labeling (已完成,需优化)
- [x] Step 2: Utility Scorer训练 (已完成,指标异常)
- [ ] Step 3: 反思模块 (Reflection Query Rewriter)
- [ ] Step 4: 知识扩展模块
- [ ] Step 5: 系统集成
- [ ] Step 6: 完整实验与论文

## 7. 技术债务记录
- [ ] evaluator.py的evaluate方法需要优化(当前复杂度O(n²))
- [ ] trainer.py的collate_fn应该提取为类方法
- [ ] 缺少数据增强(同义词替换、查询改写等)
- [ ] 缺少模型蒸馏到小模型的逻辑
- [ ] 缺少在线学习(continual learning)机制

---
**生成时间**: 2026-02-07  
**训练环境**: Windows + Python 3.10 + PyTorch CPU  
**模型保存路径**: attack_kb/models/best_model, attack_kb/models/final_model
