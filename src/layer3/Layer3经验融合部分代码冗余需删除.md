我把整套融合代码（SEC → EWC → RME → BCC → KLM）通读了一遍，把分析分成两部分：**A. 删 KLM 与时间衰减后必须做的连锁清理**，**B. 真正的架构冗余/不合理处**（你问的"其他还有什么"）。

------

## A. 删除 KLM 与时间衰减的连锁清理清单

| 位置          | 当前内容                                                     | 需要做的事                                                   |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `klm.py`      | 整个文件                                                     | 删除                                                         |
| `ewc.py`      | `_DECAY_LAMBDA*`、`_get_decay_lambda()`、`_calc_decay_factor()` | 删除                                                         |
| `ewc.py`      | `compute_weight_for_exp` 返回的 `w_decay` 字段               | 删除                                                         |
| `ewc.py`      | `weight_effective = weight × w_decay`                        | 改为 `weight_effective = weight`，或干脆只保留 `weight` 一个字段 |
| `ewc.py`      | 所有签名的 `now` 参数与 `datetime` 导入                      | 删除                                                         |
| `models.py`   | `LifecycleStatus` 枚举（5 态）                               | 删除——删 KLM 后只剩 `active` / `conflicted`，可以降级为常量字符串 |
| `models.py`   | `WeightedExperience.w_decay`                                 | 删除                                                         |
| `models.py`   | `BccResult.should_reflux`                                    | 删除（无消费者）                                             |
| `models.py`   | `ConsolidatedExp.merged_into`、`refluxed`                    | 删除（KLM 专用字段）                                         |
| `bcc.py`      | 行 343 `should_reflux = ...`                                 | 删除                                                         |
| `bcc.py`      | 行 451 `refluxed=False`、`merged_into=None`                  | 删除                                                         |
| `__init__.py` | `KLM` 相关导入与 `__all__` 条目                              | 删除                                                         |

这是机械性的，做完之后管线变成 `SEC → EWC → RME → BCC` 四段。

------

## B. 真正的架构冗余（建议你下手删/改的地方）

### B1. EWC 的四维权重过度设计，至少一半可删

当前权重模型：`w_raw = w_quality × w_maturity × w_outcome × w_coverage`，归一化到 [0.3, 1.0]。

逐一审视：

| 维度                                    | 问题                                                         | 建议                                                         |
| --------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `w_quality = confidence`                | 本来就是 EWC 最有信息量的维度                                | **保留**                                                     |
| `w_maturity ∈ {0.4, 0.7, 1.0}`          | 系统冷启动时所有源经验都是 raw=0.4，此维度退化为常数；删 KLM 后没有跨轮 reflux 写回 validated/consolidated 到源经验，这一维基本永远是 0.4 | **删除**                                                     |
| `w_outcome ∈ {0.6, 1.0, 1.5}`           | PROCEDURAL_NEG 集群里几乎全是 failure，整组都是 0.6，区分度为零；POS 集群里几乎全是 success，整组都是 1.5。**实际上只在 cluster 同时存在 POS/NEG 时才有作用**——而你的 SEC 已经按 layer 把它们分到不同 cluster 了 | **删除**（或仅作为 BCC 内部计算 contradiction 时的标签使用，不参与权重） |
| `w_coverage = n_cve/5 × 0.3 + 0.7`      | "覆盖更多 CVE 的经验更可信"在理论上站不住——多 CVE 经验常常是 Layer 2 提取时模糊的结果，可能恰恰是噪声 | **删除**                                                     |
| `_W_MIN=0.3, _W_MAX=1.0` Min-Max 归一化 | 归一化区间是为了让权重在 BCC 贝叶斯公式里"有最低保留"，但同 cluster 内经验差异本就不大，归一化后区分度更小，于是又加 `slot_in_turn × 0.0001` 微扰打破僵局——典型的"补丁套补丁" | **删除归一化**：直接用 `confidence` 当权重                   |

**激进方案**：EWC 整个模块退化为一行 `weight = confidence`，把 EWC 与 BCC 合并； **保守方案**：保留 EWC 模块作为权重计算的接口（便于以后扩展），但内部只保留 `w_quality`，删归一化。

无论哪种方案，`BUG-3` 和 `BUG-4` 的补丁注释都可以一起删除，因为问题根源（多维乘积+归一化压缩）也被一并消除了。

### B2. BCC 的"单轮双 Pass"是为已经被删的功能打的补丁

```
Pass 1：dominant_maturity=raw → 可能升到 validated
Pass 2：force dominant=validated → 判断能否到 consolidated
```

这套机制存在的唯一原因是模拟 Layer 5 的 reflux 把 consolidated 标记写回到源经验、让源经验下次迭代时是 validated。**KLM 删了之后这个 reflux 链路也没了**，双 Pass 在做一件不存在的事。

更根本的：删 KLM 后，"raw → validated → consolidated"的严格阶梯失去意义——源经验的 maturity 永远停在 raw，consolidated 标签只能挂在融合产物上。这种情况下成熟度其实是**融合产物的标签**而不是"经验的状态"。

**建议**：

- 删 `force_dominant_maturity` 参数与整个 Pass 2 逻辑

- 删 

  ```
  _decide_maturity
  ```

   中的"按 dominant_maturity 分支"，直接基于 

  ```
  (p_fused, n_independent, n_strong_counterex)
  ```

   三元组判定 final maturity：

  ```
  P_fused ≥ 0.80 且 n_ind ≥ 3 且 contra ≤ θ → consolidatedP_fused ≥ 0.60 且 n_ind ≥ 2                → validated其余                                        → raw
  ```

- BccResult 的 `upgraded`/`downgraded`/`old_maturity` 字段也可以删——它们隐含"源经验有成熟度状态"的假设，现在不再成立。

### B3. `_contradiction_score` 是死代码

`rme.py` 第 189 行 `return 0.0`——这个函数实际上总是返回 0。下游 BCC 用这个 0 判定 `contra ≤ 0.6`，于是这个安全阀**永远满足条件**。

```python
def _contradiction_score(wes):
    ...
    # 长达 25 行的预处理
    return 0.0  # 暂时归零
```

两条路：

- **删掉**：`MergeResult.contradiction_score` 字段、BCC 中所有 `contra ≤ θ` 判定、`_CONTRA_MAX` 和 `_CONTRA_MAX_META` 常量、`lifecycle_status="conflicted"` 分支——全部清掉
- **真正实现**：在 PROCEDURAL_NEG 集群内度量"同样 IF 条件下 THEN 的离散度"，或在 FACTUAL_LLM 集群内度量"同一 CVE 的 success vs failure 比例"

考虑到你前面提过想要"差异化的来源可信度"的论文叙事，建议选**真正实现**而非删。否则论文里宣称做了冲突检测，代码里却始终是 0，是要被审稿人 ablation 一查就穿帮的点。

### B4. `ConsolidatedExp.p_fused` 与 `confidence` 重复存储同一值

`bcc.py` 行 366：`new_confidence = round(p_fused, 4)`——两个字段始终相等。

**建议**：只保留 `confidence` 作主字段，把 `p_fused`、`n_independent_sessions`、`contradiction_score` 三个调试用的统计量放进 `metadata.fusion_stats: dict`：

```python
metadata["fusion_stats"] = {
    "p_fused": ...,
    "n_independent_sessions": ...,
    "contradiction_score": ...,
}
```

`ConsolidatedExp` 顶层字段瘦身到与 Layer 2 经验 schema 完全一致（exp_id / knowledge_layer / content / metadata / maturity / confidence / minority_opinions / provenance），便于写回主库。

### B5. `_build_cve_commands_map` 跨集群回填违反了 RME 的模块边界

`rme.py` 的 `_build_cve_commands_map` 从 PROCEDURAL_NEG 集群提取命令，回填到 FACTUAL_LLM 集群的 `cve_exploitation_map`。这是**跨等价集**的信息流动，但被塞在了"对单个等价集做融合"的 `_merge_factual_llm` 内部。

后果：

- `_merge_factual_llm` 的接口被迫多了一个 `cve_commands_map` 参数，与其他 `_merge_*` 函数签名不一致
- `merge_equivalence_set()` 因此需要特例处理 FACTUAL 分支（`rme.py` 行 1148-1151）
- 测试和审计变难——一个 cluster 的融合结果依赖另一个 cluster 的内容

**建议**：把它拆为独立的后处理步骤：

```python
def run_rme(wes_list):
    merge_results = [merge_equivalence_set(wes) for wes in wes_list]  # 纯单集群融合
    merge_results = _enrich_factual_with_neg_commands(merge_results)   # 显式后处理
    return merge_results
```

这样 RME 主循环干净，跨集群信息流动作为一个有名字的后处理阶段单独存在。

### B6. FACTUAL 内部分裂为 RULE/LLM 两条融合分支

`_merge_factual` 根据 `sub_dim` 后缀（FACTUAL::RULE / FACTUAL::LLM）路由到两个完全不同的融合函数，处理两套完全不同的字段结构（`discovered_facts` vs `cve_exploitation_map`）。

这本质上是 **Layer 2 提取阶段 schema 不统一的债务**被转嫁到 Layer 3。当前不是急需修的问题，但写论文时要注意：

- 这违反了"FACTUAL 是统一知识层"的叙事
- 在消融时不好讲——是融合一种 FACTUAL 还是两种？
- 长期看应该让 Layer 2 在提取时就把 rule-based 和 LLM-based 的 schema 对齐

**短期建议**：保留现状，但论文里把它写成"FACTUAL 的双子流融合"作为已知设计选择，而不是含糊地说 FACTUAL 融合。

------

## 删完之后的最终架构

清理完 A + B 后，融合管线变成：

```
SEC（语义等价聚类，4 层硬/软键匹配）
  ↓ EquivalenceSet
EWC（单维权重 = confidence，无衰减、无归一化）
  ↓ WeightedEquivalenceSet
RME（层特定融合 + FACTUAL 命令回填后处理）
  ↓ MergeResult + contradiction_score（真正实现）
BCC（贝叶斯独立证据合并 + 单 Pass 成熟度判定）
  ↓ ConsolidatedExp（schema 与 Layer 2 一致）
```

代码量预计减少 30-40%，每个部件的职责更清晰，且每一项都能说出"为什么需要它"。

------

## 优先级建议

如果你时间有限，按 ROI 排序：

1. **必做**（删 KLM 的连锁清理，否则代码跑不起来）：A 全部
2. **强烈建议**（论文严谨性）：B3（contradiction_score 死代码）—— 这是审稿人 ablation 会查穿帮的点
3. **建议**（架构简化）：B2（双 Pass）、B1（EWC 维度瘦身）
4. **可选**（代码整洁）：B4、B5、B6

要不要我直接给出 B1（EWC 瘦身到单维）+ B2（删双 Pass）+ B3（实现 contradiction_score）的具体代码 diff？