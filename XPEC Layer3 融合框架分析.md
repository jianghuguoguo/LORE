***\*XPEC Layer3 融合框架\****

基于真实数据的字段级对齐核查 · 重复步骤识别 · 缺失补全方案

session: 5db69512 · 11条Layer2经验 · 44个Layer1标注事件

 

 

 

# ***\*§1  现有实现的数据流全貌\****

在深入分析每个Phase之前，先明确三个Layer的实际输出内容，这是所有衔接分析的数据基础。

## ***\*1.1  Layer0 — 日志标准化层\****

Layer0 输出的核心结构是 all_events 数组，每条事件包含：

**•** ***\*event_id:\**** 唯一标识，格式为 sessionId_turnIndex_slotIndex（如 5db69512_0001_00）

**•** ***\*call.action_category:\**** STRUCTURED_TOOL_CALL / GENERIC_COMMAND_CALL / RAG_QUERY / CODE_WRITE（4类，无语义判断）

**•** ***\*call.tool_name:\**** 原样保留（nmap_scan / generic_linux_command / make_kb_search / execute_code）

**•** ***\*result.return_code / timed_out / success:\**** 原始结果字段，不做成功失败判断

**•** ***\*has_rag_context:\**** true/false，仅表示时间窗口内是否有RAG调用

**•** ***\*rag_query_ref:\**** 关联到 rag_index 中的具体RAG查询对象

本次session统计：44个事件，其中 STRUCTURED_TOOL_CALL=5, GENERIC_COMMAND_CALL=33, RAG_QUERY=2, CODE_WRITE=4。

## ***\*1.2  Layer1 — 事件语义理解层\****

Layer1 在每条事件上叠加语义标注，生成 annotated_events，并在 session 级别计算综合指标：

**•** ***\*failure_root_cause.dimension:\**** ENV/INV/DEF/INT/EFF（五维分类，规则层+LLM层两阶段）

**•** ***\*failure_root_cause.sub_dimension:\**** 如 PERMISSION / INCOMPLETE_RECON / PATCHED / ACTIVE_BLOCKING 等

**•** ***\*attack_phase:\**** RECON_WEAPONIZATION / EXPLOITATION 等七维Kill Chain标注

**•** ***\*outcome_label:\**** success / failure / partial

**•** ***\*rag_adoption:\**** { level: 0-3, label: ignored/informed/direct, weight: 0-1.0 }（仅有rag_context的事件）

Session级别字段：***\*bar_score=0.6\****（2次RAG均为informed级别0.6，平均值）、***\*session_outcome.outcome_label='failure'\****。

## ***\*1.3  Layer2 — 经验提取层\****

Layer2 从语义标注后的事件流中提炼结构化经验，本次session产出11条（5层）：

| ***\*经验ID\****       | ***\*层级\****         | ***\*核心字段\****                                           | ***\*置信度\**** | ***\*成熟度\**** |
| ---------------------- | ---------------------- | ------------------------------------------------------------ | ---------------- | ---------------- |
| exp_5db69512_0001-0002 | FACTUAL×2 （rule提取） | open_port=7001, service=WebLogic 10.3.6.0 target_service+target_version+cve_ids | 0.75             | raw              |
| exp_5db69512_0003      | FACTUAL×1 （llm提取）  | exploitation_status + cve_context known_ineffective_vectors  | 0.80             | raw              |
| exp_5db69512_0004-0008 | PROCEDURAL_NEG×5       | decision_rule.IF/THEN/NOT/next_actions failure_dimension/sub_dimension | 0.72             | raw              |
| exp_5db69512_0009      | METACOGNITIVE×1        | decision_mistakes + key_lessons optimal_decision_path        | 0.60             | raw              |
| exp_5db69512_0010      | CONCEPTUAL×1           | pattern_type + core_insight retrieval_triggers               | 0.30             | raw              |
| exp_5db69512_0011      | RAG_EVALUATION×1       | rag_adoption_stats bar_score=0.6                             | 0.40             | raw              |

关键发现：每条经验的 ***\*metadata.applicable_constraints\**** 中均已包含 target_service='Oracle WebLogic Server', target_version='10.3.6.0', cve_ids=['CVE-2017-10271']。这三个字段直接对应 XPEC Phase 1 SEC 的 L1 硬键匹配所需输入。

 

 

# ***\*§2  Phase-1：语义等价聚类（SEC）衔接分析\****

## ***\*2.1  技术方案的对应部分\****

技术方案 Layer3 中定义了「同类判定标准」（三条优先级规则）：

1. cve_id 相同 → 直接认定为同类
2. target_service + attack_phase 均相同 → 认定为同类
3. knowledge_layer + root_cause_dimension 均相同 → 认定为潜在同类，由LLM确认

XPEC Phase 1 SEC 的四层匹配（L1硬键 / L2软键 / L3语义 / L4版本）是对上述三条规则的精确形式化和扩展，不是重新定义一套不同的逻辑。

## ***\*2.2  字段对齐：Layer2已有什么\****

| ***\*SEC匹配层级\****    | ***\*需要的字段\****           | ***\*Layer2中的位置\****                                     | ***\*状态\****                 |
| ------------------------ | ------------------------------ | ------------------------------------------------------------ | ------------------------------ |
| L1 硬键 （必要条件）     | knowledge_layer                | exp根级字段 knowledge_layer                                  | ✅ 完全就绪                     |
| L1 硬键 （必要条件）     | target_service                 | metadata.applicable_constraints.target_service （注意：NEG的content.target_service为空，需从metadata读） | ⚠️ 需改读路径                   |
| L1 硬键 （必要条件）     | failure_sub_dimension（NEG层） | content.failure_sub_dimension                                | ✅ 完全就绪                     |
| L2 软键 （强信号）       | cve_ids（交集≥1）              | metadata.applicable_constraints.cve_ids content.cve_ids（部分层） | ✅ 完全就绪                     |
| L2 软键 （强信号）       | path/endpoint（路径重叠）      | content.decision_rule.IF 中提取 content.known_ineffective_vectors | ⚠️ 需从文本中提取               |
| L3 语义 （辅助）         | decision_rule.IF 的向量嵌入    | 当前无预计算向量 需在SEC阶段实时计算cosine距离               | ❌ 需新增计算步骤               |
| L4 版本约束 （排除条件） | target_version版本族判断       | metadata.applicable_constraints.target_version               | ✅ 就绪（需添加版本族解析逻辑） |
| SSO规范化                | CVE别名 / 服务名规范化         | 无SSO层，但Layer1已使用标准CVE编号 服务名需额外规范化映射    | ⚠️ 需构建SSO小词典              |

## ***\*2.3  当前数据的SEC模拟结果\****

基于现有11条Layer2经验，按技术方案「同类判定标准」（即SEC的L1+L2匹配）进行模拟：

| ***\*模拟结果：1个等价集，8条经验满足同类条件（CVE-2017-10271相同）\**** |
| ------------------------------------------------------------ |
| Group[cve:CVE-2017-10271]：8条经验（2 FACTUAL_rule + 1 FACTUAL_llm + 5 NEG）→ 满足≥3触发条件 |
| 其中5条NEG按 failure_sub_dimension 进一步细分为5个子等价集： |
| NEG/INCOMPLETE_RECON: 1条 \| NEG/BLIND_EXECUTION: 1条 \| NEG/WRONG_ARGS: 1条 |
| NEG/PATCHED: 1条 \| NEG/ACTIVE_BLOCKING: 1条                 |
| ***\*关键判断：\****同CVE的不同sub_dimension的NEG不应合并——它们描述了同一目标的不同失败场景。SEC的L1必须以 knowledge_layer + failure_sub_dimension 联合作为硬键，而非仅CVE。 |

## ***\*2.4  SEC实现的核心工作量\****

**•** ***\*L1+L2实现（低工作量）：\****直接读取metadata.applicable_constraints字段匹配，一个字典lookup即可。Layer2数据完全支持。

**•** ***\*L3语义匹配（中等工作量）：\****需要对IF语句做embedding并计算cosine距离。建议使用已有embedding API，离线批量计算后缓存在metadata中。

**•** ***\*SSO构建（低工作量）：\****本项目CVE集合有限，只需维护一个几百条的别名映射字典（JSON文件），无需外部本体工程。

**•** ***\*版本族解析（低工作量）：\****解析 '10.3.6.0' → '10.3.x'，一个正则表达式规则即可。

 

 

# ***\*§3  Phase-2：证据权重计算（EWC）衔接分析\****

## ***\*3.1  现有字段与EWC公式的对应关系\****

EWC公式：W(E) = α × session_factor × β × maturity_factor × γ × outcome_factor

| ***\*EWC因子\**** | ***\*公式定义\****                       | ***\*Layer2实际字段\****                                     | ***\*已有值（示例）\****          |
| ----------------- | ---------------------------------------- | ------------------------------------------------------------ | --------------------------------- |
| session_factor    | session_bar_score × confidence           | metadata.session_bar_score × exp.confidence（根级字段）      | 0.6 × 0.72 = 0.432                |
| maturity_factor   | raw=0.4, validated=0.7, consolidated=1.0 | exp.maturity（根级字段）                                     | raw → 0.4                         |
| outcome_factor    | success=1.5, partial=1.0, failure=0.6    | metadata.session_outcome（字符串） → Layer1.session_outcome.outcome_label | failure → 0.6                     |
| W(E) 计算结果     | 归一化到[0.1, 1.0]                       | 归一化: 0.432 × 0.4 × 0.6 = 0.104                            | W≈0.11（raw级别低权重，符合预期） |

所有EWC输入字段均已在Layer2经验中存在，EWC只是对这些已有字段的正式计算公式化，不需要任何新数据。

## ***\*3.2  时效性衰减的实现接入点\****

时效性衰减 W_effective(E,t) = W(E) × exp(-λ × Δt) 需要 ***\*created_at\**** 字段（Layer2已有：metadata.created_at）和当前时间。

不同知识层的衰减率 λ 建议按技术方案的现有分类映射：

• PROCEDURAL_NEG/DEF类 → λ=0.005（CVE利用路径，约140天半衰期）

• PROCEDURAL_NEG/ENV类 → λ=0.010（工具使用，约70天，工具更新较快）

• METACOGNITIVE类   → λ=0.001（决策规则，约700天，极稳定）

• FACTUAL类      → λ=0.003（版本/服务信息，约230天）

 

 

# ***\*§4  Phase-3：规则融合引擎（RME）衔接分析\****

## ***\*4.1  技术方案的描述 vs RME的实现\****

技术方案 Layer3 提出三种融合类型（横向/纵向/通用化），并说明「LLM执行融合，规则引擎更新maturity字段」，但没有规定融合的具体算法。RME正是这个「LLM执行融合」的精确实现规范。

| ***\*技术方案融合类型\****       | ***\*映射到RME的操作对象\****                                | ***\*字段级融合算法\****                                     | ***\*状态\****       |
| -------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------- |
| 横向融合 同漏洞不同环境的FACTUAL | FACTUAL_LLM.cve_context （CVE地图汇聚）                      | cve_attempted取并集 exploitation_results按CVE分组加权投票 known_ineffective_vectors取并集+验证次数统计 | ✅ 可直接实现         |
| 纵向融合 同漏洞正向+负向经验     | PROCEDURAL_NEG.decision_rule （IF/THEN/NOT/next_actions融合） | IF：加权最大公约数 THEN：加权多数投票（阈值θ=0.4） NOT：取并集（任一建议均保留） next_actions：步骤对齐+最高权重版本 | ✅ 字段完整，算法新增 |
| 通用化提升 多框架攻击模式        | CONCEPTUAL.core_insight （综合洞察升级）                     | LLM对N条core_insight做语义合并 applicable_conditions.positive/negative 按频次加权排序 | ✅ 字段完整，LLM调用  |

## ***\*4.2  NEG融合的关键字段分析（最重要场景）\****

以当前5条PROCEDURAL_NEG经验为例，验证RME所需字段的完整性：

| ***\*PROCEDURAL_NEG 字段完整性核查（以 exp_5db69512_0004 为例）\**** |
| ------------------------------------------------------------ |
| content.decision_rule.IF: '在Oracle WebLogic侦察阶段，对非标准端口访问返回HTTP 404' |
| content.decision_rule.THEN: ['使用nmap确认端口', '测试wls-wsat端点']（数组，支持多数投票） |
| content.decision_rule.NOT: '不应继续使用错误端口'（字符串，取并集后变数组） |
| content.decision_rule.next_actions: [{step:1, tool:nmap, ...}, ...]（结构化步骤，支持步骤对齐） |
| content.evidence: 支撑证据（用于判断IF触发条件的合理性）     |
| ***\*结论：\****所有RME所需字段完整，但5条NEG的 sub_dimension 各不相同（INCOMPLETE_RECON/BLIND_EXECUTION/WRONG_ARGS/PATCHED/ACTIVE_BLOCKING），意味着这5条不应做横向合并，而是保留各自独立——RME的L1硬键（failure_sub_dimension）将正确处理这个情况。 |

## ***\*4.3  RME与技术方案的唯一真正差异\****

技术方案说「LLM执行融合」，但没有给LLM一个可操作的merge prompt模板。实际上，如果直接让LLM「把这3条经验合并成一条」，LLM会丢弃少数意见（minority opinions），因为它倾向于生成一致性强的单一答案。

RME的价值在于：在调用LLM之前，先用确定性算法计算出THEN的加权投票结果、NOT的并集，然后把这个结构化的「合并草稿」交给LLM来做语言润色和连贯性改写，而不是让LLM从头做合并决策。

| ***\*建议实现方式：两阶段合并\****                           |
| ------------------------------------------------------------ |
| ***\*第一阶段（确定性算法）：\****计算IF加权最大公约数、THEN加权票数、NOT并集、next_actions步骤对齐 → 生成结构化草稿JSON |
| ***\*第二阶段（LLM）：\****把草稿JSON+原始N条经验交给LLM，让其做语言自然化处理（保证IF是流畅的条件语句，THEN是清晰的操作建议） |
| ***\*这正是技术方案「LLM执行融合，规则引擎控制」原则的具体实现。\****不是新增职责，而是明确分工。 |

 

 

# ***\*§5  Phase-4：贝叶斯置信度校准（BCC）衔接分析\****

## ***\*5.1  技术方案的置信度更新 vs BCC（重叠分析）\****

***\*这是唯一一个存在概念重叠的Phase\****，需要仔细区分。技术方案Layer3有：

• 自动置信度升级：被引用且成功 → +0.05；被引用但失败 → -0.03；12个月未成功引用 → -0.02/月

XPEC BCC：P_fused = 1 - ∏(1 - Pᵢ × Wᵢ)，在merge时一次性计算consolidated经验的置信度。

这两个操作运行在完全不同的时间点：

| ***\*置信度更新的两个时间点（互补，不重复）\****             |
| ------------------------------------------------------------ |
| ***\*时间点A：融合时（BCC负责）\**** → 当3条raw经验合并为1条consolidated经验时 |
| 问题：这条新的consolidated经验应该有多高的初始置信度？       |
| 答案：P_fused = 1-(1-0.72×0.11)×(1-0.72×0.11)×... ≈ 0.65 → 已接近validated阈值 |
|                                                              |
| ***\*时间点B：运行时（技术方案Layer3负责）\**** → 当Agent在新session中检索并使用了该consolidated经验之后 |
| 问题：这次使用的结果如何？应该调整置信度吗？                 |
| 答案：若该次session成功 → +0.05；失败 → -0.03                |

两者共同作用：BCC给出合理的初始置信度（基于历史证据集合），技术方案的运行时更新在此基础上随实战表现动态调整。

***\*结论：\****BCC和技术方案的+0.05/-0.03机制不重复，各管一段，必须同时保留。

## ***\*5.2  maturity升级阈值与技术方案的对应\****

| ***\*maturity状态\****   | ***\*XPEC BCC升级条件\****         | ***\*技术方案表述\****                          | ***\*是否一致\****                            |
| ------------------------ | ---------------------------------- | ----------------------------------------------- | --------------------------------------------- |
| raw → validated          | P_fused ≥ 0.60 且独立来源n≥2       | ≥3条同类 + LLM确认                              | ✅ 逻辑一致，BCC提供了 量化判断替代「LLM确认」 |
| validated → consolidated | P_fused ≥ 0.80 且 n≥3 且无严重矛盾 | 技术方案未明确定义 validated→consolidated的条件 | ⚠️ XPEC补充了该条件的精确定义                  |
| consolidated → 降级      | 出现n≥2强反例(weight>0.7)          | 「冲突检测」触发降权，但未定义降级              | ⚠️ XPEC补充了降级规则                          |

 

 

# ***\*§6  Phase-5：知识生命周期管理（KLM）衔接分析\****

## ***\*6.1  KLM vs 技术方案Layer4（管理对象不同）\****

这是最容易混淆的地方，需要先明确管理对象：

| ***\*两套生命周期管理的对象边界\****                         |
| ------------------------------------------------------------ |
| ***\*技术方案 Layer4（知识库维护层）：\****管理的是主知识库（外部爬取的CVE文档、PoC代码、工具说明等），负责P0/P1/P2爬虫调度、冲突检测和清理。 |
| ***\*XPEC KLM（经验库生命周期管理）：\****管理的是Layer2提取的自生成经验（experiences.jsonl），负责raw→validated→consolidated状态转换、时效性衰减、回滚机制。 |
| ***\*两者管理不同的集合，互不干扰，都必须存在。\****主知识库是外部知识来源，经验库是自产知识沉淀，前者通过Layer4维护，后者通过KLM维护。 |

## ***\*6.2  当前schema与KLM所需字段的对比\****

| ***\*KLM所需字段\****                                        | ***\*Layer2当前状态\****                                     | ***\*需要的操作\****                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| lifecycle_status active/archived/suspended/conflicted/deleted | ❌ 当前只有 maturity 字段（raw/validated/consolidated） maturity管理知识成熟度，lifecycle管理物理状态，是不同维度 | 新增 lifecycle_status 字段（默认active）                     |
| merged_into 指向consolidated经验的exp_id                     | ❌ 当前schema无此字段 没有融合关系链，无法回滚                | 新增 merged_into: str \| null 融合时填写consolidated经验的exp_id |
| provenance（在consolidated经验中） source_exp_ids + weight_distribution | ❌ 当前source_exp_ids是原始事件IDs 不是layer3融合的源经验IDs  | consolidated经验增加 provenance 字段 与原有metadata.source_event_ids含义不同 |
| created_at（时效性衰减用）                                   | ✅ metadata.created_at 已存在                                 | 直接使用                                                     |
| maturity（状态机节点）                                       | ✅ exp.maturity 已存在（raw/validated/consolidated）          | 直接使用，KLM只需更新该字段                                  |
| confidence（衰减后重算用）                                   | ✅ exp.confidence 已存在                                      | 直接使用                                                     |

## ***\*6.3  Layer5经验回流在KLM中的位置\****

技术方案Layer5（经验回流层）：consolidated + confidence>0.8 → 写回主知识库，最高检索优先级。这个操作是KLM Phase 5的最终输出，而不是一个独立的系统层。

具体说：KLM的 lifecycle_status=active 且 maturity=consolidated 且 confidence>0.8 的经验，触发回流写入主知识库（或向量库的高优先级命名空间）。KLM既是Layer3的最后一个Phase，也是连接Layer3到Layer5的桥梁。

 

 

# ***\*§7  重复步骤完整清单与处置建议\****

综合以上分析，整理所有可能的重复点和处置建议：

 

| ***\*可能重复的内容\****                                     | ***\*实际关系\****                                           | ***\*处置建议\****                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 技术方案「同类判定标准」3条规则 vs XPEC Phase1 SEC 4层匹配   | 不重复：SEC是3条规则的 形式化+扩展。3条规则 ≈SEC的L1+L2部分  | 直接用SEC替换技术方案中 对「同类」的文字描述， 3条规则变成SEC的L1/L2实现 |
| 技术方案「自动置信度升级+0.05/-0.03」 vs XPEC Phase4 BCC贝叶斯公式 | 不重复：BCC是融合时的 初始置信度计算 +0.05/-0.03是运行时更新 | 两者并存：BCC在merge 时运行，+0.05/-0.03在 Agent引用经验后运行 |
| 技术方案Layer4「冲突检测」 vs XPEC Phase5 KLM「conflicted状态」 | 不重复：Layer4处理 外部KB冲突，KLM处理 经验库内部冲突        | 两者并存，各管各的 数据集合                                  |
| 技术方案Layer3「LLM执行融合」 vs XPEC Phase3 RME规则融合引擎 | 不重复：RME是「LLM执行融合」 的具体算法实现，明确了LLM 应该怎么做融合 | RME是技术方案Layer3 LLM融合的精确规范， 直接采纳             |

 

| ***\*真正需要删减的重复内容：无\****                         |
| ------------------------------------------------------------ |
| 经过仔细分析，XPEC 5个Phase与技术方案现有描述之间不存在需要删除的重复。所有看似重叠的内容都运行在不同时间点或管理不同对象。 |
| 技术方案提供了系统架构和运行逻辑（编排层），XPEC提供了具体算法（实现层），两者是纵向补充关系，不是横向竞争关系。 |

 

 

# ***\*§8  基于现有代码的最小化实现路线\****

## ***\*8.1  Schema修改（极小改动）\****

只需在Layer2的经验JSON schema中新增3个字段，现有数据无需迁移：

| ***\*经验JSON新增字段（3个）\****                            |
| ------------------------------------------------------------ |
| // 在 metadata 对象中新增：                                  |
| "lifecycle_status": "active"  // active\|archived\|suspended\|conflicted\|deleted，默认active |
| "merged_into": null       // 被融合后填写consolidated经验的exp_id |
|                                                              |
| // 在 consolidated 经验的 metadata 中新增：                  |
| "provenance": {                                              |
| "source_exp_ids": ["exp_5db69512_0004", "exp_8cb881bb_0007"], |
| "weight_distribution": {"exp_5db69512_0004": 0.52, "exp_8cb881bb_0007": 0.48}, |
| "fusion_algorithm": "XPEC-RME-v1.0",                         |
| "fusion_timestamp": "2026-03-01T10:00:00Z"                   |
| }                                                            |

## ***\*8.2  SEC实现的具体接入点\****

SEC可以以一个独立的 layer3_sec.py 模块实现，接受经验库列表作为输入：

| ***\*layer3_sec.py 接口设计\****                             |
| ------------------------------------------------------------ |
| def cluster_experiences(experiences: list[dict]) -> list[EquivalenceSet]: |
| """                                                          |
| 输入: Layer2输出的所有experience对象列表                     |
| 输出: 等价集列表，每个等价集包含:                            |
| - cluster_id: 等价集唯一ID                                   |
| - experiences: 属于该集合的经验列表                          |
| - version_constraint: 适用版本族（如 '10.3.x'）              |
| - trigger_level: 触发了哪个级别的匹配（L1/L2/L3）            |
| """                                                          |
|                                                              |
| # L1硬键匹配（直接用现有字段，无需额外计算）:                |
| l1_key = (exp['knowledge_layer'],                            |
| exp['metadata']['applicable_constraints'].get('target_service',''), |
| exp['content'].get('failure_sub_dimension',''))  # 仅NEG层   |
|                                                              |
| # L2软键匹配（CVE交集检测）:                                 |
| cve_ids = set(exp['metadata']['applicable_constraints'].get('cve_ids', [])) |

## ***\*8.3  优先级建议\****

| ***\*实现项目\****                                      | ***\*优先级\**** | ***\*工作量估计\**** | ***\*依赖前置\**** |
| ------------------------------------------------------- | ---------------- | -------------------- | ------------------ |
| 新增 lifecycle_status / merged_into 字段 （schema修改） | P0 必须          | 0.5天                | 无                 |
| Layer3 触发器：检测等价集≥3条的CVE组 （L1+L2硬键匹配）  | P0 必须          | 1天                  | schema修改完成     |
| EWC权重计算函数 （直接用现有字段，纯计算）              | P0 必须          | 0.5天                | 无                 |
| RME: FACTUAL_LLM CVE地图合并 （横向融合）               | P1 高优先        | 2天                  | SEC + EWC          |
| RME: NEG IF/THEN/NOT/next_actions合并 （纵向融合）      | P1 高优先        | 3天 （最复杂）       | SEC + EWC          |
| BCC贝叶斯置信度计算 （合并时调用）                      | P1 高优先        | 0.5天                | RME                |
| KLM lifecycle状态机 （active/archived/suspended转换）   | P1 高优先        | 1天                  | BCC                |
| SEC L3语义匹配（IF向量cosine距离）                      | P2 次优先        | 2天                  | embedding服务接入  |
| SSO小词典构建                                           | P2 次优先        | 1天                  | 人工整理CVE别名    |
| 回流触发器（→Layer5主知识库）                           | P2 次优先        | 1天                  | KLM完成            |

 

 

# ***\*§9  总结\****

基于对 layer0/layer1/layer2 实际数据的字段级核查，得出以下结论：

**•** ***\*数据就绪度高：\****Layer2经验中已包含XPEC所有Phase所需的绝大多数输入字段（target_service, target_version, cve_ids, failure_sub_dimension, IF/THEN/NOT, bar_score, maturity, confidence, created_at）。无需对现有提取逻辑做改动。

**•** ***\*无结构性冲突：\****XPEC的5个Phase是技术方案Layer3「经验成熟与融合」的算法内核，技术方案是架构编排，XPEC是具体实现，纵向补充关系。

**•** ***\*唯一概念重叠已厘清：\****BCC（融合时）与技术方案的+0.05/-0.03（运行时）分处不同时间点，两者协同而非竞争。

**•** ***\*Schema改动极小：\****仅需新增 lifecycle_status 和 merged_into 两个字段，不改变现有结构，现有数据无需迁移。

**•** ***\*注意一个当前Bug：\****NEG经验的 content.target_service 为空字符串，但target_service实际在 metadata.applicable_constraints.target_service 中。SEC的L1硬键必须从metadata读取，而非content。建议在下一版本的提取器中同步写入content。

 

 

 

 

XPEC Alignment Analysis · Based on session 5db69512 actual data · 2026

 