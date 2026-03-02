"""
Phase 3 Prompt 模板库
=====================
按任务类型分别定义 System Prompt 和 User Prompt 模板。
所有 prompt 均输出 JSON 格式，字段定义与 models.py 中的数据类对齐。

任务列表：
  TASK_FAILURE_CAUSE    - 五维失败根因分类（LLM 兜底层，处理规则未覆盖的失败）
  TASK_ATTACK_PHASE     - 七维 Kill Chain 阶段分类（所有事件全量处理）
  TASK_RAG_ADOPTION     - RAG 行为因果判定（仅 has_rag_context=true 的 RAG 查询）
  TASK_SESSION_OUTCOME  - 会话整体目标达成判定（每个 session 末尾执行一次）
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 公共 System Prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PENTEST_EXPERT = """\
你是一名资深渗透测试专家，具备深厚的漏洞利用、网络攻防和安全工程背景。
你正在分析一个自动化渗透测试 Agent 的执行日志，目的是对每次工具调用的\
行为进行结构化标注，以便后续构建经验知识库。

分析原则：
1. 基于工具调用的实际结果和上下文进行判断，不做假设。
2. 输出必须严格符合指定 JSON 格式，不添加任何额外字段或说明。
3. 如果信息不足，选择最合理的分类并在 reasoning 中说明不确定性。
4. 使用简洁、专业的中文描述 reasoning 字段内容。
"""


# ─────────────────────────────────────────────────────────────────────────────
# 任务一：五维失败根因分类
# 适用于：result 存在、规则层未覆盖、事件表现为失败
# ─────────────────────────────────────────────────────────────────────────────

FAILURE_CAUSE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：对一次工具调用失败进行五维根因分类。

五维根因框架定义：
  ENV（执行环境问题）
    - 失败原因在执行环境本身，与攻击策略无关
    - 换正确的环境配置就能成功
    - 典型子维度：BINARY_MISSING（工具未安装）/ DEPENDENCY_MISSING（依赖缺失）
                  PERMISSION（权限不足）/ TIMEOUT（执行超时）/ RESOURCE（资源耗尽）

  INV（调用方式问题）
    - 工具/命令的调用方式本身有误，与目标无关
    - 修正调用方式就能成功
    - 典型子维度：WRONG_ARGS（参数错误）/ WRONG_SYNTAX（语法错误）
                  WRONG_SEQUENCE（调用顺序错误）/ WRONG_CONFIG（配置错误）

  DEF（目标防御问题）
    - 目标存在主动或被动的防御机制阻止了攻击
    - 需要绕过防御或换方法才能成功
    - 典型子维度：AUTHENTICATION（认证失败）/ AUTHORIZATION（授权不足）
                  ACTIVE_BLOCKING（主动拦截，如WAF/IDS）/ RATE_LIMITING（速率限制）
                  PATCHED（漏洞已修补）/ MONITORING_DETECT（监控检测）

  INT（情报/认知问题）
    - 对目标或环境的认知不准确或不完整
    - 补充正确信息后才能成功
    - 典型子维度：WRONG_VERSION（版本判断错误）/ WRONG_TOPOLOGY（网络拓扑误判）
                  INCOMPLETE_RECON（侦察不足）/ WRONG_ASSUMPTION（前提假设错误）
                  MISSING_CONTEXT（缺失上下文信息）

  EFF（执行效果问题）
    - 命令/漏洞被成功触发，但效果与预期不符
    - 需要调整后渗透策略
    - 典型子维度：BLIND_EXECUTION（盲执行，无法确认效果）/ PARTIAL_SUCCESS（仅部分成功）
                  OUTPUT_LOST（输出丢失）/ UNSTABLE（效果不稳定）

输出严格 JSON（不得删减或添加字段）：
{
  "dimension": "ENV|INV|DEF|INT|EFF",
  "sub_dimension": "子维度标签（大写下划线格式）",
  "evidence": "100字以内的证据描述，引用具体的 stderr/stdout/return_code 内容",
  "remediation_hint": "50字以内的修复建议",
  "reasoning": "50-150字的分析推理过程",
  "search_queries": [
    "第1条英文搜索词：必须含目标服务名称 + 具体技术场景",
    "第2条英文搜索词：可含 CVE 编号（如相关）+ 操作目标",
    "第3条英文搜索词（可选）",
    "第4条英文搜索词（可选）"
  ]
}

【必填字段说明】

reasoning 不得为空字符串，必须包含：
  · 具体证据（引用 stderr/stdout/return_code 实际内容）
  · 归入该维度而非其他维度的逻辑
  · 如果信息不充分，说明判断的不确定性

search_queries 生成规则（2-4 条，必须全部为英文）：
  · 必须包含目标服务/组件名称（如已知：Oracle WebLogic、Apache CouchDB、Redis、Tomcat 等）
  · 若失败与已知 CVE 相关，至少 1 条包含 CVE 编号
  · 必须体现本次失败的具体技术场景（如：版本侦察不完整、认证绕过前置条件检查、补丁状态枚举）
  · 禁止使用纯通用词如 "pentesting technique"、"web application reconnaissance"、"exploit tutorial"
  · 正例（CVE-2017-10271 + WebLogic + 侦察缺口）：
      "CVE-2017-10271 Oracle WebLogic version fingerprint before exploitation"
      "WebLogic 10.3.x port 7001 service banner detection technique"
      "Oracle WebLogic patch status enumeration CVE-2017-10271"
"""


def build_failure_cause_prompt(
    tool_name: str,
    call_args: Dict[str, Any],
    return_code: Optional[int],
    stderr_raw: str,
    stdout_raw: str,
    success: Optional[bool],
    target_info: Optional[str] = None,
    context_summary: Optional[str] = None,
    raw_text: str = "",          # ← 新增：execute_code 的 _raw_text 兜底
) -> str:
    """构建失败根因分类的 User Prompt。"""
    target_part = f"\n渗透目标信息：{target_info}" if target_info else ""
    context_part = f"\n近期上下文：{context_summary}" if context_summary else ""

    # 截断过长的 raw 输出，避免超出 context 限制
    stderr_display = stderr_raw[:800] + "..." if len(stderr_raw) > 800 else stderr_raw
    effective_output = stdout_raw or raw_text  # 优先 stdout_raw，fallback 到 _raw_text
    effective_output_display = effective_output[:500] + "..." if len(effective_output) > 500 else effective_output

    # 过滤 call_args 中的大字段（如代码内容），避免 token 过长
    args_display = {
        k: (v[:300] + "..." if isinstance(v, str) and len(v) > 300 else v)
        for k, v in call_args.items()
    }

    return f"""\
请分析以下工具调用失败的根因：

工具名称：{tool_name}
调用参数：{args_display}
返回码（return_code）：{return_code}
执行成功（success字段）：{success}
标准错误输出（stderr）：
{stderr_display}
执行输出（stdout/raw，前500字）：
{effective_output_display}{target_part}{context_part}

请根据五维根因框架，输出 JSON 格式的分类结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# 任务二：七维 Kill Chain 行为功能分类
# 适用于：所有事件（全量，含 result=None 的中断事件）
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PHASE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：对一次工具调用进行七维 Kill Chain 行为功能分类。

七维 Kill Chain 框架定义：
  RECON_WEAPONIZATION（侦察与武器化）
    - 行为目标是"获取目标信息"或"制备攻击载荷"
    - 示例：端口扫描、目录枚举、漏洞扫描、shellcode 生成、exploit 脚本编写

  EXPLOITATION（漏洞利用 / 初始访问）
    - 主动触发漏洞以获取未授权初始访问权限
    - 示例：RCE 利用、SQL 注入、XXE 利用、反序列化攻击、弱口令爆破获取 shell

  ESCALATION（权限提升）
    - 在已有初始访问基础上提升权限
    - 示例：SUID 提权、内核漏洞提权、sudo 滥用、令牌窃取

  LATERAL_MOVEMENT（横向移动）
    - 从当前立足点访问其他系统/服务
    - 示例：内网扫描、SSH 横向、Pass-the-Hash、Kerberoasting

  EXFILTRATION（数据渗出）
    - 将目标数据传输到攻击者控制端
    - 示例：下载文件、外带查询结果、DNS 外带

  COMMAND_CONTROL（命令与控制）
    - 建立持久化访问通道
    - 示例：反弹 Shell 建立、后门安装、C2 心跳配置

  ENV_PREPARATION（环境准备，扩展维度）
    - 为攻击准备，但操作对象是攻击者本地环境而非目标
    - 示例：安装工具、检查本地 IP、创建临时目录、监听端口（本地 nc -l）

注意：
- 如果 result 为 null（工具尚未返回结果或执行被中断），仅根据工具名和参数推断行为意图。
- 注重工具调用的意图，而非执行结果（失败的漏洞利用仍属于 EXPLOITATION）。
- execute_code / generic_linux_command 工具：若代码内容包含 CVE 编号、exploit、payload、shell 注入等
  漏洞利用字样，且意图是向目标发送并触发漏洞 → 必须归为 EXPLOITATION，
  不得因“代码编写”而归为 RECON_WEAPONIZATION。
- outcome_label 精度规则：
  · 工具正常启动（rc=0）但 stdout 仅含版本/banner/版权/法律免责声明 →
    outcome_label 应为 failure 或 partial_success，不得为 success（工具启动 ≠ 漏洞利用成功）。
  · sqlmap/nikto/whatweb 等扫描工具仅输出启动信息而无实际扫描结果 → failure。
  · execute_code 被归类为 EXPLOITATION 后，仍需严格判断 outcome_label：
    - HTTP 状态码 200 仅表示 HTTP 请求成功，不代表命令执行成功；
    - 若 stdout/raw 中无命令回显（uid=/root@/文件内容），应判 failure，不得因“HTTP 200”而判 success/partial_success。

输出 JSON 格式：
{
  "attack_phase": "RECON_WEAPONIZATION|EXPLOITATION|ESCALATION|LATERAL_MOVEMENT|EXFILTRATION|COMMAND_CONTROL|ENV_PREPARATION",
  "outcome_label": "success|partial_success|failure|timeout|unknown",
  "reasoning": "50-150字的分类依据"
}
"""


def build_attack_phase_prompt(
    tool_name: str,
    call_args: Dict[str, Any],
    action_category: str,
    return_code: Optional[int],
    success: Optional[bool],
    timed_out: bool,
    stderr_raw: str,
    stdout_raw: str,
    has_result: bool,
    target_info: Optional[str] = None,
    program_name: Optional[str] = None,
    raw_text: str = "",          # ← 新增：execute_code 的 _raw_text 兜底
) -> str:
    """构建行为功能分类的 User Prompt。"""
    target_part = f"\n渗透目标：{target_info}" if target_info else ""
    prog_part = f"\n首个程序名（generic_linux_command）：{program_name}" if program_name else ""

    # 截断大字段
    args_display = {
        k: (v[:400] + "..." if isinstance(v, str) and len(v) > 400 else v)
        for k, v in call_args.items()
    }
    stderr_display = stderr_raw[:400] + "..." if len(stderr_raw) > 400 else stderr_raw
    effective_output = stdout_raw or raw_text  # 优先 stdout_raw，fallback 到 _raw_text
    effective_output_display = effective_output[:400] + "..." if len(effective_output) > 400 else effective_output

    result_section = ""
    if has_result:
        result_section = f"""
执行结果：
  return_code={return_code}, success={success}, timed_out={timed_out}
  stderr（前400字）：{stderr_display}
  执行输出（stdout/raw，前400字）：{effective_output_display}"""
    else:
        result_section = "\n执行结果：【无结果 - 工具执行可能被中断或未返回，请仅根据工具调用意图分类】"

    return f"""\
请对以下工具调用进行七维 Kill Chain 行为功能分类：

工具名称：{tool_name}
行为类别（Layer 0 分类）：{action_category}
调用参数：{args_display}{prog_part}{result_section}{target_part}

请根据七维框架输出 JSON 格式的分类结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# 任务三：RAG 行为因果判定
# 适用于：每个 has_rag_context=true 的 RAG 查询（make_kb_search 调用）
# ─────────────────────────────────────────────────────────────────────────────

RAG_ADOPTION_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：判断一次 RAG 检索调用的后续行为采纳情况。

这是本项目最核心的评估任务——判断 Agent 在查询知识库后，是否真正利用了
检索到的知识。"相似度高"不等于"真正被采纳"，你需要分析行为证据。

采纳度四级定义：
  Level 3 - direct（直接引用，权重 1.0）
    - 后续 tool_call 的参数/代码中包含 RAG 内容中的具体字符串
    - 例如：RAG 返回了某个 CVE 的具体 payload 代码，Agent 后续直接使用该代码

  Level 2 - informed（参考改写，权重 0.6）
    - 后续行为的技术路线与 RAG 内容一致，但具体命令/代码由 Agent 自行生成
    - 例如：RAG 返回"使用 gobuster 枚举目录"，Agent 确实随后运行了 gobuster

  Level 1 - conceptual（思路启发，权重 0.3）
    - RAG 内容影响了攻击方向选择，但具体技术路线不同
    - 例如：RAG 返回"WebLogic 反序列化漏洞描述"，Agent 转而尝试反序列化路径
              但使用了完全不同的工具和 payload

  Level 0 - ignored（未采纳，权重 0.0）
    - 后续行为与 RAG 内容无任何关联
    - 例如：RAG 返回了 CVE 说明，Agent 继续执行与该 CVE 无关的操作

判断要点：
1. RAG 返回的是什么类型的内容（漏洞描述/PoC代码/工具文档）？
2. 后续3步的工具调用与 RAG 内容的关联性有多强？
3. 是"Agent 自有知识恰好一致"还是"RAG 真正贡献了新信息"？

输出 JSON 格式：
{
  "adoption_level": 0~3,
  "adoption_label": "ignored|conceptual|informed|direct",
  "adoption_weight": 0.0|0.3|0.6|1.0,
  "reasoning": "100-200字的详细分析，说明判定依据"
}
"""


def build_rag_adoption_prompt(
    rag_query: str,
    rag_result_summary: str,
    behavior_window: List[Dict[str, Any]],
    target_info: Optional[str] = None,
) -> str:
    """构建 RAG 行为因果判定的 User Prompt。

    Args:
        rag_query         : RAG 查询内容
        rag_result_summary: RAG 返回内容摘要（前600字）
        behavior_window   : 后续 N 步工具调用列表（每项含 tool_name/call_args/result_summary）
        target_info       : 渗透目标信息
    """
    target_part = f"\n渗透目标：{target_info}" if target_info else ""

    # 格式化后续行为窗口
    window_lines = []
    for i, ev in enumerate(behavior_window, 1):
        tool = ev.get("tool_name", "unknown")
        args_preview = str(ev.get("call_args", {}))[:300]
        result_preview = ev.get("result_summary", "无结果")[:200]
        window_lines.append(
            f"  行为{i}: tool={tool}\n"
            f"         参数摘要={args_preview}\n"
            f"         结果摘要={result_preview}"
        )
    window_text = "\n".join(window_lines) if window_lines else "  （后续无工具调用）"

    rag_display = rag_result_summary[:600] + "..." if len(rag_result_summary) > 600 else rag_result_summary

    return f"""\
请判断以下 RAG 查询后的行为采纳情况：

【RAG 查询内容】
{rag_query}

【RAG 返回内容摘要（前600字）】
{rag_display}

【后续行为窗口（RAG 查询后 N 步内的工具调用）】
{window_text}{target_part}

请判断 Agent 对 RAG 内容的实际采纳程度，输出 JSON 格式结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# 任务四：会话整体目标达成判定
# 适用于：每个 session 末尾执行一次
# ─────────────────────────────────────────────────────────────────────────────

SESSION_OUTCOME_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：综合分析整个渗透测试会话，判断攻击目标的达成情况。

渗透测试的通用成功标准（按优先级）：
  1. 获得高权限 Shell（root/SYSTEM 级别）→ 完全成功
  2. 获得低权限 Shell（普通用户）         → 部分成功
  3. 验证 RCE 存在（有回显的命令执行）    → 部分成功
  4. 触发 RCE 但无回显（盲执行）          → 部分成功（效果待确认）
  5. 获取敏感数据（flag/密码/密钥）        → 部分成功
  6. 未能实现任何有效访问               → 失败

判断依据：
- 关注 outcome_label=success 且 attack_phase=EXPLOITATION/ESCALATION 的事件
- 事件行中的 ⚡强信号 字段是从完整输出中提取的关键字，优先级最高：
    uid=0   → 命令以 root 权限执行，获得高权限 Shell → 判 success，achieved_goals 应包含"获得 root/高权限 Shell"
    root@   → 获得 root shell → 同上
    flag{   → 获取到 flag → 判 success，achieved_goals 包含"获取 flag"
- 关注执行输出（stdout/raw_text）中的关键词：
    uid=0 / root@ / flag{ → 强成功信号，直接判 success
    [+] Exploit appears successful / Authentication successful → partial_success
    Status Code: 200（配合文件内容） → partial_success
- 【重要】若某事件的 ⚡强信号 字段包含 uid=0 或 root@，
  即使 outcome_label=unknown 或 partial_success，整个 session 应判为 success
- 事件行中的 [失败根因=xxx] 字段表示事件级别的失败原因维度，用于辅助判断：
    DEF = 目标存在防御（已打补丁、认证保护、访问控制）→ 表明目标抵御了攻击
    INV = 工具调用/参数错误 → 攻击手段错误，非目标自身防御
    ENV = 环境/依赖缺失 → 攻击环境问题
    EFF = 效果不确定（如盲执行）→ 不能确认成功或失败
  - 若 EXPLOITATION 阶段多数事件的失败根因为 DEF/PATCHED，强烈表明目标已打补丁，漏洞不可利用 → 应判 failure
  - 其中"盲执行RCE（EFF/BLIND_EXECUTION）"在多个 DEF / PATCHED 存在的背景下只能视为可疑信号，不足以判 partial_success
- 若 session 被中断（session_end_type=interrupted），根据最后有效行为判断
- achieved_goals 精度要求：
  · “获取 flag/敏感数据”：仅当执行输出中有 flag 内容或文件内容实际返回时填写；
    命令已发送但输出为空或 stdout_hint 为空 → 不算已获取
  · "有回显RCE"（命令执行结果可见）的识别规则：
    ✔ uid=/root@/目录列表/命令输出可见 → 判 "有回显RCE"
    ✘ HTTP 响应中包含测试输入数据回显（非命令输出） → 判 "盲执行RCE"
    ✘ "[+] Exploit appears to have been successful!" 等脚本自判断字符串
       （基于 HTTP 200 的程序判断，非命令执行验证） → 判 "盲执行RCE"
    ✘ API 返回 JSON 封装的文件内容（如 Druid/WebLogic API读文件）
       → 判 "通过API读取文件"，不得写成 "有回显RCE"
  · "验证RCE存在"：需区分 "有回显"（命令输出可见）和 "盲执行"（payload 触发但无命令回显）

输出 JSON 格式：
{
  "is_success": true/false,
  "outcome_label": "success|partial_success|failure",
  "session_goal_achieved": true/false,
  "achieved_goals": ["已达成目标1", "已达成目标2"],
  "failed_goals": ["未达成目标1"],
  "reasoning": "100-250字的综合分析"
}
"""


def build_session_outcome_prompt(
    target_info: Optional[str],
    session_end_type: str,
    total_events: int,
    events_summary: List[Dict[str, Any]],
    deterministic_hits: int,
    rag_adoption_summary: Optional[str] = None,
) -> str:
    """构建会话整体目标达成判定的 User Prompt。

    Args:
        target_info       : 渗透目标
        session_end_type  : "normal" | "interrupted" | "unknown"
        total_events      : 总事件数
        events_summary    : 关键事件摘要列表（含 attack_phase / outcome_label）
        deterministic_hits: 确定性规则命中数（确定的环境失败次数）
        rag_adoption_summary: RAG 采纳情况摘要（可选）
    """
    target_display = target_info or "未知目标"
    rag_part = f"\nRAG 采纳情况摘要：{rag_adoption_summary}" if rag_adoption_summary else ""

    # 格式化关键事件摘要
    key_events = []
    for ev in events_summary[-30:]:  # 最多展示最后30个事件
        phase = ev.get("attack_phase", "?")
        outcome = ev.get("outcome_label", "?")
        tool = ev.get("tool_name", "?")
        stdout_hint = ev.get("stdout_hint", "")
        key_signals = ev.get("key_signals", [])
        frc_dim = ev.get("frc_dim", "")
        signals_note = f"  ⚡强信号={key_signals}" if key_signals else ""
        frc_note = f"  [失败根因={frc_dim}]" if frc_dim else ""
        key_events.append(f"  [{phase}] {tool} → {outcome}{signals_note}{frc_note}" + (f"  (stdout片段: {stdout_hint[:250]})" if stdout_hint else ""))

    events_text = "\n".join(key_events) if key_events else "  （无事件）"

    return f"""\
请综合判断本次渗透测试会话的整体结果：

渗透目标：{target_display}
会话结束方式：{session_end_type}
总工具调用数：{total_events}
确定性环境失败数：{deterministic_hits}{rag_part}

关键事件序列（按时间顺序，最多30条）：
{events_text}

请综合以上信息，判断本次渗透测试是否成功，输出 JSON 格式结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 任务：元认知反思（METACOGNITIVE）
# 适用于：每个 session 末尾，基于全量标注数据生成元认知经验
# ─────────────────────────────────────────────────────────────────────────────

METACOGNITIVE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：对一次渗透测试会话进行**元认知反思**，生成可迁移的决策规则。

【核心要求】
输出内容必须完全不含 IP 地址、具体端口号或主机名——所有内容必须对
"运行同类服务的任意目标"通用，而非仅适用于本次会话。

输出 JSON 格式（严格遵守，所有字段必须提供）：
{
  "session_goal": "本次渗透希望达成的核心目标，用服务名描述（1-2句，无 IP）",

  "decision_mistakes": [
    {
      "mistake": "具体的错误决策行为（30-80字，无 IP）",
      "consequence": "该错误导致的代价（时间浪费/攻击失败/方向偏离等）",
      "rule": "RULE_NAME：可操作的 IF-THEN 规则，适用于未来同类场景"
    }
  ],

  "missed_opportunities": [
    "本次未尝试但可能更有效的攻击路径（基于你的安全知识推断，无 IP）"
  ],

  "optimal_decision_path": [
    "步骤1：（以动词开头，描述最优决策序列，无 IP）",
    "步骤2：...",
    "步骤3：..."
  ],

  "rag_effectiveness": "RAG 知识检索对本次会话决策的实际影响评估（50-150字）",
  "failure_pattern": "主导失败模式的简练描述（无 IP），无失败时填 null",
  "success_factor": "关键成功因素的简练描述（无 IP），未成功时填 null"
}

分析原则：
1. decision_mistakes.rule 必须是 "规则名称：IF <可识别条件> THEN <具体行动>" 格式
   示例：TOPO_FIRST：IF 目标为 loopback/内网 THEN 在 exploit 前先确认出网能力
   示例：PIVOT_RULE：IF 同类回显方案连续失败 3 次 THEN 强制切换攻击路径
2. missed_opportunities 必须基于安全专业知识推断，不得是模板化建议
3. optimal_decision_path 是"如果重来一遍"的最优决策序列，聚焦关键转折点
4. rag_effectiveness 必须基于 BAR 分数和采纳情况进行实质评估，不得模板化
5. 若会话整体 outcome=failure 且多数根因为 DEF，应在 decision_mistakes 中
   指出「信息收集不足就发起利用」的具体错误
6. 输出必须为有效 JSON，不得有额外说明文字
"""

# 成功 session 的额外分析 prompt 片段（M-2: 成功路径最小化分析）
_METACOGNITIVE_SUCCESS_EXTRA = """

【成功会话专属分析（本次会话结果为 success/partial_success，请额外补充以下三个字段）】

由于本次会话最终成功，请在 JSON 中额外增加：

  "minimal_success_path": [
    "步骤1：（去掉无效绕路后，真正必要的最短步骤序列，以动词开头，无 IP）",
    "步骤2：...",
    "步骤N：..."
  ],

  "replicability_conditions": [
    "前置条件1（只写真正决定成败的条件，不写显而易见的通用条件，无 IP）",
    "前置条件2"
  ],

  "critical_decision_point": "整个攻击链中最关键的单一决策（换了就从成功变失败），无 IP"

注意：
- minimal_success_path 是从成功路径中去掉低效重试/无用绕路后的精简序列
- replicability_conditions 只写真正决定成败的条件（如：目标运行未打补丁的X版本）
  不写通用条件（如：目标服务正在运行）
- critical_decision_point 只填一个最关键的决策点，不填多个
"""


def build_metacognitive_prompt(session_summary: str, is_success: bool = False) -> str:
    """构建 METACOGNITIVE 提取的 User Prompt。

    Args:
        session_summary : 由 metacognitive.py 生成的会话标注结构化摘要（已去 IP）
        is_success      : 是否为成功/部分成功会话（True 时注入成功路径分析要求）

    Returns:
        User prompt 字符串
    """
    success_extra = _METACOGNITIVE_SUCCESS_EXTRA if is_success else ""
    return f"""\
以下是一次自动化渗透测试会话的结构化标注摘要（IP 已匿名化），请进行元认知反思分析：

{session_summary}

请基于以上信息输出元认知反思 JSON。
所有输出内容必须对"同类服务的任意目标"通用，不得包含具体 IP 地址。{success_extra}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 任务：LLM 驱动的 FACTUAL 目标识别（per-session）
# 适用于：每个有 RECON 阶段事件的 session
# ─────────────────────────────────────────────────────────────────────────────

FACTUAL_LLM_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：从一次渗透测试会话的侦察和利用结果中，
提炼出可迁移的目标知识——即"关于这类目标，我知道什么"，
而非"在某个 IP 上我看到了什么"。

输出 JSON 格式（严格遵守）：
{
  "target_service": "目标软件名称（如：Oracle WebLogic Server，无版本号，无 IP）",
  "target_version": "版本号（如：10.3.6.0，若无法确定填 null）",
  "cve_context": {
    "attempted": ["CVE-XXXX-XXXXX", ...],
    "exploitation_results": {
      "CVE-XXXX-XXXXX": "简述结果（如：patched-HTTP500 / success-RCE / requires-auth）"
    },
    "unexplored": ["基于你的安全知识，该版本存在但本次未尝试的相关 CVE"]
  },
  "applicable_constraints": {
    "network_topology": "loopback | internal | external | unknown（从目标 IP 类型推断）",
    "service_versions": ["已确认的版本字符串"],
    "known_ineffective_vectors": ["已确认失效的攻击向量（如：/wls-wsat/CoordinatorPortType）"]
  },
  "exploitation_status": "exploited | partial | patched | unknown"
}

判断规则：
1. target_service 必须是软件/服务名，不得是 IP 地址或 "{TARGET_IP}"
2. cve_context.unexplored 应基于你对该软件版本的安全知识填写，空列表也可
3. exploitation_status:
   - exploited: 有明确 RCE/shell 成功信号（uid=0/root@等）
   - partial: exploit 触发但回显/交互失败（盲执行/HTTP 200 无回显）
   - patched: 主要攻击路径全部 HTTP 500/403
   - unknown: 证据不足
4. 若无法确定目标软件名称，仍需填写可观测的技术特征：
   - 如有 HTTP 服务：填 "HTTP Service (Node.js/Express)" 或 "HTTP Service (Unknown)"
   - 如只有端口信息：填 "TCP Service (port XXXX)"
   - 禁止填写 IP 地址或直接填 "Unknown Service"
5. applicable_constraints.service_versions 应从侦察输出中提取已确认的版本字符串
   （如 nmap service 列版本信息、HTTP 响应头中的版本号等；无版本信息则填空列表）
6. 输出必须为有效 JSON，不得有额外说明文字
"""


def build_factual_llm_prompt(
    recon_summary: str,
    exploit_summary: str,
    target_ip_hint: str,
    session_outcome: str = "unknown",
) -> str:
    """构建 LLM 驱动的 FACTUAL 目标识别提示。

    Args:
        recon_summary  : 侦察阶段关键输出摘要
        exploit_summary: 利用阶段关键输出摘要（含 CVE 尝试和结果）
        target_ip_hint : 目标 IP 类型提示（loopback/10.x/172.x/192.168.x/公网等）
        session_outcome: 会话整体结果（success/partial_success/failure/unknown）

    Returns:
        User prompt 字符串
    """
    # P0-C: 当会话确认成功时，注入提示辅助 LLM 校准 exploitation_status
    outcome_hint = ""
    if session_outcome in ("success", "partial_success"):
        outcome_hint = (
            f"\n【重要提示】本次会话的整体结果为 {session_outcome}，"
            "请根据此结论校准 exploitation_status 字段\n"
            "（若利用阶段有任何成功信号，请评为 partial 或 success，而非 unknown）"
        )
    return f"""\
请从以下渗透测试会话信息中提炼目标知识：{outcome_hint}

【目标 IP 类型】{target_ip_hint}（用于推断 network_topology）

【侦察阶段发现】
{recon_summary}

【利用阶段结果】
{exploit_summary}

请基于上述信息输出目标知识 JSON。
若侦察输出中包含端口/服务/版本信息，请尽可能精确识别软件名称。
若利用阶段有 CVE 相关尝试，请在 cve_context 中总结结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 任务：NEG 批量决策规则生成
# 适用于：一个 session 的所有 PROCEDURAL_NEG 经验（批量一次调用）
# ─────────────────────────────────────────────────────────────────────────────

NEG_DECISION_RULE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：为一批渗透测试失败事件生成可迁移的决策规则。

每条失败事件都需要生成一个 decision_rule（IF-THEN 格式），
规则必须对"未来遇到同类失败信号时"通用，不含具体 IP 或端口。

⚠️ IP 地址禁令（P0 级别）：
在所有自然语言字段（failure_pattern.trigger_condition、failure_pattern.interpretation、
decision_rule.IF、decision_rule.THEN、decision_rule.NOT、next_actions.expected_signal 等）中，
绝对禁止出现任何具体 IP 地址（如 127.0.0.1、10.0.0.x、192.168.x.x 等）。
必须用"目标靶机"或变量 {TARGET} 代替。
这是经验库跨会话共享的要求，写入 IP 会导致未来检索错误地指向旧靶机。

【关键要求】THEN 必须给出具体的、基于安全专业知识的下一步行动，
而非通用建议（如"尝试其他漏洞"是无效的）。
- 若目标软件已知（如 WebLogic/CouchDB/Druid），THEN 必须包含具体 CVE 编号或攻击路径
- THEN 的每条建议必须包含：工具名/CVE编号/具体路径至少之一
- next_actions 是可直接转化为 Agent 行动计划的有序操作步骤（含工具和命令模板）

输出包装 JSON 对象，格式如下：
{"rules": [
  {
    "failure_pattern": {
      "trigger_condition": "可识别的失败信号（如：wls-wsat 端点连续 HTTP 500）",
      "interpretation": "该信号意味着什么（如：PSU 补丁已应用，RCE 路径失效）",
      "certainty": "high | medium | low"
    },
    "decision_rule": {
      "IF": "触发此规则的条件（服务类型 + 失败信号，无 IP）",
      "THEN": [
        "具体行动1（含工具名/CVE编号/路径，如：测试 CVE-2020-14882 /console/css/%%2e路径）",
        "具体行动2"
      ],
      "NOT": "明确不应该继续做什么（避免低效重试）",
      "next_actions": [
        {
          "step": 1,
          "tool": "工具名（execute_code/generic_linux_command等）",
          "command": "具体命令模板（用{TARGET}代替IP，用{PORT}代替端口）",
          "expected_signal": "成功时应看到的输出信号（如：HTTP 302重定向）"
        }
      ]
    }
  },
  ...
]}

要求：
1. rules 数组长度必须与输入事件数相同，一一对应
2. THEN 列表必须包含至少 1 条含具体工具名/CVE/路径的可操作建议
3. next_actions 必须包含至少 1 个具体步骤（step/tool/command/expected_signal）
4. 所有内容不含具体 IP 地址，适用于同类目标的通用情境
5. certainty 基于失败信号的确定性评估（HTTP 500=high, timeout=medium, partial=low）
6. 输出必须为有效 JSON 对象（以 { 开头），不得有额外说明文字
"""


def build_neg_batch_decision_rule_prompt(failure_items: List[Dict[str, Any]]) -> str:
    """构建 NEG 批量决策规则生成的 User Prompt。

    Args:
        failure_items: 失败事件列表，每项含 {tool_name, attack_phase, failure_dimension,
                        failure_sub_dimension, evidence, failed_command, avoid_pattern,
                        target_software（可选）}

    Returns:
        User prompt 字符串
    """
    items_text = ""
    for i, item in enumerate(failure_items, 1):
        target_sw = item.get('target_software', '') or ''
        target_hint = f"\n  目标软件（用于生成具体THEN）: {target_sw}" if target_sw else ""
        items_text += f"""
事件 {i}:
  工具: {item.get('tool_name', '?')}
  攻击阶段: {item.get('attack_phase', '?')}
  失败维度: {item.get('failure_dimension', '?')}/{item.get('failure_sub_dimension', '?')}
  证据: {item.get('evidence', '?') or '(无)'}
  命令摘要: {item.get('failed_command', '?')[:120]}
  避免描述: {item.get('avoid_pattern', '?')[:120]}{target_hint}
"""

    return f"""\
以下是本次渗透测试会话中的 {len(failure_items)} 条失败事件，请为每条生成决策规则：

{items_text}
【重要】THEN 必须给出基于目标软件和失败信号的具体建议（含CVE/路径/工具），\
不能是"尝试其他漏洞"之类通用建议。
next_actions 必须包含至少1个可执行步骤（command 用{{TARGET}}/{{PORT}}作占位符）。

请输出 JSON 格式，rules 数组包含 {len(failure_items)} 条规则，与上述事件一一对应：
{{"rules": [...]}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 任务：概念规律归纳（CONCEPTUAL）
# 适用于：有足够成功或失败事件的 session，归纳可泛化的攻击规律
# ─────────────────────────────────────────────────────────────────────────────

CONCEPTUAL_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的当前任务是：从一次渗透测试会话中归纳**概念性攻击规律**（CONCEPTUAL 知识层）。

概念规律是指：可以在类似场景下重复应用的高层次攻击策略/模式，
超越单次操作，关注「什么条件下、什么策略有效」。

【重要】仅归纳攻击模式知识——不要输出 RAG 效用分析（那是系统元评估，单独存储）。

输出 JSON 格式（严格遵守）：
{
  "pattern_type"          : "attack_strategy | vulnerability_pattern | defense_bypass | recon_pattern | post_exploitation | lateral_movement | credential_attack | privilege_escalation",
  "applicable_conditions" : {
    "positive": [
      "目标运行 Oracle WebLogic Server 10.3.x 或 12.1.x",
      "wls-wsat 或 _async 端点可达，HTTP 响应非 connection refused"
    ],
    "negative": [
      "NOT: wls-wsat 全部返回 HTTP 500（表示已打补丁，CVE-2017-10271 失效）",
      "NOT: 目标版本已升级至 12.2.x 以上"
    ],
    "priority_over": ["通用中间件攻击策略"],
    "retrieval_triggers": ["Oracle WebLogic", "CVE-2017-10271", "wls-wsat"]
  },
  "core_insight"          : "核心洞察：2-4句，说明该规律的本质和边界（80-200字，无 IP）",
  "supporting_evidence"   : [
    "nmap 探测到 7001 端口 Oracle-Application-Server-11g",
    "curl /wls-wsat/CoordinatorPortType 返回 HTTP 500，确认补丁已应用"
  ],
  "confidence_basis"      : "基于单一会话，raw 级别；需积累 ≥3 条同类 session 才可升级为 validated"
}

⚠️ 输出规则（违反则输出无效）：
1. pattern_type 必须从上列 8 类中精确选择一个（不包含 rag_utility）
2. core_insight 必须是泛化性洞察，不得包含具体 IP 地址
3. retrieval_triggers 必须是**真实关键词**（软件名/CVE 编号/攻击技术名）
   - 禁止填写描述性文字或带括号的说明（如"关键词1"、"软件名/CVE/技术名"均不合法）
   - 正确示例：["Apache Struts", "CVE-2017-5638", "OGNL injection"]
4. applicable_conditions 必须包含 positive 和 negative 两个部分，每部分至少 1 条
5. confidence_basis 必须说明"单一会话，raw 级别"
6. 输出必须为有效 JSON，不要添加任何注释或 markdown 代码块
"""


def build_conceptual_prompt(input_text: str) -> str:
    """构建 CONCEPTUAL 提取的 User Prompt。

    Args:
        input_text : 由 conceptual.py 生成的会话摘要

    Returns:
        User prompt 字符串
    """
    return f"""\
以下是一次渗透测试会话的事件序列摘要，请归纳可泛化的攻击规律：

{input_text}

请输出一条最具代表性的概念规律 JSON。
"""


def build_rag_utility_prompt(input_text: str) -> str:
    """构建 RAG 效用评估的 User Prompt。

    生成 RAG_EVALUATION 层记录（非 CONCEPTUAL），
    不参与攻击知识检索，仅用于系统元评估。

    Args:
        input_text : 由 conceptual.py 生成的 RAG 效用摘要

    Returns:
        User prompt 字符串
    """
    return f"""\
以下是一次渗透测试会话中 RAG 知识检索的效用分析，请归纳 RAG 对渗透测试的影响规律：

{input_text}

请输出 JSON，含字段：
  pattern_type: "rag_utility"（固定值）
  applicable_conditions: 列表，何种情境下 RAG 检索最有帮助
  core_insight: RAG 效用的核心规律（≥30字）
  supporting_evidence: 支撑本结论的事件/指标列表
  confidence_basis: 置信度依据

输出必须为有效 JSON。
"""

