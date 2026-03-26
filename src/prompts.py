"""
Phase 3 / Layer 2 Prompt 模板
=============================
集中定义系统提示词与用户提示词构建函数。

说明：
- 输出格式统一要求 JSON。
- 保留所有被 Layer1/Layer2 调用的常量与函数签名。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 公共 System Prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PENTEST_EXPERT = """\
你是一名资深渗透测试专家，正在分析自动化渗透执行日志。
请基于证据进行结构化标注，禁止臆造不存在的信息。

通用规则：
1. 输出必须是合法 JSON。
2. 字段名必须严格匹配要求，不要增加额外键。
3. 证据不足时可给出 uncertain/unknown，并在 reasoning 里说明。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1: 失败根因分类
# ─────────────────────────────────────────────────────────────────────────────

FAILURE_CAUSE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：对单次失败调用进行根因分类。

根因维度：
- ENV: 执行环境问题（工具缺失、依赖缺失、超时、权限等）
- INV: 调用方式问题（参数/语法/顺序/配置错误）
- DEF: 目标防御问题（认证、授权、WAF、补丁等）
- INT: 情报认知问题（版本误判、侦察不足、前提假设错误）
- EFF: 执行效果问题（触发后无回显、部分成功、输出缺失）

输出 JSON:
{
  "dimension": "ENV|INV|DEF|INT|EFF",
  "sub_dimension": "大写下划线标签",
  "evidence": "100字以内，引用具体证据",
  "remediation_hint": "50字以内修复建议",
  "reasoning": "50-150字分析",
  "search_queries": ["英文检索词1", "英文检索词2"]
}
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
    raw_text: str = "",
) -> str:
    """构建失败根因分类用户提示词。"""
    target_part = f"\n渗透目标信息: {target_info}" if target_info else ""
    context_part = f"\n近期上下文: {context_summary}" if context_summary else ""

    stderr_display = stderr_raw[:800] + "..." if len(stderr_raw) > 800 else stderr_raw
    effective_output = stdout_raw or raw_text
    output_display = effective_output[:500] + "..." if len(effective_output) > 500 else effective_output

    args_display = {
        k: (v[:300] + "..." if isinstance(v, str) and len(v) > 300 else v)
        for k, v in call_args.items()
    }

    return f"""\
请分析以下工具调用失败的根因。

工具名称: {tool_name}
调用参数: {args_display}
返回码(return_code): {return_code}
执行成功(success字段): {success}
标准错误(stderr):
{stderr_display}
执行输出(stdout/raw, 前500字):
{output_display}{target_part}{context_part}

请输出 JSON 分类结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1: 攻击阶段分类
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PHASE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：对单次工具调用进行攻击阶段分类，并给出 outcome_label。

阶段枚举：
- RECON_WEAPONIZATION
- EXPLOITATION
- ESCALATION
- LATERAL_MOVEMENT
- EXFILTRATION
- COMMAND_CONTROL
- ENV_PREPARATION

outcome_label 枚举：
- success
- partial_success
- failure
- timeout
- uncertain
- unknown

输出 JSON:
{
  "attack_phase": "...",
  "outcome_label": "...",
  "reasoning": "50-150字"
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
    raw_text: str = "",
) -> str:
    """构建攻击阶段分类用户提示词。"""
    target_part = f"\n渗透目标: {target_info}" if target_info else ""
    prog_part = f"\n首个程序名(generic_linux_command): {program_name}" if program_name else ""

    args_display = {
        k: (v[:400] + "..." if isinstance(v, str) and len(v) > 400 else v)
        for k, v in call_args.items()
    }
    stderr_display = stderr_raw[:400] + "..." if len(stderr_raw) > 400 else stderr_raw
    effective_output = stdout_raw or raw_text
    output_display = effective_output[:400] + "..." if len(effective_output) > 400 else effective_output

    if has_result:
        result_section = f"""
执行结果:
  return_code={return_code}, success={success}, timed_out={timed_out}
  stderr(前400字): {stderr_display}
  stdout/raw(前400字): {output_display}
"""
    else:
        result_section = "\n执行结果: 无结果(可能被中断或未返回)"

    return f"""\
请对以下工具调用进行七维 Kill Chain 分类。

工具名称: {tool_name}
行为类别(Layer0): {action_category}
调用参数: {args_display}{prog_part}{result_section}{target_part}

请输出 JSON 分类结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1: 会话结果判定
# ─────────────────────────────────────────────────────────────────────────────

SESSION_OUTCOME_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：综合会话事件，判定会话结果。

判定标准（必须遵守）：
- success：已获得明确攻击目标成果（如稳定高权限/关键敏感数据获取/核心利用链闭环）。
- partial_success：出现了可验证的攻击进展，但未形成完整闭环或成果不稳定。
- failure：未观察到可验证攻击进展，或仅停留在探测/尝试阶段。

一致性约束（必须遵守）：
- outcome_label=success   -> is_success=true  且 session_goal_achieved=true
- outcome_label=partial_success -> is_success=false 且 session_goal_achieved=true
- outcome_label=failure   -> is_success=false 且 session_goal_achieved=false

输出 JSON:
{
  "is_success": true/false,
  "outcome_label": "success|partial_success|failure",
  "session_goal_achieved": true/false,
  "achieved_goals": ["..."],
  "failed_goals": ["..."],
  "reasoning": "100-250字"
}
"""


def build_session_outcome_prompt(
    target_info: Optional[str],
    session_end_type: str,
    total_events: int,
    events_summary: List[Dict[str, Any]],
    deterministic_hits: int,
) -> str:
    """构建会话整体结果判定用户提示词。"""
    target_display = target_info or "未知目标"

    if len(events_summary) <= 30:
        sampled_events = events_summary
        sample_note = "全部事件"
    else:
        sampled_events = events_summary[:10] + events_summary[-20:]
        sample_note = "前10条 + 后20条"

    key_events: List[str] = []
    for ev in sampled_events:
        phase = ev.get("attack_phase", "?")
        outcome = ev.get("outcome_label", "?")
        tool = ev.get("tool_name", "?")
        stdout_hint = ev.get("stdout_hint", "")
        key_signals = ev.get("key_signals", [])
        frc_dim = ev.get("frc_dim", "")

        signals_note = f"  强信号={key_signals}" if key_signals else ""
        frc_note = f"  [失败根因={frc_dim}]" if frc_dim else ""
        stdout_note = f"  (stdout片段: {stdout_hint[:250]})" if stdout_hint else ""
        key_events.append(f"  [{phase}] {tool} -> {outcome}{signals_note}{frc_note}{stdout_note}")

    events_text = "\n".join(key_events) if key_events else "  (无关键事件)"

    return f"""\
请综合判断本次渗透测试会话的整体结果。

渗透目标: {target_display}
会话结束方式: {session_end_type}
总工具调用数: {total_events}
确定性规则命中数: {deterministic_hits}

关键事件序列(按时间顺序, 最多30条):
{events_text}
事件采样策略: {sample_note}

请输出 JSON 结果。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: 元认知
# ─────────────────────────────────────────────────────────────────────────────

METACOGNITIVE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：基于会话摘要提炼元认知经验。

要求：
- 内容必须可迁移，不允许出现具体 IP/端口。
- 决策规则要可执行，避免空泛建议。
- 输出必须是 JSON，且必须包含以下字段（不可改字段名）：
  {
    "session_goal": "...",
    "decision_mistakes": [
      {"mistake": "...", "consequence": "...", "rule": "..."}
    ],
    "missed_opportunities": ["..."],
    "optimal_decision_path": ["..."],
    "key_lessons": ["..."],
    "rag_effectiveness": "...",
    "failure_pattern": "...",
    "success_factor": "..."
  }
- 若某字段暂无信息，使用空字符串或空数组，不得省略字段。
"""

_METACOGNITIVE_SUCCESS_EXTRA = """

成功会话额外要求：
- 补充 minimal_success_path
- 补充 replicability_conditions
- 补充 critical_decision_point
"""


def build_metacognitive_prompt(session_summary: str, is_success: bool = False) -> str:
    """构建 METACOGNITIVE 用户提示词。"""
    success_extra = _METACOGNITIVE_SUCCESS_EXTRA if is_success else ""
    return f"""\
以下是一次渗透测试会话结构化摘要，请进行元认知反思：

{session_summary}

请严格按系统提示中的字段输出 JSON。不得包含具体 IP 地址。{success_extra}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: FACTUAL(LLM)
# ─────────────────────────────────────────────────────────────────────────────

FACTUAL_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：从侦察与利用信息中提炼目标事实知识。

硬性约束：
1. exploit 摘要中出现的 CVE，必须尽量写入 cve_context.attempted。
2. 若 attempted 非空，exploitation_results 必须包含 attempted 的每个 CVE 键。
3. exploitation_results 的值仅允许: success|partial|failure|patched|unknown。
4. 证据不足时使用 unknown，不得省略已有 CVE 的结果。
5. target_service 必须输出“厂商+产品”的规范服务名（例如 Oracle WebLogic Server, Apache Solr, Spring Framework）。
6. target_service 不得包含版本号、CVE 编号、IP 或端口。

输出 JSON:
{
  "target_service": "服务名",
  "target_version": "版本或null",
  "cve_context": {
    "attempted": [],
    "exploitation_results": {},
    "unexplored": []
  },
  "applicable_constraints": {
    "network_topology": "loopback|internal|external|unknown",
    "service_versions": [],
    "known_ineffective_vectors": []
  },
  "exploitation_status": "exploited|partial|patched|unknown"
}
"""


def build_factual_prompt(
    recon_summary: str,
    exploit_summary: str,
    target_ip_hint: str,
    session_outcome: str = "unknown",
) -> str:
    """构建 FACTUAL 用户提示词。"""
    outcome_hint = ""
    if session_outcome in ("success", "partial_success"):
        outcome_hint = (
            "\n重要提示: 会话整体结果为 "
            f"{session_outcome}，请据此校准 exploitation_status。"
        )

    return f"""\
请从以下会话信息提炼目标事实知识。{outcome_hint}

目标IP类型提示: {target_ip_hint}

侦察阶段摘要:
{recon_summary}

利用阶段摘要:
{exploit_summary}

请输出 JSON。
禁止引入输入中不存在的软件名、CVE 或利用结论；证据不足时保持 unknown。
若识别到 attempted CVE，禁止返回空的 exploitation_results。
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: NEG 批量决策规则
# ─────────────────────────────────────────────────────────────────────────────

NEG_DECISION_RULE_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：为一批失败事件生成可迁移的决策规则。

硬性约束：
1. 单事件作用域：每条规则只能使用对应事件的信息。
2. 禁止跨事件污染：不得借用其他事件的软件名/CVE/路径。
3. 证据不足时禁止臆造具体 CVE/路径，应给出保守核验步骤。
4. 所有自然语言字段不得出现具体 IP，统一使用 {TARGET}/{PORT} 占位。

输出格式：
{
  "rules": [
    {
      "failure_pattern": {
        "trigger_condition": "...",
        "interpretation": "...",
        "certainty": "high|medium|low"
      },
      "decision_rule": {
        "IF": "...",
        "THEN": ["..."],
        "NOT": "...",
        "next_actions": [
          {
            "step": 1,
            "tool": "...",
            "command": "...",
            "expected_signal": "..."
          }
        ]
      }
    }
  ]
}
"""


def build_neg_batch_decision_rule_prompt(failure_items: List[Dict[str, Any]]) -> str:
    """构建 NEG 批量决策规则用户提示词。"""
    items_text = ""
    for i, item in enumerate(failure_items, 1):
        target_sw = item.get("target_software", "") or ""
        target_hint = f"\n  目标软件: {target_sw}" if target_sw else ""
        items_text += f"""
事件 {i}:
  事件标识: EVT_{i}
  【边界声明】仅允许使用 EVT_{i} 的信息，禁止跨事件引用
  工具: {item.get('tool_name', '?')}
  攻击阶段: {item.get('attack_phase', '?')}
  失败维度: {item.get('failure_dimension', '?')}/{item.get('failure_sub_dimension', '?')}
  证据: {item.get('evidence', '?') or '(空)'}
  命令摘要: {item.get('failed_command', '?')[:120]}
  避免描述: {item.get('avoid_pattern', '?')[:120]}{target_hint}
"""

    return f"""\
以下是本次渗透测试会话中的 {len(failure_items)} 条失败事件，请为每条生成决策规则。

{items_text}
【边界声明】此条规则只能基于本事件(EVT_i)信息，不得引用其他事件数据。
【边界提醒】每条规则只能引用同编号事件(EVT_i)的信息，禁止跨事件借用软件名/CVE/路径。
【重要】THEN 必须给出具体建议，next_actions 至少包含1个可执行步骤。

请输出 JSON:
{{"rules": [...]}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: CONCEPTUAL
# ─────────────────────────────────────────────────────────────────────────────

CONCEPTUAL_SYSTEM = SYSTEM_PENTEST_EXPERT + """
你的任务：归纳可迁移的概念性攻击规律(CONCEPTUAL)。

要求：
- 仅输出攻击模式知识，不输出系统运维元评估。
- 核心洞察必须可迁移，不允许包含具体 IP。
- 输出必须是合法 JSON，且必须包含以下字段（不可改字段名）：
  {
    "pattern_type": "attack_strategy|vulnerability_pattern|defense_bypass|recon_pattern|post_exploitation|lateral_movement|credential_attack|privilege_escalation",
    "core_insight": "...",
    "applicable_conditions": {
      "positive": ["..."],
      "negative": ["..."],
      "priority_over": ["..."],
      "retrieval_triggers": ["..."]
    },
    "supporting_evidence": ["..."],
    "confidence_basis": "..."
  }
- 不得输出 conceptual_patterns / meta_cognitive_insights 这类替代字段名。
"""


def build_conceptual_prompt(input_text: str) -> str:
    """构建 CONCEPTUAL 用户提示词。"""
    return f"""\
以下是一次渗透测试会话摘要，请归纳最具代表性的概念规律。

{input_text}

请严格按系统提示中的字段输出 JSON。
"""


def build_rag_utility_prompt(input_text: str) -> str:
    """构建 RAG 效用评估用户提示词。"""
    return f"""\
以下是一次渗透测试会话中的 RAG 使用摘要，请归纳其效用规律。

{input_text}

请输出 JSON，字段包含:
- pattern_type(固定 rag_utility)
- applicable_conditions
- core_insight
- supporting_evidence
- confidence_basis
"""
