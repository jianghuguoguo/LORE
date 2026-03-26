"""
Metacognitive 经验提取器（LLM 驱动）
======================================
从会话整体视角提取元认知反思经验（METACOGNITIVE layer）。

元认知经验记录「这次渗透测试我学到了什么」，包括：
- 关键决策点及其得失
- 成功/失败的根本驱动因素
- RAG 知识检索的实际效果
- 对下一次类似场景的指导建议

每个 session 最多生成 1 条 METACOGNITIVE 经验。

提取条件：
- session_outcome 不为 None（至少有基本的会话结果标注）
- annotated_events 非空（至少有 1 个事件）

LLM 输入构造：
- 使用 sess 中已有的所有语义标注（attack_phase/outcome/frc）
- 不回溯原始日志（token 节省）
- 输出直接映射 METACOGNITIVE_CONTENT_KEYS
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ...llm_client import LLMClient
from ...models import AnnotatedTurnSequence
from ..experience_models import (
    Experience,
    ExperienceMaturity,
    ExperienceMetadata,
    ExperienceSource,
    KnowledgeLayer,
)
from ...utils.log_utils import get_logger

logger = get_logger(__name__)


def _sample_events(ann_seq: AnnotatedTurnSequence, n_head: int = 10, n_tail: int = 10):
    """智能采样事件：头部 + 关键 EXPLOITATION/ESCALATION成功事件 + 尾部。

    避免直接截取最后 30 条导致错过前半段侦察阶段关键内容。
    """
    all_events = ann_seq.annotated_events
    if not all_events:
        return []
    head = list(all_events[:n_head])
    tail = list(all_events[-n_tail:])
    key = [
        e for e in all_events
        if e.attack_phase in ("EXPLOITATION", "ESCALATION")
        and e.outcome_label in ("success", "partial_success")
    ]
    seen_ids: set = set()
    combined = []
    for e in [*head, *key, *tail]:
        if e.event_id not in seen_ids:
            seen_ids.add(e.event_id)
            combined.append(e)
    combined.sort(key=lambda e: e.turn_index)
    return combined


def _anonymize_target(target_raw: Optional[str]) -> str:
    """将目标描述去 IP 化，保留服务类型提示。

    策略：将 IP 地址替换为 "{TARGET}"，但保留端口号和协议提示符。
    例：http://127.0.0.1:7001 → http://{TARGET}:7001
        192.168.1.100         → {TARGET}
    """
    import re
    if not target_raw:
        return "未知目标"
    # 替换 IPv4 地址（包括 loopback/内网/公网等）
    anonymized = re.sub(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b',
        "{TARGET}",
        target_raw,
    )
    return anonymized


def _infer_ip_topology(target_raw: Optional[str]) -> str:
    """从目标 IP 推断网络拓扑类型（loopback/内网/公网）。"""
    import re
    if not target_raw:
        return "unknown"
    ips = re.findall(
        r'\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b',
        target_raw,
    )
    if not ips:
        return "external (domain)"
    # 取第一个完整 IP
    first_ip = re.search(
        r'\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b',
        target_raw,
    )
    if not first_ip:
        return "unknown"
    ip = first_ip.group(0)
    if ip.startswith("127."):
        return "loopback"
    if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
        return "internal"
    return "external"


def _build_phase_distribution(ann_seq: AnnotatedTurnSequence) -> Dict[str, Any]:
    """统计攻击阶段分布、工具多样性和卡点特征。"""
    from collections import Counter
    phase_counter: Counter = Counter()
    tool_set: set = set()
    stuck_phases: Dict[str, int] = {}  # 失败次数较多的阶段

    for ev in ann_seq.annotated_events:
        if ev.attack_phase:
            phase_counter[ev.attack_phase] += 1
        if ev.base.call.tool_name:
            tool_set.add(ev.base.call.tool_name)
        if ev.failure_root_cause and ev.attack_phase:
            stuck_phases[ev.attack_phase] = stuck_phases.get(ev.attack_phase, 0) + 1

    # 找出卡巴最多的阶段（如果有）
    most_stuck = max(stuck_phases, key=stuck_phases.get) if stuck_phases else None

    return {
        "phase_distribution": dict(phase_counter.most_common()),
        "tool_diversity": len(tool_set),
        "most_stuck_phase": most_stuck,
        "stuck_counts": stuck_phases,
    }


def _build_session_summary(ann_seq: AnnotatedTurnSequence) -> str:
    """将会话标注数据压缩为 LLM 可用的结构化摘要（IP 已匿名化）。

    关键设计：target 中的 IP 被替换为 {TARGET}，仅保留服务类型线索，
    以确保生成的元认知经验对任意同类目标可用。
    """
    session_id = ann_seq.metadata.session_id[:8]
    # 去 IP 化：把 IP 替换为 {TARGET}，保留协议/端口提示
    target_anon = _anonymize_target(ann_seq.metadata.target_raw)
    topology_hint = _infer_ip_topology(ann_seq.metadata.target_raw)

    so = ann_seq.session_outcome
    outcome_label = so.outcome_label if so else "unknown"
    achieved = (so.achieved_goals or []) if so else []
    failed = (so.failed_goals or []) if so else []
    so_reasoning = (so.reasoning or "")[:400] if so else ""

    # 智能采样事件（头部 + 关键 EXPLOITATION 成功 + 尾部）
    sampled_events = _sample_events(ann_seq)

    event_lines = []
    for ev in sampled_events:
        tool = ev.base.call.tool_name
        phase = ev.attack_phase or "?"
        outcome = ev.outcome_label or "?"
        frc = ""
        if ev.failure_root_cause:
            frc = f"[失败:{ev.failure_root_cause.dimension.value}"
            if ev.failure_root_cause.sub_dimension:
                frc += f"/{ev.failure_root_cause.sub_dimension}"
            frc += "]"
        rag_flag = "[RAG引用]" if ev.base.has_rag_context else ""
        event_lines.append(f"  [{phase}] {tool} → {outcome}{frc}{rag_flag}")

    rag_summary = ""

    # 失败根因统计（含子维度明细，帮助 LLM 生成精准规则）
    frc_detail: Dict[str, int] = {}
    for ev in ann_seq.annotated_events:
        if ev.failure_root_cause:
            dim = ev.failure_root_cause.dimension.value
            sub = ev.failure_root_cause.sub_dimension or "GENERAL"
            key = f"{dim}/{sub}"
            frc_detail[key] = frc_detail.get(key, 0) + 1

    frc_summary = ""
    if frc_detail:
        frc_parts = [f"{k}×{v}" for k, v in sorted(frc_detail.items(), key=lambda x: -x[1])]
        frc_summary = "失败根因（含子维度）：" + ", ".join(frc_parts)

    lines = [
        f"会话 ID：{session_id}…",
        f"目标（IP 已匿名）：{target_anon}",
        f"网络拓扑推断：{topology_hint}",
        f"最终结果：{outcome_label}",
        f"已达成目标：{', '.join(achieved) if achieved else '无'}",
        f"未达成目标：{', '.join(failed) if failed else '无'}",
        f"结果推理：{so_reasoning}",
        rag_summary,
        frc_summary,
        f"",
        f"事件序列（共 {ann_seq.total_events} 条事件，展示关键 {len(event_lines)} 条）：",
    ] + event_lines

    return "\n".join(l for l in lines if l is not None)


def _call_metacognitive_llm(
    session_summary: str,
    client: LLMClient,
    session_id: str,
    is_success: bool = False,
) -> Optional[Dict[str, Any]]:
    """调用 LLM 生成元认知反思内容（含 decision_mistakes + optimal_decision_path）。

    Args:
        is_success: True 时注入成功会话专属分析 prompt（M-2 额外字段）
    """
    from ...prompts import METACOGNITIVE_SYSTEM, build_metacognitive_prompt

    system = METACOGNITIVE_SYSTEM
    user_prompt = build_metacognitive_prompt(session_summary, is_success=is_success)

    try:
        raw = client.chat(
            system_prompt=system,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=2000,  # 增大以容纳 decision_mistakes 和 optimal_decision_path
        )
        # 解析 JSON
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip().rstrip("```").strip()
        parsed = json.loads(raw)
        return parsed
    except json.JSONDecodeError as e:
        logger.warning("[metacognitive] JSON 解析失败 session=%s err=%s", session_id[:8], e)
        return None
    except Exception as e:
        logger.warning("[metacognitive] LLM 调用失败 session=%s err=%s", session_id[:8], e)
        return None


def _rule_fingerprint(rule_text: str) -> str:
    """M-1: 基于规则文本生成 12 字符指纹，用于跨 session 规则去重标记。"""
    import hashlib as _hl
    import re as _re
    normalized = _re.sub(r'[\s\W]', '', rule_text.lower())[:80]
    return _hl.md5(normalized.encode("utf-8")).hexdigest()[:12]


def _validate_decision_mistakes(raw: Any) -> List[Dict[str, str]]:
    """校验并标准化 decision_mistakes 结构。

    每条 mistake 必须含 mistake/consequence/rule 三个字段。
    """
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw[:6]:  # 最多 6 条
        if not isinstance(item, dict):
            continue
        mistake = str(item.get("mistake", ""))[:200]
        consequence = str(item.get("consequence", ""))[:200]
        rule = str(item.get("rule", ""))[:200]
        if mistake and rule:
            result.append({
                "mistake": mistake,
                "consequence": consequence,
                "rule": rule,
                "rule_fingerprint": _rule_fingerprint(rule),  # M-1: 跨 session 去重键
            })
    return result


def _collect_text_snippets(value: Any, max_len: int = 300) -> List[str]:
    """递归收集文本片段并去重保序。"""
    collected: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            text = node.strip()
            if text:
                collected.append(text[:max_len])
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)
            return
        if isinstance(node, dict):
            for item in node.values():
                _walk(item)

    _walk(value)
    return list(dict.fromkeys(collected))


def _normalize_metacognitive_payload(parsed: Dict[str, Any], session_id: str = "") -> Dict[str, Any]:
    """兼容 legacy 输出格式，归一化到当前提取器所需字段。

    当前线上模型常返回：
      {
        "meta_cognitive_insights": {...},
        "reasoning": "..."
      }
    而提取器需要 decision_mistakes/key_lessons/optimal_decision_path。
    """
    if not isinstance(parsed, dict):
        return {}

    has_canonical = any(
        parsed.get(k)
        for k in ("decision_mistakes", "key_lessons", "optimal_decision_path")
    )
    insights = parsed.get("meta_cognitive_insights")
    if not isinstance(insights, dict):
        return parsed

    normalized = dict(parsed)

    # 1) transferable_decision_rules -> decision_mistakes
    transferable_rules = _ensure_str_list(insights.get("transferable_decision_rules", []), max_len=240)
    if not normalized.get("decision_mistakes") and transferable_rules:
        normalized["decision_mistakes"] = [
            {
                "mistake": "决策路径未显式固化为可执行规则",
                "consequence": "导致重复试错与策略切换滞后",
                "rule": rule,
            }
            for rule in transferable_rules
        ]

    # 2) 各子模块文本 -> key_lessons
    if not normalized.get("key_lessons"):
        lessons: List[str] = []
        for key in ("reconnaissance_lessons", "exploitation_lessons", "methodology_improvements"):
            lessons.extend(_collect_text_snippets(insights.get(key), max_len=220))
        lessons.extend(transferable_rules)
        normalized["key_lessons"] = list(dict.fromkeys(lessons))[:8]

    # 3) methodology_improvements -> optimal_decision_path
    if not normalized.get("optimal_decision_path"):
        opt_path: List[str] = []
        methodology = insights.get("methodology_improvements")
        if isinstance(methodology, dict):
            for field in (
                "attack_progression_rule",
                "failure_response_handling",
                "environment_assumption_check",
            ):
                value = methodology.get(field)
                if isinstance(value, str) and value.strip():
                    opt_path.append(value.strip()[:240])
        if not opt_path:
            opt_path = _ensure_str_list(normalized.get("key_lessons", []), max_len=240)[:4]
        normalized["optimal_decision_path"] = opt_path[:10]

    # 4) 推导 failure_pattern/success_factor/rag_effectiveness
    recon = insights.get("reconnaissance_lessons") if isinstance(insights.get("reconnaissance_lessons"), dict) else {}
    exploit = insights.get("exploitation_lessons") if isinstance(insights.get("exploitation_lessons"), dict) else {}

    if not normalized.get("failure_pattern"):
        fp = (
            exploit.get("persistent_failure_pattern")
            or exploit.get("defense_evasion_trigger")
            or ""
        )
        if isinstance(fp, str) and fp.strip():
            normalized["failure_pattern"] = fp.strip()[:200]

    if not normalized.get("success_factor"):
        sf_candidates = [
            recon.get("version_identification_success"),
            exploit.get("partial_success_analysis"),
        ]
        for sf in sf_candidates:
            if isinstance(sf, str) and sf.strip():
                normalized["success_factor"] = sf.strip()[:200]
                break

    if not normalized.get("rag_effectiveness"):
        reasoning = parsed.get("reasoning")
        if isinstance(reasoning, str) and reasoning.strip():
            normalized["rag_effectiveness"] = reasoning.strip()[:300]

    if session_id and not has_canonical:
        logger.info(
            "[metacognitive] session=%s 使用 legacy payload 归一化，top_keys=%s",
            session_id[:8],
            sorted(parsed.keys()),
        )

    return normalized


def extract_metacognitive_experience(
    ann_seq: AnnotatedTurnSequence,
    client: LLMClient,
    exp_counter: int = 1,
) -> Optional[Experience]:
    """从会话中提取 1 条 METACOGNITIVE 经验（LLM 驱动）。

    按技术方案 R-05 生成包含 decision_mistakes（IF-THEN 决策规则）和
    optimal_decision_path（最优决策序列）的完整元认知经验。

    Args:
        ann_seq     : Layer 1 标注完成的会话序列
        client      : LLM 客户端
        exp_counter : 经验 ID 计数器

    Returns:
        单条 METACOGNITIVE 经验，或 None（LLM 失败/条件不满足）
    """
    if not ann_seq.annotated_events:
        return None
    if ann_seq.session_outcome is None:
        return None

    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    so = ann_seq.session_outcome
    session_outcome_str = so.outcome_label if so else "unknown"

    # 构建会话摘要（IP 已去除）
    summary = _build_session_summary(ann_seq)

    # M-2：判断是否为成功会话，影响 LLM prompt 内容
    is_success_session = session_outcome_str in {"success", "partial_success"}

    # LLM 调用
    parsed = _call_metacognitive_llm(summary, client, session_id, is_success=is_success_session)
    if not parsed:
        return None
    parsed = _normalize_metacognitive_payload(parsed, session_id=session_id)

    # ── 提取核心字段（R-05 标准格式）─────────────────────────────────────────
    decision_mistakes = _validate_decision_mistakes(parsed.get("decision_mistakes", []))
    missed_opportunities = _ensure_str_list(parsed.get("missed_opportunities", []))[:5]
    optimal_path = _ensure_str_list(parsed.get("optimal_decision_path", []))[:10]
    rag_effectiveness = str(parsed.get("rag_effectiveness", ""))[:300]
    failure_pattern = str(parsed.get("failure_pattern", "") or "")[:200] or None
    success_factor = str(parsed.get("success_factor", "") or "")[:200] or None

    # ── M-2：成功会话专属字段提取 ────────────────────────────────────────────
    minimal_success_path: Optional[List[str]] = None
    replicability_conditions: Optional[List[str]] = None
    critical_decision_point: Optional[str] = None
    if is_success_session:
        msp = _ensure_str_list(parsed.get("minimal_success_path", []))[:10]
        if msp:
            minimal_success_path = msp
        rc = _ensure_str_list(parsed.get("replicability_conditions", []))[:6]
        if rc:
            replicability_conditions = rc
        cdp = str(parsed.get("critical_decision_point", "") or "")[:300]
        if cdp:
            critical_decision_point = cdp

    # ── 从 decision_mistakes 派生向后兼容字段 ────────────────────────────────
    # key_lessons = decision_mistakes.rule 字段列表（无则 fallback 到旧字段）
    if decision_mistakes:
        key_lessons = [m["rule"] for m in decision_mistakes]
    else:
        key_lessons = _ensure_str_list(parsed.get("key_lessons", []))[:5]


    # ── 最小内容验证 ──────────────────────────────────────────────────────────
    if not decision_mistakes and not key_lessons and not optimal_path:
        logger.warning(
            "[metacognitive] LLM 返回内容不足（decision_mistakes/key_lessons/optimal_path 均空）"
            " session=%s", session_id[:8],
        )
        return None

    # ── 交叉校验 outcome 与 failure_pattern/success_factor ───────────────────
    if is_success_session and not success_factor:
        success_factor = "（LLM 未提供，会话结果为成功）"
    elif not is_success_session and not failure_pattern:
        failure_pattern = "（LLM 未提供，会话结果为失败/部分成功）"


    content: Dict[str, Any] = {
        "session_goal": str(parsed.get("session_goal", target_raw or "未知"))[:200],
        "session_outcome": session_outcome_str,
        # R-05 核心字段
        "decision_mistakes": decision_mistakes,
        "missed_opportunities": missed_opportunities,
        "optimal_decision_path": optimal_path,
        # 核心教训（由 decision_mistakes.rule 派生）
        "key_lessons": key_lessons,
        "rag_effectiveness": rag_effectiveness,
        "failure_pattern": failure_pattern,
        "success_factor": success_factor,
        # M-2：成功会话专属字段（failure session 保持 None，不写入）
        "minimal_success_path": minimal_success_path,
        "replicability_conditions": replicability_conditions,
        "critical_decision_point": critical_decision_point,
    }

    # 全部来源 event_ids（涵盖全会话）
    all_event_ids = [e.event_id for e in ann_seq.annotated_events]
    all_turn_indices = list(dict.fromkeys(e.turn_index for e in ann_seq.annotated_events))

    # Tags：包含 mistake 规则名前缀，便于检索
    rule_tags = []
    for m in decision_mistakes[:3]:
        rule = m.get("rule", "")
        # 提取 "RULE_NAME：..." 格式中的规则名
        if "：" in rule:
            rule_tags.append(rule.split("：")[0].strip().lower())

    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=all_event_ids[:20],
        source_turn_indices=all_turn_indices,
        extraction_source=ExperienceSource.LLM,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        tags=list(dict.fromkeys(
            [session_outcome_str, "metacognitive"] + rule_tags
        )),
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{exp_counter:04d}",
        knowledge_layer=KnowledgeLayer.METACOGNITIVE,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=0.82,  # LLM + 结构化校验
    )


def _ensure_str_list(value: Any, max_len: int = 400) -> List[str]:
    """确保値为字符串列表，截断每项（中文内容限400全文字符）。"""
    if isinstance(value, list):
        return [str(v)[:max_len] for v in value if v]
    if isinstance(value, str) and value:
        return [value[:max_len]]
    return []
