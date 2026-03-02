"""
Conceptual 经验提取器（LLM 驱动）
=====================================
在单个会话内归纳「概念性规律」（CONCEPTUAL layer）和「RAG 效用评估」（RAG_EVALUATION layer）。

与 METACOGNITIVE（会话回顾）不同，CONCEPTUAL 专注于从
事件序列中归纳出可泛化的攻击模式/防御规避洞察，适合后续
跨会话融合（Layer 3）使用。

触发条件：
  - 会话包含 ≥ 2 个 EXPLOITATION 或 ESCALATION 成功事件，或
  - 会话包含 ≥ 3 个 PROCEDURAL_NEG 事件（失败经验多，规律显著），或
  - 会话有 RAG 有效采纳结果（adoption_level ≥ 2）

每个会话最多生成 2 条经验：
  1. CONCEPTUAL：主攻击规律（attack_strategy/vulnerability_pattern/...）
     - applicable_conditions 为结构化 dict（含 positive/negative/retrieval_triggers）
     - 初始 maturity=raw, confidence=0.3（Layer 3 融合时升级为 validated）
  2. RAG_EVALUATION：RAG 效用评估（rag_utility pattern_type）——仅当有效 RAG 采纳时生成
     - **独立存储，不进入 Agent 检索池**，仅供系统优化用途
"""

from __future__ import annotations

import json
import re
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
from ..utils.parameterizer import extract_cve_ids

logger = get_logger(__name__)

# 触发阈值
_MIN_SUCCESS_FOR_CONCEPTUAL = 2   # ≥N 个成功 EXPLOITATION/ESCALATION 事件
_MIN_FAILURE_FOR_CONCEPTUAL = 3   # 或 ≥N 个失败事件

# pattern_type 受控词汇表（与 ATT&CK tactics 对齐）
# 注意：空弹排除了 rag_utility——它单独层存想为 RAG_EVALUATION
_VALID_PATTERN_TYPES = frozenset({
    "attack_strategy",
    "vulnerability_pattern",
    "defense_bypass",
    "recon_pattern",
    "post_exploitation",
    "lateral_movement",
    "credential_attack",
    "privilege_escalation",
})
_DEFAULT_PATTERN_TYPE = "attack_strategy"


def _should_extract_conceptual(ann_seq: AnnotatedTurnSequence) -> bool:
    """判断是否满足 CONCEPTUAL 提取触发条件。"""
    exploit_success = sum(
        1 for e in ann_seq.annotated_events
        if e.attack_phase in ("EXPLOITATION", "ESCALATION")
        and e.outcome_label in ("success", "partial_success")
    )
    failure_count = sum(
        1 for e in ann_seq.annotated_events
        if e.failure_root_cause is not None
    )
    # 仅当 adoption_level ≥ 2 的 RAG 结果才算「有效采纳」
    has_useful_rag = any(
        r.adoption_level >= 2
        for r in (ann_seq.rag_adoption_results or [])
    )

    return (
        exploit_success >= _MIN_SUCCESS_FOR_CONCEPTUAL
        or failure_count >= _MIN_FAILURE_FOR_CONCEPTUAL
        or has_useful_rag
    )


def _select_key_events(ann_seq: AnnotatedTurnSequence) -> List:
    """智能选取关键事件（保留头/尾 + EXPLOITATION成功 + FRC事件 + RAG上下文事件）。

    避免直接截取前 40 个事件（可能错过后半段的 EXPLOITATION 关键动作）。
    """
    all_events = ann_seq.annotated_events
    if not all_events:
        return []

    head = list(all_events[:10])
    tail = list(all_events[-10:])

    # EXPLOITATION/ESCALATION 成功事件
    exploit_success = [
        e for e in all_events
        if e.attack_phase in ("EXPLOITATION", "ESCALATION")
        and e.outcome_label in ("success", "partial_success")
    ]
    # 失败根因事件
    frc_events = [e for e in all_events if e.failure_root_cause is not None]
    # RAG 上下文事件
    rag_events = [e for e in all_events if e.base.has_rag_context]

    seen_ids: set = set()
    combined = []
    for e in [*head, *exploit_success, *frc_events, *rag_events, *tail]:
        if e.event_id not in seen_ids:
            seen_ids.add(e.event_id)
            combined.append(e)
    # 按 turn_index 排序，限制总数
    combined.sort(key=lambda e: e.turn_index)
    return combined[:60]


def _build_conceptual_input(ann_seq: AnnotatedTurnSequence) -> str:
    """构建 CONCEPTUAL 提取的 LLM 输入（使用智能关键事件选取）。"""
    so = ann_seq.session_outcome
    outcome_label = so.outcome_label if so else "unknown"
    target = ann_seq.metadata.target_raw or "未知目标"

    key_events = _select_key_events(ann_seq)

    phase_outcome_pairs = []
    for ev in key_events:
        tool = ev.base.call.tool_name
        phase = ev.attack_phase or "?"
        outcome = ev.outcome_label or "?"
        frc = ""
        if ev.failure_root_cause:
            frc = f"[{ev.failure_root_cause.dimension.value}"
            if ev.failure_root_cause.sub_dimension:
                frc += f"/{ev.failure_root_cause.sub_dimension}"
            frc += "]"
        phase_outcome_pairs.append(f"  {phase}: {tool} → {outcome}{frc}")

    # CVE IDs：扫描命令 + 输出（nmap NSE / exploit 输出中常含CVE）
    all_text_parts = []
    for ev in ann_seq.annotated_events:
        args = ev.base.call.call_args or {}
        all_text_parts.append(args.get("command", "") + args.get("code", ""))
        if ev.base.result:
            raw_text = (ev.base.result.raw_result or {}).get("_raw_text", "") or ""
            all_text_parts.append(ev.base.result.stdout_raw or "")
            all_text_parts.append(raw_text)
    cve_ids = extract_cve_ids(" ".join(all_text_parts))

    rag_info = ""
    if ann_seq.rag_adoption_results:
        adoptions = [r.adoption_level for r in ann_seq.rag_adoption_results]
        useful = [a for a in adoptions if a >= 2]
        rag_info = (
            f"RAG查询 {len(adoptions)} 次，有效采纳 {len(useful)} 次，"
            f"平均采纳度 {sum(adoptions)/len(adoptions):.1f}，"
            f"BAR 分数 {ann_seq.bar_score:.2f}"
        )

    lines = [
        f"目标：{target}",
        f"最终结果：{outcome_label}",
        f"涉及 CVE：{', '.join(cve_ids) if cve_ids else '无'}",
        f"RAG 信息：{rag_info or '无 RAG 查询'}",
        f"",
        "关键事件序列摘要：",
    ] + phase_outcome_pairs

    return "\n".join(l for l in lines if l is not None)


def extract_conceptual_experiences(
    ann_seq: AnnotatedTurnSequence,
    client: LLMClient,
    exp_counter: int = 1,
) -> List[Experience]:
    """从会话提取最多 2 条 CONCEPTUAL 规律经验（LLM 驱动）。

    Args:
        ann_seq     : Layer 1 标注完成的会话序列
        client      : LLM 客户端
        exp_counter : 经验 ID 计数器起始值

    Returns:
        CONCEPTUAL 经验列表（0-2 条）：
        - [0]: 主攻击规律（attack_pattern）
        - [1]: RAG 效用规律（rag_utility），仅当有效 RAG 采纳时生成
    """
    if not _should_extract_conceptual(ann_seq):
        return []
    if not ann_seq.annotated_events:
        return []

    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    so = ann_seq.session_outcome
    session_outcome_str = so.outcome_label if so else "unknown"
    bar_score = ann_seq.bar_score

    results: List[Experience] = []

    # ── 第 1 条：主攻击规律 ───────────────────────────────────────────────
    input_text = _build_conceptual_input(ann_seq)
    parsed = _call_conceptual_llm(input_text, client, session_id)
    if parsed:
        exp = _build_experience_from_parsed(
            parsed=parsed,
            session_id=session_id,
            target_raw=target_raw,
            session_outcome_str=session_outcome_str,
            bar_score=bar_score,
            ann_seq=ann_seq,
            exp_counter=exp_counter,
        )
        if exp:
            results.append(exp)
            exp_counter += 1

    # ── 第 2 条：RAG 效用规律（仅当有效 RAG 采纳时生成）────────────────────
    has_useful_rag = any(
        r.adoption_level >= 2
        for r in (ann_seq.rag_adoption_results or [])
    )
    if has_useful_rag:
        rag_exp = _extract_rag_utility_experience(
            ann_seq=ann_seq,
            client=client,
            session_id=session_id,
            target_raw=target_raw,
            session_outcome_str=session_outcome_str,
            bar_score=bar_score,
            exp_counter=exp_counter,
        )
        if rag_exp:
            results.append(rag_exp)

    return results


def _build_experience_from_parsed(
    parsed: Dict[str, Any],
    session_id: str,
    target_raw: Optional[str],
    session_outcome_str: str,
    bar_score: float,
    ann_seq: AnnotatedTurnSequence,
    exp_counter: int,
) -> Optional[Experience]:
    """从 LLM 解析结果构建 CONCEPTUAL Experience，含结构验证。"""
    # ── 字段验证 ──────────────────────────────────────────────────────────
    core_insight = str(parsed.get("core_insight", "")).strip()
    if not core_insight or len(core_insight) < 20:
        logger.warning(
            "[conceptual] LLM 返回 core_insight 为空或过短 session=%s", session_id[:8]
        )
        return None

    # pattern_type 受控词汇约束
    raw_pt = str(parsed.get("pattern_type", "")).strip().lower()
    pattern_type = raw_pt if raw_pt in _VALID_PATTERN_TYPES else _DEFAULT_PATTERN_TYPE

    applicable = _normalize_applicable_conditions(parsed.get("applicable_conditions", []))
    if not applicable.get("positive"):
        logger.warning(
            "[conceptual] LLM 返回空 applicable_conditions.positive session=%s", session_id[:8]
        )
        return None

    content: Dict[str, Any] = {
        "pattern_type": pattern_type,
        # C-3: applicable_conditions 现为结构化 dict
        "applicable_conditions": _normalize_applicable_conditions(parsed.get("applicable_conditions", [])),
        "core_insight": core_insight[:400],
        "supporting_evidence": _ensure_str_list(parsed.get("supporting_evidence", []))[:5],
        "confidence_basis": str(parsed.get("confidence_basis", ""))[:200],
    }

    all_turn_indices = list(dict.fromkeys(e.turn_index for e in ann_seq.annotated_events))
    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=[e.event_id for e in ann_seq.annotated_events[:10]],
        source_turn_indices=all_turn_indices,
        extraction_source=ExperienceSource.LLM,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        session_bar_score=bar_score,
        tags=["conceptual", pattern_type, session_outcome_str]
        + _extract_retrieval_triggers(parsed.get("applicable_conditions", {})),
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{exp_counter:04d}",
        knowledge_layer=KnowledgeLayer.CONCEPTUAL,
        content=content,
        metadata=metadata,
        # C-2: 单 session 永远是 raw + confidence=0.3
        # Layer3 聚合 ≥₃条同类时可升为 validated（接口预留）
        maturity=ExperienceMaturity.RAW,
        confidence=0.3,
    )


def _extract_rag_utility_experience(
    ann_seq: AnnotatedTurnSequence,
    client: LLMClient,
    session_id: str,
    target_raw: Optional[str],
    session_outcome_str: str,
    bar_score: float,
    exp_counter: int,
) -> Optional[Experience]:
    """生成第 2 条 CONCEPTUAL 经验：RAG 效用规律（rag_utility pattern_type）。"""
    from ...prompts import CONCEPTUAL_SYSTEM, build_rag_utility_prompt  # noqa: F401

    rag_results = ann_seq.rag_adoption_results or []
    useful = [r for r in rag_results if r.adoption_level >= 2]

    # 构建 RAG 效用摘要输入
    lines = [
        f"目标：{ann_seq.metadata.target_raw or '未知'}",
        f"最终结果：{session_outcome_str}",
        f"BAR 分数：{bar_score:.2f}",
        f"RAG 有效采纳次数：{len(useful)} / {len(rag_results)}",
        "",
        "有效 RAG 采纳事件（adoption_level≥2）：",
    ]
    for r in useful[:10]:
        lines.append(
            f"  - 查询：{(r.query or '')[:80]}  采纳度：{r.adoption_level}"
            + (f"  推理：{str(r.reasoning or '')[:80]}" if r.reasoning else "")
        )

    input_text = "\n".join(lines)

    try:
        user_prompt = build_rag_utility_prompt(input_text)
        raw = client.chat(
            system_prompt=CONCEPTUAL_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=600,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip().rstrip("```").strip()
        parsed = json.loads(raw)
    except Exception as e:
        logger.warning("[conceptual/rag_utility] LLM 失败 session=%s err=%s", session_id[:8], e)
        return None

    core_insight = str(parsed.get("core_insight", "")).strip()
    if not core_insight or len(core_insight) < 20:
        return None

    content: Dict[str, Any] = {
        "pattern_type": "rag_utility",
        "applicable_conditions": _ensure_str_list(parsed.get("applicable_conditions", []))[:5],
        "core_insight": core_insight[:400],
        "supporting_evidence": _ensure_str_list(parsed.get("supporting_evidence", []))[:5],
        "confidence_basis": str(parsed.get("confidence_basis", ""))[:200],
        "rag_adoption_stats": {
            "total_queries": len(rag_results),
            "useful_adoptions": len(useful),
            "bar_score": bar_score,
        },
    }

    all_turn_indices = list(dict.fromkeys(e.turn_index for e in ann_seq.annotated_events))
    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=[e.event_id for e in ann_seq.annotated_events[:10]],
        source_turn_indices=all_turn_indices,
        extraction_source=ExperienceSource.LLM,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        session_bar_score=bar_score,
        tags=["rag_evaluation", "rag_utility", session_outcome_str],
    )

    # C-1: RAG 效用评估独立存储为 RAG_EVALUATION 层，不参与 Agent 检索池
    return Experience(
        exp_id=f"exp_{session_id[:8]}_{exp_counter:04d}",
        knowledge_layer=KnowledgeLayer.RAG_EVALUATION,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=0.70,
    )


def _normalize_applicable_conditions(raw: Any) -> Dict[str, Any]:
    """C-3: 将 LLM 输出的 applicable_conditions 规范化为结构化 dict。

    支持两种 LLM 输出格式：
    1. dict 格式（新格式，含 positive/negative/retrieval_triggers 等）
    2. list 格式（旧格式，向后兼容，全部放入 positive）
    """
    if isinstance(raw, dict):
        # P1/P2: 过滤包含 prompt 模板示例标记的 retrieval_triggers 条目
        # 覆盖以下模式：
        #   "触发检索的关键词1（软件名/CVE/技术名）"  → 关键词\d+ / 软件名.CVE
        #   "触发词2（如：ENV/BINARY_MISSING…）"      → 触发词\d+ / （如[：:]
        #   "必须满足的条件1"                          → 条件\d+
        #   纯描述性文字（含汉字 + 数字编号）
        _TEMPLATE_RE = re.compile(
            r'（如[：:]|例如|触发词\d+|关键词\d+|软件名[/／]CVE|条件\d+|证据\d+|'
            r'触发检索|攻击规律|来自本次会话|【描述】|\d+（[^）]{5,}）'
        )
        raw_triggers = _ensure_str_list(raw.get("retrieval_triggers", []))
        valid_triggers = [t for t in raw_triggers if not _TEMPLATE_RE.search(t)]
        if len(valid_triggers) < len(raw_triggers):
            logger.warning(
                "[conceptual] retrieval_triggers 含模板示例文字，已过滤 %d 条",
                len(raw_triggers) - len(valid_triggers),
            )
        return {
            "positive": _ensure_str_list(raw.get("positive", []))[:5],
            "negative": _ensure_str_list(raw.get("negative", []))[:3],
            "priority_over": _ensure_str_list(raw.get("priority_over", []))[:3],
            "retrieval_triggers": valid_triggers[:8],
        }
    elif isinstance(raw, list):
        # 向后兼容：旧格式 list → 全部归入 positive
        positive = _ensure_str_list(raw)[:5]
        return {
            "positive": positive,
            "negative": [],
            "priority_over": [],
            "retrieval_triggers": [],
        }
    return {"positive": [], "negative": [], "priority_over": [], "retrieval_triggers": []}


def _extract_retrieval_triggers(applicable_conditions: Any) -> List[str]:
    """从 applicable_conditions 中提取 retrieval_triggers（用于 metadata.tags）。"""
    if isinstance(applicable_conditions, dict):
        return applicable_conditions.get("retrieval_triggers", [])[:5]
    return []


def _call_conceptual_llm(
    input_text: str,
    client: LLMClient,
    session_id: str,
) -> Optional[Dict[str, Any]]:
    """调用 LLM 提取 CONCEPTUAL 规律。"""
    from ...prompts import CONCEPTUAL_SYSTEM, build_conceptual_prompt

    user_prompt = build_conceptual_prompt(input_text)

    try:
        raw = client.chat(
            system_prompt=CONCEPTUAL_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=800,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip().rstrip("```").strip()
        return json.loads(raw)
    except Exception as e:
        logger.warning("[conceptual] LLM 失败 session=%s err=%s", session_id[:8], e)
        return None


def _ensure_str_list(value: Any, max_len: int = 400) -> List[str]:
    if isinstance(value, list):
        return [str(v)[:max_len] for v in value if v]
    if isinstance(value, str) and value:
        return [value[:max_len]]
    return []


# ── 向后兼容别名（旧代码可能调用 extract_conceptual_experience）─────────────
def extract_conceptual_experience(
    ann_seq: AnnotatedTurnSequence,
    client: LLMClient,
    exp_counter: int = 1,
) -> Optional[Experience]:
    """已废弃：请使用 extract_conceptual_experiences()（返回列表）。"""
    results = extract_conceptual_experiences(ann_seq, client, exp_counter)
    return results[0] if results else None

