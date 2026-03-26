"""
LLM 驱动的 FACTUAL 提取器（目标服务识别）
==========================================
按技术方案 R-02 要求，使用 LLM 从会话中识别：
  - 目标服务名称与版本（软件而非 IP）
  - CVE 上下文（已尝试、结果、未探索）
  - 可用约束（网络拓扑、有效/无效向量）
  - 漏洞利用状态

与规则驱动 factual.py 的区别：
  - 规则提取：端口/服务/路径等结构化输出（基于正则）
  - LLM 提取：软件名+版本+CVE关联（语义理解，不绑定 IP）

每个会话生成 **一条** 服务抽象的 FACTUAL 经验。
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from ...models import AnnotatedTurnSequence
from ...utils.log_utils import get_logger
from ...utils.service_name_normalizer import normalize_service_name as shared_normalize_service_name
from ..experience_models import (
    Experience,
    ExperienceMaturity,
    ExperienceMetadata,
    ExperienceSource,
    KnowledgeLayer,
)

logger = get_logger(__name__)

def canonicalize_service_name(name: str) -> str:
    """向后兼容别名：统一走共享服务名规范化实现。"""
    return shared_normalize_service_name(name)

_RECON_PHASES = {"RECON_WEAPONIZATION", "ENV_PREPARATION"}
_EXPLOIT_PHASES = {"EXPLOITATION", "ESCALATION", "LATERAL_MOVEMENT", "EXFILTRATION"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# 内部辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _get_event_text(event) -> str:
    """提取事件的工具输入命令和输出文本（取前 600 字符总量）。"""
    parts: List[str] = []
    # 命令/代码输入
    args = event.base.call.call_args or {}
    cmd = args.get("command", "") or args.get("code", "")
    if cmd:
        parts.append(str(cmd)[:300])
    # 标准输出
    result = event.base.result
    if result:
        stdout = str(result.stdout_raw or "")
        stderr = str(result.stderr_raw or "")
        raw_text = str((result.raw_result or {}).get("_raw_text", "") or "")
        merged_output = "\n".join(part for part in (stdout, stderr, raw_text) if part)
        if merged_output:
            parts.append(merged_output[:300])
    return " | ".join(parts)[:600]


def _build_recon_summary(ann_seq: AnnotatedTurnSequence, max_items: int = 6) -> str:
    """从 RECON 阶段事件构建侦察摘要（用于 LLM 提示）。

    保留最多 max_items 条最具代表性的 RECON 事件文本。
    """
    lines: List[str] = []
    for event in ann_seq.annotated_events:
        if event.attack_phase not in _RECON_PHASES:
            continue
        tool = event.base.call.tool_name if event.base and event.base.call else "unknown"
        text = _get_event_text(event)
        if text:
            lines.append(f"[{tool}] {text}")
        if len(lines) >= max_items:
            break
    return "\n".join(lines) if lines else "（无 RECON 阶段数据）"


def _build_exploit_summary(ann_seq: AnnotatedTurnSequence, max_items: int = 12) -> str:
    """从 EXPLOITATION 阶段事件构建漏洞利用摘要（用于 LLM 提示）。

    优先选取带 CVE 的事件，其次按阶段顺序。
    max_items=12（原6）避免成功利用事件出现在会话后期时被截断。
    """
    cve_events: List[str] = []
    other_events: List[str] = []

    for event in ann_seq.annotated_events:
        if event.attack_phase not in _EXPLOIT_PHASES:
            continue
        tool = event.base.call.tool_name if event.base and event.base.call else "unknown"
        text = _get_event_text(event)
        outcome = event.outcome_label or "unknown"
        if not text:
            continue
        entry = f"[{tool}][{outcome}] {text}"
        cves = _CVE_RE.findall(text)
        if cves:
            cve_events.append(entry)
        else:
            other_events.append(entry)

    combined = cve_events[:max_items] + other_events[:max(0, max_items - len(cve_events))]
    return "\n".join(combined) if combined else "（无 EXPLOITATION 阶段数据）"


def _infer_target_ip_hint(ann_seq: AnnotatedTurnSequence) -> str:
    """提取目标 IP 提示（仅传给 LLM 帮助理解拓扑，不出现在经验内容中）。"""
    target = ann_seq.metadata.target_raw or ""
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", target)
    if m:
        ip = m.group(1)
        octets = ip.split(".")
        if octets[0] == "127":
            return f"{ip} (loopback)"
        elif octets[0] in ("10",) or (octets[0] == "172" and 16 <= int(octets[1]) <= 31) or (octets[0] == "192" and octets[1] == "168"):
            return f"{ip} (internal)"
        else:
            return f"{ip} (external)"
    if target:
        return f"{target} (domain/unknown)"
    return "unknown"


def _collect_attempted_cves_from_events(ann_seq: AnnotatedTurnSequence) -> List[str]:
    """当 LLM 未返回 attempted 时，从会话事件中兜底提取 CVE 列表。"""
    cves: List[str] = []
    for event in ann_seq.annotated_events:
        if event.attack_phase not in _EXPLOIT_PHASES:
            continue
        text = _get_event_text(event)
        for cve in _CVE_RE.findall(text):
            cve_u = cve.upper()
            if cve_u not in cves:
                cves.append(cve_u)
    return cves[:10]


def _infer_cve_results_from_events(
    ann_seq: AnnotatedTurnSequence,
    attempted_cves: List[str],
) -> Dict[str, str]:
    """基于事件证据推断每个 attempted CVE 的 exploitation_results 兜底状态。"""
    inferred: Dict[str, str] = {}
    for cve in attempted_cves:
        cve_u = str(cve).upper()
        status = "unknown"
        for event in ann_seq.annotated_events:
            if event.attack_phase not in _EXPLOIT_PHASES:
                continue
            text = _get_event_text(event)
            if cve_u not in text.upper():
                continue

            txt_lower = text.lower()
            outcome = (event.outcome_label or "").lower()

            if "not vulnerable" in txt_lower or "already patched" in txt_lower:
                status = "patched"
                break
            if outcome == "success":
                status = "success"
                continue
            if outcome == "partial_success" and status not in ("success", "patched"):
                status = "partial"
                continue
            if outcome in ("failure", "timeout") and status == "unknown":
                status = "failure"

        inferred[cve_u] = status
    return inferred


def _call_factual_llm(
    recon_summary: str,
    exploit_summary: str,
    target_ip_hint: str,
    client,
    session_id: str,
    session_outcome: str = "unknown",
) -> Optional[Dict[str, Any]]:
    """调用 LLM 生成服务抄象的 FACTUAL 知识。"""
    from ...prompts import FACTUAL_SYSTEM, build_factual_prompt

    user_prompt = build_factual_prompt(
        recon_summary, exploit_summary, target_ip_hint,
        session_outcome=session_outcome,  # P0-C: 注入会话结果辅助判断 exploitation_status
    )

    try:
        raw = client.chat(
            system_prompt=FACTUAL_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.1,
            max_tokens=1200,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip().rstrip("```").strip()
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("[factual_llm] JSON 解析失败 session=%s err=%s", session_id[:8], e)
        return None
    except Exception as e:
        logger.warning("[factual_llm] LLM 调用失败 session=%s err=%s", session_id[:8], e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 公开 API
# ─────────────────────────────────────────────────────────────────────────────

def extract_factual_experience_llm(
    ann_seq: AnnotatedTurnSequence,
    client,
    exp_counter: int = 1,
) -> Optional[Experience]:
    """使用 LLM 从会话中提取 1 条服务抽象的 FACTUAL 经验（R-02 标准）。

    产出内容以 *服务* 而非 *IP* 为核心，符合知识库跨目标复用的要求。

    Args:
        ann_seq    : Layer 1 标注完成的会话序列
        client     : LLMClient 实例
        exp_counter: 经验 ID 计数器

    Returns:
        单条 FACTUAL 经验，或 None（LLM 失败/会话无有效数据）
    """
    if not ann_seq.annotated_events:
        return None

    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    session_outcome_str = "unknown"

    if ann_seq.session_outcome:
        session_outcome_str = ann_seq.session_outcome.outcome_label

    recon_summary = _build_recon_summary(ann_seq)
    exploit_summary = _build_exploit_summary(ann_seq)
    target_ip_hint = _infer_target_ip_hint(ann_seq)

    # 两部分都为默认值时跳过（会话无有效内容）
    if recon_summary == "（无 RECON 阶段数据）" and exploit_summary == "（无 EXPLOITATION 阶段数据）":
        logger.debug("[factual_llm] 会话无 RECON/EXPLOIT 数据，跳过 session=%s", session_id[:8])
        return None

    parsed = _call_factual_llm(
        recon_summary, exploit_summary, target_ip_hint, client, session_id,
        session_outcome=session_outcome_str,  # P0-C
    )
    if not parsed:
        return None

    # ── 校验核心字段 ─────────────────────────────────────────────────────────
    target_service_raw = str(parsed.get("target_service", ""))[:100].strip()
    # P1: 仅过滤完全为空的服务名；"Unknown Service" 等保留（低置信度但有参考价值）
    if not target_service_raw:
        logger.debug("[factual_llm] LLM 未识别出服务名（空）session=%s", session_id[:8])
        return None

    cve_context_raw = parsed.get("cve_context", {})
    if not isinstance(cve_context_raw, dict):
        cve_context_raw = {}
    raw_version_for_check = parsed.get("target_version")
    target_version_for_check = str(raw_version_for_check).strip() if raw_version_for_check is not None else ""
    cve_list_for_check = [
        str(c)
        for c in cve_context_raw.get("attempted", [])
        if str(c).strip()
    ]
    has_substance = (
        bool(cve_list_for_check)
        or (
            target_version_for_check
            and target_version_for_check.lower() not in ("none", "null", "unknown", "")
        )
    )
    if not has_substance:
        logger.debug(
            "[factual_llm] FACTUAL 内容无实质（无CVE且无版本），跳过 service=%s session=%s",
            target_service_raw[:40],
            session_id[:8],
        )
        return None

    # P2: 规范化服务名
    target_service = canonicalize_service_name(target_service_raw)

    # 🟡 Fix: JSON null → Python None → str(None) = "None" 需要规范化
    _raw_ver = parsed.get("target_version")
    target_version = str(_raw_ver).strip()[:50] if _raw_ver is not None else ""
    if target_version.lower() in ("none", "null", "unknown", ""):
        target_version = ""
    exploitation_status = str(parsed.get("exploitation_status", "unknown"))[:30]

    attempted_cves = [str(c).upper()[:30] for c in cve_context_raw.get("attempted", [])[:10] if str(c).strip()]
    if not attempted_cves:
        attempted_cves = _collect_attempted_cves_from_events(ann_seq)

    llm_exploitation_results = {
        str(k).upper()[:30]: str(v)[:100]
        for k, v in cve_context_raw.get("exploitation_results", {}).items()
        if str(k).strip()
    }
    inferred_results = _infer_cve_results_from_events(ann_seq, attempted_cves)

    merged_exploitation_results: Dict[str, str] = {}
    for cve in attempted_cves:
        cve_u = cve.upper()
        llm_status = (llm_exploitation_results.get(cve_u) or "").strip().lower()
        if llm_status:
            merged_exploitation_results[cve_u] = llm_status
        else:
            merged_exploitation_results[cve_u] = inferred_results.get(cve_u, "unknown")

    cve_context = {
        "attempted": attempted_cves,
        "exploitation_results": merged_exploitation_results,
        "unexplored": [str(c).upper()[:30] for c in cve_context_raw.get("unexplored", [])[:10] if str(c).strip()],
    }

    constraints_raw = parsed.get("applicable_constraints", {})
    if not isinstance(constraints_raw, dict):
        constraints_raw = {}
    applicable_constraints = {
        "network_topology": str(constraints_raw.get("network_topology", "unknown"))[:30],
        "service_versions": [str(v)[:50] for v in constraints_raw.get("service_versions", [])[:5]],
        "known_ineffective_vectors": [
            str(v)[:100] for v in constraints_raw.get("known_ineffective_vectors", [])[:8]
        ],
    }

    content: Dict[str, Any] = {
        # LLM 提取的服务抽象知识（R-02 核心字段）
        "target_service": target_service,
        "target_version": target_version,
        "cve_context": cve_context,
        "applicable_constraints": applicable_constraints,
        "exploitation_status": exploitation_status,
        "extraction_method": "llm_service_abstract",
    }

    # 源事件 IDs（全会话）
    all_event_ids = [e.event_id for e in ann_seq.annotated_events]
    all_turn_indices = list(dict.fromkeys(e.turn_index for e in ann_seq.annotated_events))

    # Tags：服务名 + CVE IDs（便于检索）
    tags = [target_service.lower().replace(" ", "_"), exploitation_status, "llm_factual"]
    for cve in cve_context.get("attempted", [])[:3]:
        tags.append(cve.upper())

    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=all_event_ids[:20],
        source_turn_indices=all_turn_indices,
        extraction_source=ExperienceSource.LLM,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        tags=list(dict.fromkeys(tags)),
        # P1: 将 target_service / cve_ids 填入 metadata.applicable_constraints，支持检索时精确过滤
        applicable_constraints={
            "target_service": target_service,
            "target_version": target_version,
            "cve_ids": cve_context.get("attempted", [])[:5],
            "service_type": "http",  # placeholder; refined downstream
        },
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{exp_counter:04d}",
        knowledge_layer=KnowledgeLayer.FACTUAL,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=0.80,
    )
