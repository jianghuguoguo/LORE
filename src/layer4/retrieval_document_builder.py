"""
Build retrieval-friendly documents before RAGFlow reflux.

This module turns structured KLM experiences into short, query-oriented
plain text documents, validates quality constraints, and returns routing hints
(primary/secondary) for downstream upload.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DOC_MAX_WORDS = 300
_SENSITIVE_KEYS = frozenset({"command", "cmd", "payload", "exploit_code", "exec"})

DOCUMENT_BUILDER_SYSTEM = (
    "You are a retrieval document writer for pentest knowledge. "
    "Produce concise, high-signal plain text docs for semantic retrieval."
)


@dataclass
class RetrievalDocBuildResult:
    content_text: str
    quality_issues: List[str] = field(default_factory=list)
    route: str = "primary"  # primary | secondary
    word_count: int = 0


def normalize_layer(layer: str) -> str:
    if str(layer).startswith("FACTUAL_"):
        return "FACTUAL"
    return layer or "UNKNOWN"


def _strip_sensitive(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if k in _SENSITIVE_KEYS else _strip_sensitive(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_strip_sensitive(v) for v in obj]
    return obj


def _safe_json(obj: Any, max_len: int = 3600) -> str:
    try:
        text = json.dumps(_strip_sensitive(obj), ensure_ascii=False)
    except Exception:
        text = str(obj)
    if len(text) > max_len:
        return text[:max_len] + " ...[truncated]"
    return text


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_\-]*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    return text.strip()


def _extract_cve_ids(exp: Dict[str, Any]) -> List[str]:
    cves: List[str] = []

    def _add(values: Any) -> None:
        if isinstance(values, list):
            for x in values:
                sx = str(x).upper().strip()
                if sx.startswith("CVE-") and sx not in cves:
                    cves.append(sx)

    content = exp.get("content", {}) or {}
    metadata = exp.get("metadata", {}) or {}
    constraints = metadata.get("applicable_constraints", {}) or {}

    _add(exp.get("cve_ids"))
    _add(content.get("cve_ids"))
    _add(constraints.get("cve_ids"))

    cve_ctx = content.get("cve_context", {}) or {}
    _add(cve_ctx.get("attempted"))
    cem = content.get("cve_exploitation_map", {}) or {}
    if isinstance(cem, dict):
        for k in cem.keys():
            sk = str(k).upper().strip()
            if sk.startswith("CVE-") and sk not in cves:
                cves.append(sk)

    fallback_text = _safe_json({"content": content, "metadata": metadata}, max_len=2200)
    for m in re.findall(r"CVE-\d{4}-\d+", fallback_text, flags=re.IGNORECASE):
        sm = m.upper()
        if sm not in cves:
            cves.append(sm)

    return cves


def _extract_target_service(exp: Dict[str, Any]) -> str:
    content = exp.get("content", {}) or {}
    metadata = exp.get("metadata", {}) or {}
    constraints = metadata.get("applicable_constraints", {}) or {}
    return (
        exp.get("target_service")
        or content.get("target_service")
        or constraints.get("target_service")
        or "unknown"
    )


def _build_query_hints(exp: Dict[str, Any], layer: str, target_service: str, cve_ids: List[str]) -> List[str]:
    hints: List[str] = [layer]
    if target_service and target_service != "unknown":
        hints.append(target_service)
    hints.extend(cve_ids[:8])

    content = exp.get("content", {}) or {}
    for k in ("attack_phase", "failure_dimension", "failure_sub_dimension", "pattern_type"):
        v = content.get(k)
        if v:
            hints.append(str(v))

    # preserve order and deduplicate
    seen: set = set()
    deduped: List[str] = []
    for h in hints:
        hs = str(h).strip()
        if not hs or hs in seen:
            continue
        seen.add(hs)
        deduped.append(hs)
    return deduped[:12]


def _build_template_document(exp: Dict[str, Any]) -> str:
    exp_id = exp.get("exp_id", "UNKNOWN")
    layer = normalize_layer(str(exp.get("knowledge_layer", "UNKNOWN")))
    maturity = str(exp.get("maturity", "unknown"))
    confidence = exp.get("p_fused") or exp.get("confidence") or 0.0
    target_service = _extract_target_service(exp)
    cve_ids = _extract_cve_ids(exp)

    content = exp.get("content", {}) or {}
    summary_lines: List[str] = []

    if layer == "PROCEDURAL_NEG":
        dr = content.get("decision_rule", {}) or {}
        summary_lines.append(f"failure_dimension: {content.get('failure_dimension', 'unknown')}")
        summary_lines.append(f"failure_sub_dimension: {content.get('failure_sub_dimension', 'unknown')}")
        if dr.get("IF"):
            summary_lines.append(f"if_condition: {dr.get('IF')}")
        if dr.get("THEN"):
            summary_lines.append(f"then_actions: {dr.get('THEN')}")
        if dr.get("NOT"):
            summary_lines.append(f"avoid: {dr.get('NOT')}")
    elif layer == "PROCEDURAL_POS":
        summary_lines.append(f"attack_phase: {content.get('attack_phase', 'unknown')}")
        if content.get("preconditions"):
            summary_lines.append(f"preconditions: {content.get('preconditions')}")
        if content.get("success_indicators"):
            summary_lines.append(f"success_indicators: {content.get('success_indicators')}")
    elif layer == "FACTUAL":
        if content.get("discovered_facts"):
            summary_lines.append(f"discovered_facts: {content.get('discovered_facts')}")
        if content.get("cve_exploitation_map"):
            summary_lines.append(f"cve_exploitation_map: {content.get('cve_exploitation_map')}")
        if content.get("cve_unexplored"):
            summary_lines.append(f"cve_unexplored: {content.get('cve_unexplored')}")
    elif layer == "CONCEPTUAL":
        if content.get("core_insight"):
            summary_lines.append(f"core_insight: {content.get('core_insight')}")
        if content.get("applicable_conditions"):
            summary_lines.append(f"applicable_conditions: {content.get('applicable_conditions')}")
    elif layer == "METACOGNITIVE":
        if content.get("session_goal"):
            summary_lines.append(f"session_goal: {content.get('session_goal')}")
        if content.get("key_lessons"):
            summary_lines.append(f"key_lessons: {content.get('key_lessons')}")
    else:
        summary_lines.append(_safe_json(content, max_len=1500))

    hints = _build_query_hints(exp, layer, target_service, cve_ids)

    lines: List[str] = [
        f"[XPEC] {layer} | {exp_id}",
        f"knowledge_layer: {layer}",
        f"target_service: {target_service}",
        f"maturity: {maturity}",
        f"confidence: {float(confidence):.4f}",
    ]

    if cve_ids:
        lines.append("cve_ids: " + ", ".join(cve_ids))

    lines.append("")
    lines.append("SUMMARY:")
    for s in summary_lines[:8]:
        lines.append("- " + str(s)[:360])

    lines.append("")
    lines.append("QUERY_HINTS:")
    for hint in hints:
        lines.append("- " + hint)

    return "\n".join(lines).strip()


def _build_llm_prompt(exp: Dict[str, Any], fallback_doc: str) -> str:
    return (
        "Convert the following pentest experience JSON into a retrieval-first plain text document.\n"
        "Hard requirements:\n"
        "1) <= 300 words\n"
        "2) First 5 non-empty lines must include [XPEC], knowledge_layer, target_service\n"
        "3) Must include a section header exactly named QUERY_HINTS:\n"
        "4) Every CVE listed in input must appear in output\n"
        "5) Do not output code blocks; do not include scripts\n"
        "\n"
        "Input JSON:\n"
        f"{_safe_json(exp)}\n\n"
        "You may reuse this fallback template and improve wording:\n"
        f"{fallback_doc}\n\n"
        "Output plain text only."
    )


def _call_builder_llm(exp: Dict[str, Any], fallback_doc: str, llm_client: Any) -> Optional[str]:
    if llm_client is None:
        return None
    if not hasattr(llm_client, "chat"):
        return None

    prompt = _build_llm_prompt(exp, fallback_doc)
    try:
        text = llm_client.chat(
            system_prompt=DOCUMENT_BUILDER_SYSTEM,
            user_prompt=prompt,
            temperature=0.1,
            max_tokens=900,
        )
        text = _strip_code_fences(text or "")
        return text.strip() if text else None
    except Exception as exc:
        logger.warning("[reflux_doc] LLM build failed exp_id=%s err=%s", exp.get("exp_id"), exc)
        return None


def _word_count(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def _has_code_like_injection(text: str) -> bool:
    if "```" in text:
        return True
    # Explicitly guard against script-like payloads.
    if len(re.findall(r"\b(import|def)\b", text)) > 2:
        return True
    return False


def validate_retrieval_document(exp: Dict[str, Any], doc_text: str) -> List[str]:
    issues: List[str] = []
    layer = normalize_layer(str(exp.get("knowledge_layer", "UNKNOWN")))
    target_service = _extract_target_service(exp)
    cve_ids = _extract_cve_ids(exp)

    non_empty = [ln.strip() for ln in doc_text.splitlines() if ln.strip()]
    first5 = "\n".join(non_empty[:5])
    first5_lower = first5.lower()

    if "[xpec]" not in first5_lower:
        issues.append("missing_header_xpec")
    if layer.lower() not in first5_lower:
        issues.append("missing_header_layer")
    if target_service and target_service != "unknown":
        if str(target_service).lower() not in first5_lower:
            issues.append("missing_header_target_service")

    if "QUERY_HINTS:" not in doc_text:
        issues.append("missing_query_hints")

    doc_lower = doc_text.lower()
    missing_cves = [c for c in cve_ids if c.lower() not in doc_lower]
    if missing_cves:
        issues.append("missing_cve_ids:" + ",".join(missing_cves[:6]))

    wc = _word_count(doc_text)
    if wc > _DOC_MAX_WORDS:
        issues.append(f"too_long_words:{wc}")

    if _has_code_like_injection(doc_text):
        issues.append("code_like_content")

    return issues


def build_retrieval_document(
    exp: Dict[str, Any],
    llm_client: Optional[Any] = None,
) -> RetrievalDocBuildResult:
    """
    Build a retrieval document and apply quality gates.

    Route decision:
    - primary: no quality issue
    - secondary: at least one quality issue
    """
    fallback_doc = _build_template_document(exp)
    candidate_doc = fallback_doc

    llm_doc = _call_builder_llm(exp, fallback_doc, llm_client) if llm_client is not None else None
    if llm_doc:
        candidate_doc = llm_doc

    candidate_doc = _strip_code_fences(candidate_doc)
    if not candidate_doc:
        candidate_doc = fallback_doc

    issues = validate_retrieval_document(exp, candidate_doc)

    # If LLM output has quality issues, fallback to deterministic template once.
    if issues and llm_doc:
        candidate_doc = fallback_doc
        issues = validate_retrieval_document(exp, candidate_doc)

    wc = _word_count(candidate_doc)
    route = "secondary" if issues else "primary"

    return RetrievalDocBuildResult(
        content_text=candidate_doc.strip(),
        quality_issues=issues,
        route=route,
        word_count=wc,
    )
