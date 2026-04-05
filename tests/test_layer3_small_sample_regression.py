from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from src.layer3 import (
    cluster_experiences,
    run_bcc,
    run_klm,
    run_rme,
    weight_equivalence_sets,
)


_NOW_ISO = datetime(2026, 3, 17, tzinfo=timezone.utc).isoformat()


def _build_metadata(
    session_id: str,
    outcome: str,
    target_service: str,
    cve_ids: List[str],
    extraction_source: str = "rule",
) -> Dict[str, Any]:
    return {
        "source_session_id": session_id,
        "source_event_ids": [f"evt_{session_id}"],
        "source_turn_indices": [0],
        "extraction_source": extraction_source,
        "session_outcome": outcome,
        "target_raw": "10.10.10.10",
        "created_at": _NOW_ISO,
        "applicable_constraints": {
            "target_service": target_service,
            "target_version": "",
            "cve_ids": cve_ids,
        },
        "tags": [target_service.lower().replace(" ", "_") if target_service else "unknown"],
    }


def _factual_shell_like(content: Dict[str, Any]) -> bool:
    cve_ids = [str(c).strip() for c in content.get("cve_ids", []) if str(c).strip()]
    if cve_ids:
        return False

    for fact in content.get("discovered_facts", []):
        if not isinstance(fact, dict):
            continue
        key = str(fact.get("key", "")).lower()
        value = str(fact.get("value", "")).strip()
        if value and ("version" in key or "cve" in key):
            return False
    return True


def test_layer3_small_sample_resolves_four_known_issues() -> None:
    experiences: List[Dict[str, Any]] = []

    # 1) PROCEDURAL_POS: provide 3 independent successful samples.
    for i in range(3):
        experiences.append(
            {
                "exp_id": f"exp_pos_{i}",
                "knowledge_layer": "PROCEDURAL_POS",
                "content": {
                    "command_template": "python exploit.py --target {TARGET_IP}",
                    "original_command": "python exploit.py --target 10.10.10.10",
                    "tool_name": "generic_linux_command",
                    "attack_phase": "EXPLOITATION",
                    "preconditions": ["target has vulnerable endpoint"],
                    "success_indicators": ["uid=0(root)"],
                    "cve_ids": ["CVE-2021-44228"],
                    "target_service": "Apache Solr",
                },
                "metadata": _build_metadata(
                    session_id=f"sess_pos_{i}",
                    outcome="success",
                    target_service="Apache Solr",
                    cve_ids=["CVE-2021-44228"],
                ),
                "maturity": "raw",
                "confidence": 0.95,
                "lifecycle_status": "active",
            }
        )

    # 2) PROCEDURAL_NEG: heterogeneous sub-dim variants should still cluster after normalization.
    neg_sub_dims = [
        "VERSION_MISMATCH",
        "VERSION_MISMATCH_OR_PATH_INVALID",
        "VERSION_MISMATCH_OR_ASSUMPTION_ERROR",
        "VERSION_MISJUDGMENT",
    ]
    neg_sources = ["llm", "rule_fallback", "llm", "rule_fallback"]
    for i, (sub_dim, source) in enumerate(zip(neg_sub_dims, neg_sources)):
        experiences.append(
            {
                "exp_id": f"exp_neg_{i}",
                "knowledge_layer": "PROCEDURAL_NEG",
                "content": {
                    "failed_command": "python exploit.py --target 10.10.10.10",
                    "tool_name": "generic_linux_command",
                    "attack_phase": "EXPLOITATION",
                    "failure_dimension": "INT",
                    "failure_sub_dimension": sub_dim,
                    "decision_rule_source": source,
                    "decision_rule": {
                        "IF": "target responds but exploit chain fails",
                        "THEN": ["retry with CVE-2021-44228 alternate payload"],
                        "NOT": "do not repeat identical payload without version check",
                        "next_actions": [
                            {
                                "step": 1,
                                "tool": "generic_linux_command",
                                "command": "curl -i http://10.10.10.10:8983/solr",
                                "expected_signal": "server header is visible",
                            }
                        ],
                    },
                },
                "metadata": _build_metadata(
                    session_id=f"sess_neg_{i}",
                    outcome="failure",
                    target_service="Apache Solr",
                    cve_ids=["CVE-2021-44228"],
                ),
                "maturity": "raw",
                "confidence": 0.78,
                "lifecycle_status": "active",
            }
        )

    # 3) FACTUAL shells: these should be filtered by RME substance gate.
    for i in range(3):
        experiences.append(
            {
                "exp_id": f"exp_fact_shell_{i}",
                "knowledge_layer": "FACTUAL",
                "content": {
                    "service_type": "http",
                    "discovered_facts": [
                        {"key": "http_status", "value": "404"},
                        {"key": "open_port_evidence", "value": "8983"},
                    ],
                    "attack_phase": "RECON_WEAPONIZATION",
                },
                "metadata": _build_metadata(
                    session_id=f"sess_fact_shell_{i}",
                    outcome="success",
                    target_service="",
                    cve_ids=[],
                    extraction_source="rule",
                ),
                "maturity": "raw",
                "confidence": 0.72,
                "lifecycle_status": "active",
            }
        )

    # 4) FACTUAL substantive: should survive and be consolidated.
    for i in range(3):
        experiences.append(
            {
                "exp_id": f"exp_fact_real_{i}",
                "knowledge_layer": "FACTUAL",
                "content": {
                    "service_type": "http",
                    "discovered_facts": [
                        {"key": "service_version", "value": "Apache Solr/8.11.1"},
                        {"key": "cve_mentioned", "value": "CVE-2021-44228"},
                    ],
                    "attack_phase": "RECON_WEAPONIZATION",
                },
                "metadata": _build_metadata(
                    session_id=f"sess_fact_real_{i}",
                    outcome="success",
                    target_service="Apache Solr",
                    cve_ids=["CVE-2021-44228"],
                    extraction_source="rule",
                ),
                "maturity": "raw",
                "confidence": 0.84,
                "lifecycle_status": "active",
            }
        )

    clusters = cluster_experiences(experiences)
    neg_clusters = [c for c in clusters if c.knowledge_layer == "PROCEDURAL_NEG"]
    assert len(neg_clusters) == 1, "NEG 子维度应被归一后聚成同簇，避免 SEC 过碎"
    assert neg_clusters[0].meets_fusion_threshold

    wes_list = weight_equivalence_sets(clusters)
    merge_results = run_rme(wes_list)
    wes_map = {wes.cluster.cluster_id: wes for wes in wes_list}

    pos_merges = [mr for mr in merge_results if mr.knowledge_layer == "PROCEDURAL_POS"]
    assert pos_merges, "small sample should produce PROCEDURAL_POS merge results"

    neg_merges = [mr for mr in merge_results if mr.knowledge_layer == "PROCEDURAL_NEG"]
    assert len(neg_merges) == 1
    src_breakdown = neg_merges[0].fused_content.get("decision_rule_source_breakdown", {})
    assert src_breakdown.get("llm", 0) >= 1
    assert src_breakdown.get("rule_fallback", 0) >= 1

    factual_merges = [mr for mr in merge_results if mr.knowledge_layer == "FACTUAL"]
    assert factual_merges, "should keep substantive FACTUAL merges"
    assert all(not _factual_shell_like(mr.fused_content) for mr in factual_merges), (
        "FACTUAL shell entries should be filtered out before consolidation"
    )

    _, consolidated_exps = run_bcc(merge_results, wes_map)
    assert any(c.knowledge_layer == "PROCEDURAL_POS" for c in consolidated_exps)

    exp_map = {exp["exp_id"]: exp for exp in experiences}
    _, _, reflux_ready = run_klm(consolidated_exps, exp_map)
    assert any(item.get("knowledge_layer") == "PROCEDURAL_POS" for item in reflux_ready), (
        "PROCEDURAL_POS should reach phase5 reflux-ready on validated sample"
    )
