from src.layer4.reflux import format_chunk_for_ragflow


def test_format_chunk_for_ragflow_includes_maturity_header() -> None:
    exp = {
        "exp_id": "exp_consolidated_abc",
        "knowledge_layer": "PROCEDURAL_NEG",
        "maturity": "consolidated",
        "p_fused": 0.876,
        "n_independent_sessions": 4,
        "content": {
            "decision_rule": {
                "IF": "service responds with 500",
                "THEN": ["try authenticated endpoint", "switch gadget chain"],
                "NOT": ["repeat blind payload"],
            }
        },
        "metadata": {"applicable_constraints": {"target_service": "Oracle WebLogic Server"}},
    }

    text = format_chunk_for_ragflow(exp)
    lines = text.splitlines()

    assert lines[0] == "[★★★ consolidated | 4 sessions | p=0.88]"
    assert "[XPEC] PROCEDURAL_NEG | exp_consolidated_abc" in text
    assert "IF service responds with 500" in text
    assert "THEN try authenticated endpoint; switch gadget chain" in text
    assert "NOT repeat blind payload" in text


def test_format_chunk_for_ragflow_filters_transient_factual_findings() -> None:
    exp = {
        "exp_id": "exp_fact_1",
        "knowledge_layer": "FACTUAL",
        "maturity": "validated",
        "p_fused": 0.71,
        "n_independent_sessions": 2,
        "content": {
            "discovered_facts": [
                {"key": "open_port", "value": "7001/tcp"},
                {
                    "key": "open_port",
                    "value": "8983/tcp",
                    "service": "unknown",
                    "version": "Solr 8.11",
                },
                {"key": "http_status", "value": "404"},
                {"key": "output_summary", "value": "HTTP/1.1 404 Not Found"},
                {"key": "service_version", "value": "weblogic/10.3.6"},
                {"key": "cve_confirmed", "value": "CVE-2017-10271"},
            ]
        },
        "metadata": {
            "applicable_constraints": {
                "target_service": "Oracle WebLogic Server",
                "cve_ids": ["CVE-2017-10271"],
            }
        },
    }

    text = format_chunk_for_ragflow(exp)

    assert "service_version: weblogic/10.3.6" in text
    assert "cve_confirmed: CVE-2017-10271" in text
    assert "open_port: 7001/tcp" not in text
    assert "open_port: 8983/tcp | service=unknown | version=Solr 8.11" in text
    assert "http_status: 404" not in text
    assert "output_summary:" not in text


def test_format_chunk_for_ragflow_factual_llm_fallback_fields() -> None:
    exp = {
        "exp_id": "exp_fact_llm_1",
        "knowledge_layer": "FACTUAL",
        "maturity": "consolidated",
        "p_fused": 0.93,
        "n_independent_sessions": 3,
        "content": {
            "target_service": "Oracle WebLogic Server",
            "target_version": "10.3.6.0",
            "exploitation_status": "partial",
            "cve_exploitation_map": {
                "CVE-2017-10271": {"consensus_status": "partial"}
            },
        },
        "metadata": {"applicable_constraints": {"cve_ids": ["CVE-2017-10271"]}},
    }

    text = format_chunk_for_ragflow(exp)

    assert "target_service: Oracle WebLogic Server" in text
    assert "target_version: 10.3.6.0" in text
    assert "exploitation_status: partial" in text
    assert "CVE-2017-10271: partial" in text


def test_format_chunk_for_ragflow_factual_llm_cve_context_fallback() -> None:
    exp = {
        "exp_id": "exp_fact_llm_2",
        "knowledge_layer": "FACTUAL",
        "maturity": "validated",
        "p_fused": 0.81,
        "n_independent_sessions": 2,
        "content": {
            "target_service": "Apache Solr",
            "target_version": "8.11.0",
            "cve_context": {
                "attempted": ["CVE-2019-0193", "CVE-2017-12629"],
                "exploitation_results": {
                    "CVE-2019-0193": "exploited",
                    "CVE-2017-12629": "attempted",
                },
            },
        },
        "metadata": {"applicable_constraints": {"target_service": "Apache Solr"}},
    }

    text = format_chunk_for_ragflow(exp)

    assert "CVE-2019-0193: exploited" in text
    assert "CVE-2017-12629: attempted" in text


def test_format_chunk_for_ragflow_conceptual_uses_structured_fields() -> None:
    exp = {
        "exp_id": "exp_conceptual_1",
        "knowledge_layer": "CONCEPTUAL",
        "maturity": "validated",
        "p_fused": 0.78,
        "n_independent_sessions": 2,
        "content": {
            "pattern_type": "vulnerability_pattern",
            "core_insight": "Apache Solr 在特定版本链上存在可复现的 RCE 条件组合。",
            "applicable_conditions": {
                "positive": ["目标版本 <= 8.11", "暴露管理接口"],
                "negative": ["开启强认证并限制来源"],
                "retrieval_triggers": ["Apache Solr", "CVE-2019-0193"],
            },
            "supporting_evidence": ["sessionA exploit success", "sessionB partial success"],
        },
        "metadata": {"applicable_constraints": {"target_service": "Apache Solr"}},
    }

    text = format_chunk_for_ragflow(exp)

    assert "Insight: Apache Solr 在特定版本链上存在可复现的 RCE 条件组合。" in text
    assert "Pattern: vulnerability_pattern" in text
    assert "Applies when: 目标版本 <= 8.11; 暴露管理接口" in text
    assert "Retrieval triggers: Apache Solr; CVE-2019-0193" in text


def test_format_chunk_for_ragflow_metacognitive_uses_structured_fields() -> None:
    exp = {
        "exp_id": "exp_meta_1",
        "knowledge_layer": "METACOGNITIVE",
        "maturity": "consolidated",
        "p_fused": 0.84,
        "n_independent_sessions": 3,
        "content": {
            "session_goal": "验证目标是否可被历史 payload 直接利用",
            "session_outcome": "partial_success",
            "key_lessons": ["先验证版本约束再打 payload"],
            "decision_mistakes": [
                {
                    "mistake": "未先完成版本确认",
                    "rule": "版本与补丁状态不明时，先做被动指纹确认",
                }
            ],
            "optimal_decision_path": ["fingerprint", "constraint check", "exploit"],
        },
        "metadata": {},
    }

    text = format_chunk_for_ragflow(exp)

    assert "Session goal: 验证目标是否可被历史 payload 直接利用" in text
    assert "Outcome: partial_success" in text
    assert "Key lessons: 先验证版本约束再打 payload" in text
    assert "Decision mistakes: 未先完成版本确认 => 版本与补丁状态不明时，先做被动指纹确认" in text
    assert "Optimal path: fingerprint; constraint check; exploit" in text
