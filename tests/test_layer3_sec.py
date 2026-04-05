from src.layer2.extractors.factual_llm import canonicalize_service_name
from src.layer3.sec import cluster_experiences, normalize_cve_ids, normalize_service_name


def test_sec_cluster_id_should_not_collide_on_truncated_service_slug() -> None:
    """不同服务名即使前缀相同，也应得到不同 cluster_id。"""
    exp_a = {
        "exp_id": "exp_a",
        "knowledge_layer": "FACTUAL",
        "content": {
            "discovered_facts": [{"key": "service_version", "value": "Acme/1.0"}],
            "cve_ids": ["CVE-2021-44228"],
        },
        "metadata": {
            "extraction_source": "rule",
            "applicable_constraints": {
                "target_service": "Acme Vulnerable Platform Enterprise Alpha Build",
                "cve_ids": ["CVE-2021-44228"],
            },
        },
        "lifecycle_status": "active",
    }
    exp_b = {
        "exp_id": "exp_b",
        "knowledge_layer": "FACTUAL",
        "content": {
            "discovered_facts": [{"key": "service_version", "value": "Acme/2.0"}],
            "cve_ids": ["CVE-2021-44228"],
        },
        "metadata": {
            "extraction_source": "rule",
            "applicable_constraints": {
                "target_service": "Acme Vulnerable Platform Enterprise Beta Build",
                "cve_ids": ["CVE-2021-44228"],
            },
        },
        "lifecycle_status": "active",
    }

    clusters = cluster_experiences([exp_a, exp_b])
    ids = [c.cluster_id for c in clusters]

    assert len(ids) == 2
    assert len(set(ids)) == 2, f"cluster_id 冲突: {ids}"


def test_sec_extract_cve_ids_from_textual_content_fallback() -> None:
    """当 cve_ids 字段缺失时，应能从内容文本（如 decision_rule.THEN）兜底提取 CVE。"""
    exp = {
        "exp_id": "exp_neg_1",
        "knowledge_layer": "PROCEDURAL_NEG",
        "content": {
            "failure_sub_dimension": "PAYLOAD_MISMATCH",
            "attack_phase": "EXPLOITATION",
            "decision_rule": {
                "IF": "目标返回 500 且认证通过",
                "THEN": ["尝试切换到 CVE-2020-14882 的 gadget 链进行验证"],
                "NOT": "不要继续盲打旧 payload",
            },
        },
        "metadata": {
            "applicable_constraints": {
                "target_service": "Oracle WebLogic Server",
            },
        },
        "lifecycle_status": "active",
    }

    clusters = cluster_experiences([exp])
    assert len(clusters) == 1
    assert "CVE-2020-14882" in clusters[0].cve_ids


def test_sec_normalize_service_name_with_alias_and_version_suffix() -> None:
    assert normalize_service_name("Apache Solr 8.x") == "Apache Solr"
    assert normalize_service_name("solr") == "Apache Solr"
    assert normalize_service_name("Atlassian Confluence 7.13.0") == "Atlassian Confluence"
    assert normalize_service_name("Spring Framework v5.3.29") == "Spring Framework"


def test_sec_normalize_cve_ids_supports_regex_and_nonstandard_token() -> None:
    normalized = normalize_cve_ids([
        "CVE_2021_44228",
        "cve-2021-44228",
        "target vulnerable: cve 2021 44228",
    ])
    assert normalized == ["CVE-2021-44228"]


def test_service_name_normalization_is_consistent_between_layer2_and_sec() -> None:
    raw = "apache solr 8.11.0"
    assert canonicalize_service_name(raw) == normalize_service_name(raw)
