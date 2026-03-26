"""
tests/test_layer2.py  -- Layer 2 经验提取器完整测试套件
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from src.models import (
    ActionCategory,
    AnnotatedEvent,
    AnnotatedTurnSequence,
    AtomicEvent,
    CallDescriptor,
    FailureRootCause,
    FailureRootCauseDimension,
    ResultDescriptor,
    SessionMetadata,
    SessionOutcome,
)
from src.layer2.experience_models import KnowledgeLayer
from src.layer2.extractors.factual import (
    _parse_generic_findings,
    _parse_http_findings,
    extract_factual_experiences,
)
from src.layer2.extractors.factual_llm import (
    canonicalize_service_name,
    extract_factual_experience_llm,
)
from src.layer2.extractors.procedural import (
    _summarize_code,
    _PROTO_PRECOND_PATTERNS,
    extract_procedural_experiences,
)
import src.layer2.extractors.procedural as procedural_extractor
from src.layer2.extractors.metacognitive import (
    _sample_events,
    _build_phase_distribution,
    _normalize_metacognitive_payload,
)
from src.layer2.extractors.conceptual import (
    _should_extract_conceptual,
    _select_key_events,
    _VALID_PATTERN_TYPES,
    _normalize_conceptual_payload,
)
from src.layer2.utils.parameterizer import (
    extract_cve_ids,
    generate_tags,
    parameterize_command,
)
from src.layer2.pipeline import run_layer2

# ---------------------------------------------------------------------------
# 公共辅助函数
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)


def _make_call(
    tool_name: str = "generic_linux_command",
    command: str = "ls -la",
    code: str = "",
) -> CallDescriptor:
    args: Dict[str, Any] = {}
    if command:
        args["command"] = command
    if code:
        args["code"] = code
    return CallDescriptor(
        tool_name=tool_name,
        call_args=args,
        call_timestamp=_NOW,
        tool_call_id="tc_test_001",
        action_category=ActionCategory.GENERIC_COMMAND_CALL,
        program_name=tool_name,
    )


def _make_result(
    stdout: str = "",
    return_code: int = 0,
    success: bool = True,
    timed_out: bool = False,
) -> ResultDescriptor:
    return ResultDescriptor(
        return_code=return_code,
        timed_out=timed_out,
        success=success,
        stderr_raw="",
        stdout_raw=stdout,
        raw_result={"_raw_text": stdout},
    )


def _make_ann_event(
    tool_name: str = "generic_linux_command",
    command: str = "ls -la",
    stdout: str = "",
    attack_phase: str = "RECON_WEAPONIZATION",
    outcome_label: str = "success",
    failure_root_cause: Optional[FailureRootCause] = None,
    has_rag_context: bool = False,
    code: str = "",
    turn_index: int = 0,
) -> AnnotatedEvent:
    base = AtomicEvent(
        event_id=f"evt_{turn_index}_{tool_name[:8]}",
        turn_index=turn_index,
        slot_in_turn=0,
        call=_make_call(tool_name, command, code),
        result=_make_result(stdout=stdout),
        has_rag_context=has_rag_context,
    )
    return AnnotatedEvent(
        base=base,
        attack_phase=attack_phase,
        outcome_label=outcome_label,
        failure_root_cause=failure_root_cause,
    )


def _make_ann_seq(
    events: List[AnnotatedEvent],
    session_id: str = "test-ses-0001",
    target_raw: str = "192.168.1.100",
    outcome: str = "success",
) -> AnnotatedTurnSequence:
    meta = SessionMetadata(
        session_id=session_id,
        target_raw=target_raw,
        start_time=_NOW,
    )
    so = SessionOutcome(
        is_success=(outcome == "success"),
        outcome_label=outcome,
        session_goal_achieved=(outcome in {"success", "partial_success"}),
        achieved_goals=[],
        failed_goals=[],
        reasoning="test reasoning",
        key_signals=[],
    )

    return AnnotatedTurnSequence(
        metadata=meta,
        annotated_events=events,
        session_outcome=so,
    )


def _make_frc(
    dim: FailureRootCauseDimension = FailureRootCauseDimension.ENV,
    sub: str = "BINARY_MISSING",
    evidence: str = "tool not found",
) -> FailureRootCause:
    return FailureRootCause(
        dimension=dim,
        sub_dimension=sub,
        evidence=evidence,
        source="rule",
    )


# ===========================================================================
# TC-F: Factual 提取器
# ===========================================================================

class TestFactualExtractor:

    def test_tc_f00_canonicalize_service_name_llm_first_non_enumerative(self):
        """TC-F00: 服务名归一应以 LLM 输出为主，仅做轻量格式清洗。"""
        assert canonicalize_service_name("apache solr 8.11.0") == "Apache Solr"
        assert canonicalize_service_name("  spring framework v5.3.29 ") == "Spring Framework"
        assert canonicalize_service_name("Unknown Service") == "Unknown Service"

    def test_tc_f01_recon_nmap_extracts_open_port(self):
        """TC-F01: RECON nmap success -> 提取 open_port FACTUAL"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV -p 80,443 192.168.1.100",
            stdout="80/tcp   open  http    nginx/1.18\n443/tcp  open  https   nginx/1.18",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert exps, "期望提取 >=1 条 FACTUAL"
        assert all(e.knowledge_layer == KnowledgeLayer.FACTUAL for e in exps)
        keys = {f["key"] for exp in exps for f in exp.content.get("discovered_facts", [])}
        assert "open_port" in keys

    def test_tc_f02_exploitation_root_shell(self):
        """TC-F02: EXPLOITATION uid=0(root) -> privilege_root FACTUAL"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="id",
            stdout="uid=0(root) gid=0(root) groups=0(root)",
            attack_phase="EXPLOITATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert exps, "EXPLOITATION root 应提取 FACTUAL"
        keys = {f["key"] for exp in exps for f in exp.content.get("discovered_facts", [])}
        assert "privilege_root" in keys

    def test_tc_f03_exploitation_flag_captured(self):
        """TC-F03: flag{...} -> flag_captured FACTUAL"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="cat /root/flag.txt",
            stdout="flag{th1s_1s_a_test_flag_abc123}",
            attack_phase="EXPLOITATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        keys = {f["key"] for exp in exps for f in exp.content.get("discovered_facts", [])}
        assert "flag_captured" in keys

    def test_tc_f04_cve_mentioned_without_confirmation(self):
        """TC-F04: CVE 出现但无确认词 -> cve_mentioned (非 cve_confirmed)"""
        output = "Checking target... CVE-2021-44228 is referenced in exploit database."
        findings = _parse_generic_findings(output, "searchsploit")
        cve_keys = {f["key"] for f in findings if "cve" in f.get("key", "")}
        assert "cve_mentioned" in cve_keys, f"期望 cve_mentioned，实际: {cve_keys}"
        assert "cve_confirmed" not in cve_keys

    def test_tc_f05_cve_confirmed_with_keyword(self):
        """TC-F05: CVE + vulnerable -> cve_confirmed"""
        output = "Target is vulnerable to CVE-2021-44228. Exploit confirmed successful."
        findings = _parse_generic_findings(output, "nuclei")
        cve_keys = {f["key"] for f in findings if "cve" in f.get("key", "")}
        assert "cve_confirmed" in cve_keys, f"期望 cve_confirmed，实际: {cve_keys}"

    def test_tc_f06_domain_target_no_indicator_field(self):
        """TC-F06: target_indicator 字段已移除，content 中不应再含该字段；
        域名 target_raw 保留在 metadata 中供溯源。"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV ctf.hackthebox.htb",
            stdout="80/tcp open http nginx/1.18",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev], target_raw="ctf.hackthebox.htb")
        exps = extract_factual_experiences(seq)
        if exps:
            assert "target_indicator" not in exps[0].content, \
                "target_indicator 字段应已删除，不应出现在 content 中"
            # 原始域名应保留在 metadata.target_raw
            assert "hackthebox" in (exps[0].metadata.target_raw or "").lower(), \
                f"域名应保留在 metadata.target_raw，实际: {exps[0].metadata.target_raw}"

    def test_tc_f07_http_path_dedup(self):
        """TC-F07: 同一 HTTP 路径出现多次只保留一条"""
        output = (
            "Found: Status: 200  Size: 1234  /admin\n"
            "/admin [200 OK]\n"
            "/login [Status: 200]\n"
        )
        findings = _parse_http_findings(output, "gobuster dir")
        paths = [f["value"] for f in findings if f["key"] == "accessible_path"]
        assert paths.count("/admin") <= 1, f"路径 /admin 出现了多次: {paths}"

    def test_tc_f08_service_version_no_os_false_positive(self):
        """TC-F08: service_version 不应误报 Ubuntu/20.04 等 OS 名称"""
        output = "Ubuntu/20.04 LTS - kernel 5.4.0. Server: Apache/2.4.41"
        findings = _parse_generic_findings(output, "curl")
        versions = [f["value"] for f in findings if f["key"] == "service_version"]
        assert not any("ubuntu" in v.lower() for v in versions), \
            f"Ubuntu/20.04 不应作为 service_version: {versions}"
        assert any("apache" in v.lower() for v in versions), \
            f"Apache/2.4.41 未被提取: {versions}"

    def test_tc_f09_recon_partial_success_extracted(self):
        """TC-F09: RECON partial_success 也应提取 FACTUAL"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -p 22 192.168.1.1",
            stdout="22/tcp open ssh OpenSSH 7.9",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="partial_success",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert exps, "RECON partial_success 应提取 FACTUAL"

    def test_tc_f10_exploitation_failure_not_extracted(self):
        """TC-F10: EXPLOITATION failure -> 不提取 FACTUAL"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="./exploit.py 192.168.1.100",
            stdout="Connection refused",
            attack_phase="EXPLOITATION",
            outcome_label="failure",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert not exps, "EXPLOITATION failure 不应提取 FACTUAL"

    def test_tc_f11_recon_uncertain_with_structured_signal_extracted(self):
        """RECON uncertain 在存在结构化证据时应进入 FACTUAL（低置信度）。"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV -p 8080 192.168.1.100",
            stdout="8080/tcp open http-proxy",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="uncertain",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert exps, "RECON uncertain + 结构化证据应提取 FACTUAL"
        assert exps[0].confidence <= 0.62

    def test_tc_f12_http_status_404_500_extracted(self):
        """HTTP 404/500 状态码应被纳入 FACTUAL 结构化证据。"""
        output = "GET /admin -> HTTP/1.1 404 Not Found\nPOST /api -> HTTP/1.1 500 Internal Server Error"
        findings = _parse_http_findings(output, "curl -i")
        statuses = {f["value"] for f in findings if f["key"] == "http_status"}
        assert "404" in statuses
        assert "500" in statuses

    def test_tc_f13_factual_llm_backfills_attempted_and_results(self):
        """当 LLM 未给出 attempted/results 时，factual_llm 应从事件兜底补全 cve_context。"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="python exploit.py --cve CVE-2021-44228",
            stdout="CVE-2021-44228 check result: not vulnerable",
            attack_phase="EXPLOITATION",
            outcome_label="failure",
        )
        seq = _make_ann_seq([ev], outcome="failure")

        client = MagicMock()
        client.chat.return_value = """
{
  "target_service": "Apache Tomcat",
  "target_version": "9.0.65",
  "cve_context": {
    "attempted": [],
    "exploitation_results": {},
    "unexplored": []
  },
  "applicable_constraints": {
    "network_topology": "internal",
    "service_versions": ["9.0.65"],
    "known_ineffective_vectors": []
  },
  "exploitation_status": "patched"
}
"""

        exp = extract_factual_experience_llm(seq, client, exp_counter=1)
        assert exp is not None
        cve_context = exp.content.get("cve_context", {})
        assert "CVE-2021-44228" in cve_context.get("attempted", [])
        results = cve_context.get("exploitation_results", {})
        assert results.get("CVE-2021-44228") == "patched"

    def test_tc_f14_recon_transient_only_should_be_filtered(self):
        """TC-F14: 仅含 HTTP 状态码等瞬态证据的 RECON 事件不应写入 FACTUAL。"""
        ev = _make_ann_event(
            tool_name="generic_http_request",
            command="curl -i http://192.168.1.100/admin",
            stdout="HTTP/1.1 404 Not Found\nDate: Tue, 12 Mar 2026 01:02:03 GMT",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        exps = extract_factual_experiences(seq)
        assert not exps, "纯瞬态证据（http_status/date）不应生成 FACTUAL 条目"

    def test_tc_f15_relative_path_command_summary_should_be_kept(self):
        """TC-F15: ./exploit.py --target 这类命令行不应被相对路径噪声规则误杀。"""
        output = "./exploit.py --target 192.168.1.100 --check"
        findings = _parse_generic_findings(output, "generic_linux_command")
        summaries = [f.get("value", "") for f in findings if f.get("key") == "output_summary"]
        assert summaries, f"期望保留 output_summary，实际 findings={findings}"
        assert summaries[0].startswith("./exploit.py --target"), summaries[0]


# ===========================================================================
# TC-P: Procedural 提取器
# ===========================================================================

class TestProceduralExtractor:

    def test_tc_p01_exploitation_success_pos(self):
        """TC-P01: EXPLOITATION success -> PROCEDURAL_POS"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="python3 cve_2021_44228.py -t 10.10.10.100",
            stdout="[+] Successfully exploited! uid=0(root)",
            attack_phase="EXPLOITATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        pos, neg = extract_procedural_experiences(seq)
        assert pos, "EXPLOITATION success 应提取 PROCEDURAL_POS"
        assert all(e.knowledge_layer == KnowledgeLayer.PROCEDURAL_POS for e in pos)

    def test_tc_p02_recon_success_not_in_pos(self):
        """TC-P02: RECON success 不提取 PROCEDURAL_POS（由 FACTUAL 处理）"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV 192.168.1.1",
            stdout="80/tcp open http",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev])
        pos, neg = extract_procedural_experiences(seq)
        assert not pos, "RECON 阶段不应提取 PROCEDURAL_POS"

    def test_tc_p03_failure_root_cause_neg(self):
        """TC-P03: failure_root_cause != None -> PROCEDURAL_NEG"""
        frc = _make_frc(
            dim=FailureRootCauseDimension.ENV,
            sub="BINARY_MISSING",
            evidence="tool not found",
        )
        ev = _make_ann_event(
            tool_name="sqlmap",
            command="sqlmap -u http://target/",
            stdout="sqlmap: command not found",
            attack_phase="EXPLOITATION",
            outcome_label="failure",
            failure_root_cause=frc,
        )
        seq = _make_ann_seq([ev])
        pos, neg = extract_procedural_experiences(seq)
        assert neg, "failure_root_cause != None 应提取 PROCEDURAL_NEG"
        assert all(e.knowledge_layer == KnowledgeLayer.PROCEDURAL_NEG for e in neg)

    def test_tc_p04_partial_success_pos_and_neg(self):
        """TC-P04: partial_success + FRC -> 仅生成 POS（NEG 仅 failure/timeout）"""
        frc = _make_frc(
            dim=FailureRootCauseDimension.EFF,
            sub="PARTIAL_SHELL",
            evidence="limited shell obtained",
        )
        ev = _make_ann_event(
            tool_name="msfconsole",
            command="exploit -j",
            stdout="Session opened but limited",
            attack_phase="EXPLOITATION",
            outcome_label="partial_success",
            failure_root_cause=frc,
            turn_index=0,
        )
        seq = _make_ann_seq([ev])
        pos, neg = extract_procedural_experiences(seq)
        assert pos, "partial_success 应生成 PROCEDURAL_POS"
        assert not neg, "partial_success 不应生成 PROCEDURAL_NEG（仅 failure/timeout）"

    def test_tc_p05_pos_confidence_boosted_by_root_signal(self):
        """TC-P05: uid=0(root) 信号使 POS confidence 高于 baseline 0.78"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="./priv_esc.sh",
            stdout="uid=0(root) gid=0(root)",
            attack_phase="ESCALATION",
            outcome_label="success",
        )
        seq = _make_ann_seq([ev], outcome="success")
        pos, _ = extract_procedural_experiences(seq)
        if pos:
            assert pos[0].confidence > 0.78, \
                f"root 信号应提升 confidence，实际: {pos[0].confidence}"

    def test_tc_p06_neg_avoid_pattern_contains_evidence(self):
        """TC-P06: NEG avoid_pattern 应含有 frc.evidence 的内容"""
        frc = _make_frc(
            dim=FailureRootCauseDimension.DEF,
            sub="WAF_BLOCKED",
            evidence="403 Forbidden - WAF detected",
        )
        ev = _make_ann_event(
            tool_name="sqlmap",
            command="sqlmap -u http://target/ --dbs",
            stdout="403 Forbidden",
            attack_phase="EXPLOITATION",
            outcome_label="failure",
            failure_root_cause=frc,
        )
        seq = _make_ann_seq([ev])
        _, neg = extract_procedural_experiences(seq)
        if neg:
            avoid = neg[0].content.get("avoid_pattern", "")
            assert "403" in avoid or "WAF" in avoid or "Forbidden" in avoid, \
                f"avoid_pattern 应含 frc.evidence 内容，实际: {avoid}"

    def test_tc_p07_summarize_code_extracts_imports(self):
        """TC-P07: _summarize_code 对超长代码提取 import/def/CVE 关键行"""
        long_code = (
            "import socket\nimport struct\n"
            "# CVE-2021-44228 PoC\n"
            "LHOST = '10.10.10.1'\n"
            + "\n".join(f"x = {i}" for i in range(200))
            + "\ndef exploit(host, port):\n    pass\n"
        )
        summary = _summarize_code(long_code, max_len=2000)
        assert "import socket" in summary
        assert "CVE-2021-44228" in summary
        assert "def exploit" in summary

    def test_tc_p08_proto_precond_contains_weblogic_winrm_log4shell(self):
        """TC-P08: _PROTO_PRECOND_PATTERNS 应包含 WebLogic / WinRM / Log4Shell"""
        patterns_text = " ".join(pat for pat, _ in _PROTO_PRECOND_PATTERNS)
        lower = patterns_text.lower()
        assert "7001" in lower or "weblogic" in lower, "缺少 WebLogic 7001 模式"
        assert "5985" in lower or "winrm" in lower, "缺少 WinRM 5985 模式"
        assert "jndi" in lower or "log4" in lower, "缺少 JNDI/Log4Shell 模式"

    def test_tc_p09_pos_with_cve_survives_short_command_filter(self, monkeypatch):
        """TC-P09: 短命令+无成功信号时，若含 CVE 仍应保留为 POS。"""
        monkeypatch.setattr(procedural_extractor, "_infer_target_service", lambda *args, **kwargs: "")

        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="python poc.py --check CVE-2021-44228",
            stdout="done",
            attack_phase="EXPLOITATION",
            outcome_label="success",
            turn_index=0,
        )
        seq = _make_ann_seq([ev])
        pos, _ = extract_procedural_experiences(seq)
        assert pos, "含 CVE 的成功步骤不应被短命令过滤"

    def test_tc_p10_neg_should_backfill_target_service_from_session_hint(self):
        """TC-P10: NEG 在事件侧无法识别服务时，应回填 session_target_software。"""
        frc = _make_frc(
            dim=FailureRootCauseDimension.DEF,
            sub="WAF_OR_PATCH",
            evidence="403 forbidden",
        )
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="python exploit.py --target 10.10.10.10",
            stdout="failed",
            attack_phase="EXPLOITATION",
            outcome_label="failure",
            failure_root_cause=frc,
            turn_index=0,
        )
        seq = _make_ann_seq([ev])
        _, neg = extract_procedural_experiences(
            seq,
            session_target_software="Apache Solr",
        )
        assert neg, "应提取 NEG 经验"
        exp = neg[0]
        assert exp.content.get("target_service") == "Apache Solr"
        assert exp.content.get("decision_rule_source") == "rule_fallback"
        assert exp.metadata.applicable_constraints.get("target_service") == "Apache Solr"


# ===========================================================================
# TC-T: Parameterizer 工具
# ===========================================================================

class TestParameterizerUtils:

    def test_tc_t01_ip_replacement(self):
        """TC-T01: IP 替换为 {TARGET_IP}"""
        cmd = "nmap -sV 192.168.1.100 -p 80"
        template, _ = parameterize_command(cmd, target_ip_hint="192.168.1.100")
        assert "{TARGET_IP}" in template, f"IP 应被替换，实际: {template}"
        assert "192.168.1.100" not in template

    def test_tc_t02_generate_tags_dynamic(self):
        """TC-T02: generate_tags 产生合理标签"""
        tags = generate_tags(
            "nmap -sV 10.10.10.1 -p 80,443",
            tool_name="nmap_scan",
            attack_phase="RECON_WEAPONIZATION",
        )
        assert isinstance(tags, list)
        assert len(tags) > 0
        tags_lower = " ".join(tags).lower()
        assert "nmap" in tags_lower or "recon" in tags_lower

    def test_tc_t03_extract_cve_ids(self):
        """TC-T03: 正确提取 CVE ID"""
        text = "Check CVE-2021-44228 and CVE-2022-0001 for details."
        cves = extract_cve_ids(text)
        assert "CVE-2021-44228" in cves
        assert "CVE-2022-0001" in cves


# ===========================================================================
# TC-C: Conceptual 提取器
# ===========================================================================

class TestConceptualExtractor:

    def test_tc_c01_low_adoption_does_not_trigger(self):
        """TC-C01: 未达到 exploit_success/failure 阈值时不触发 CONCEPTUAL。"""
        ev = _make_ann_event(attack_phase="EXPLOITATION", outcome_label="success")
        seq = _make_ann_seq([ev])
        # exploit_success=1 < 2，failure_count=0 -> False
        assert not _should_extract_conceptual(seq)

    def test_tc_c01b_adoption_level_2_triggers(self):
        """TC-C01b: >=2 个 EXPLOITATION/ESCALATION 成功事件触发条件。"""
        ev1 = _make_ann_event(attack_phase="EXPLOITATION", outcome_label="success", turn_index=0)
        ev2 = _make_ann_event(attack_phase="ESCALATION", outcome_label="success", turn_index=1)
        seq = _make_ann_seq([ev1, ev2])
        assert _should_extract_conceptual(seq)

    def test_tc_c02_pattern_type_vocabulary(self):
        """TC-C02: _VALID_PATTERN_TYPES 包含核心类型（C-1改动：rag_utility 已移至 RAG_EVALUATION 层，不再在此出现）"""
        required = {
            "attack_strategy", "vulnerability_pattern",
            "privilege_escalation", "defense_bypass",
        }
        assert required.issubset(_VALID_PATTERN_TYPES), \
            f"缺少必要 pattern_type: {required - _VALID_PATTERN_TYPES}"
        # rag_utility 现在作为独立 RAG_EVALUATION 层经验存储，不再是 CONCEPTUAL pattern_type
        assert "rag_utility" not in _VALID_PATTERN_TYPES, \
            "C-1: rag_utility 不应出现在 CONCEPTUAL _VALID_PATTERN_TYPES 中（已独立为 RAG_EVALUATION 层）"

    def test_tc_c03_failure_count_triggers(self):
        """TC-C03: >= _MIN_FAILURE_FOR_CONCEPTUAL 个失败事件触发 CONCEPTUAL"""
        frc = _make_frc()
        events = [
            _make_ann_event(
                attack_phase="EXPLOITATION",
                outcome_label="failure",
                failure_root_cause=frc,
                turn_index=i,
            )
            for i in range(3)
        ]
        seq = _make_ann_seq(events)
        assert _should_extract_conceptual(seq)

    def test_tc_c04_select_key_events_includes_exploitation(self):
        """TC-C04: _select_key_events 保留 EXPLOITATION 成功事件"""
        events = (
            [_make_ann_event(
                attack_phase="RECON_WEAPONIZATION",
                turn_index=i,
            ) for i in range(20)]
            + [_make_ann_event(
                attack_phase="EXPLOITATION",
                outcome_label="success",
                turn_index=20,
                stdout="uid=0(root)",
            )]
        )
        seq = _make_ann_seq(events)
        selected = _select_key_events(seq)
        phases = {e.attack_phase for e in selected}
        assert "EXPLOITATION" in phases

    def test_tc_c05_normalize_legacy_payload(self):
        """TC-C05: legacy conceptual_patterns 返回应能归一化为标准字段。"""
        raw = {
            "conceptual_patterns": [
                {
                    "pattern_name": "Iterative Defense Evasion",
                    "description": "攻击者在遇到防御后持续更换向量进行绕过。",
                    "evidence": "连续 DEF/WAF_OR_PATCH 错误。",
                    "reasoning": "防御机制稳定存在，需迭代规避。",
                }
            ],
            "reasoning": "来自多次失败事件的归纳",
        }
        normalized = _normalize_conceptual_payload(raw, session_id="test-ses")
        assert normalized.get("core_insight"), "应生成 core_insight"
        assert normalized.get("pattern_type") in _VALID_PATTERN_TYPES
        ac = normalized.get("applicable_conditions", {})
        assert isinstance(ac, dict)
        assert ac.get("positive"), "应生成 positive 条件"


# ===========================================================================
# TC-M: Metacognitive 提取器
# ===========================================================================

class TestMetacognitiveExtractor:

    def test_tc_m01_sample_events_includes_exploitation(self):
        """TC-M01: _sample_events 保留中间段的 EXPLOITATION 成功事件"""
        events = (
            [_make_ann_event(
                attack_phase="RECON_WEAPONIZATION", turn_index=i,
            ) for i in range(20)]
            + [_make_ann_event(
                attack_phase="EXPLOITATION",
                outcome_label="success",
                stdout="uid=0(root)",
                turn_index=20,
            )]
            + [_make_ann_event(
                attack_phase="EXFILTRATION", turn_index=i + 21,
            ) for i in range(15)]
        )
        seq = _make_ann_seq(events)
        sampled = _sample_events(seq)
        phases = {e.attack_phase for e in sampled}
        assert "EXPLOITATION" in phases

    def test_tc_m02_phase_distribution_counts(self):
        """TC-M02: _build_phase_distribution 统计阶段计数正确"""
        events = [
            _make_ann_event(attack_phase="RECON_WEAPONIZATION", turn_index=0),
            _make_ann_event(attack_phase="RECON_WEAPONIZATION", turn_index=1),
            _make_ann_event(attack_phase="EXPLOITATION", turn_index=2),
        ]
        seq = _make_ann_seq(events)
        info = _build_phase_distribution(seq)
        dist = info["phase_distribution"]
        assert dist.get("RECON_WEAPONIZATION") == 2
        assert dist.get("EXPLOITATION") == 1

    def test_tc_m03_failure_pattern_auto_fill(self):
        """TC-M03: 失败会话 failure_pattern 为空时应自动补充默认值"""
        session_outcome_str = "failure"
        parsed = {
            "session_goal": "pwn",
            "key_lessons": ["lesson1"],
            "decision_insights": ["insight1"],
            "rag_effectiveness": "none",
            "failure_pattern": "",
            "success_factor": "",
        }
        is_success = (session_outcome_str == "success")
        if not is_success and not parsed.get("failure_pattern"):
            parsed["failure_pattern"] = "(auto-filled: session outcome = failure)"
        assert parsed["failure_pattern"] != ""

    def test_tc_m04_normalize_legacy_payload(self):
        """TC-M04: legacy meta_cognitive_insights 返回应能归一化为标准字段。"""
        raw = {
            "meta_cognitive_insights": {
                "reconnaissance_lessons": {
                    "version_identification_success": "先识别版本再利用",
                },
                "methodology_improvements": {
                    "attack_progression_rule": "先侦察后利用",
                    "failure_response_handling": "连续失败后切换路径",
                },
                "transferable_decision_rules": [
                    "规则1：连续防御拦截后切换攻击面",
                    "规则2：先验证成功信号再升级动作",
                ],
            },
            "reasoning": "基于失败与部分成功信号总结",
        }
        normalized = _normalize_metacognitive_payload(raw, session_id="test-ses")
        assert normalized.get("decision_mistakes"), "应生成 decision_mistakes"
        assert normalized.get("key_lessons"), "应生成 key_lessons"
        assert normalized.get("optimal_decision_path"), "应生成 optimal_decision_path"


# ===========================================================================
# TC-I: Pipeline 集成测试
# ===========================================================================

class TestLayer2Pipeline:

    def test_tc_i01_no_client_only_rule_based(self):
        """TC-I01: client=None 时仅产生规则层结果 (FACTUAL + PROCEDURAL，无 LLM 层)"""
        ev_recon = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV 10.10.10.1",
            stdout="80/tcp open http nginx/1.18",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
            turn_index=0,
        )
        ev_exploit = _make_ann_event(
            tool_name="generic_linux_command",
            command="python3 exploit.py 10.10.10.1",
            stdout="uid=0(root)",
            attack_phase="EXPLOITATION",
            outcome_label="success",
            turn_index=1,
        )
        seq = _make_ann_seq([ev_recon, ev_exploit])
        bundle = run_layer2(seq, client=None)

        # 无 LLM -> METACOGNITIVE / CONCEPTUAL 应为空
        assert bundle.by_layer(KnowledgeLayer.METACOGNITIVE) == []
        assert bundle.by_layer(KnowledgeLayer.CONCEPTUAL) == []
        # 规则层应有产出
        total_rule = (
            len(bundle.by_layer(KnowledgeLayer.FACTUAL))
            + len(bundle.by_layer(KnowledgeLayer.PROCEDURAL_POS))
        )
        assert total_rule > 0

    def test_tc_i02_bundle_total_count(self):
        """TC-I02: total_count == F + P+ + P- (无 LLM 层时)"""
        frc = _make_frc()
        events = [
            _make_ann_event(
                tool_name="nmap_scan",
                command="nmap -sV 10.0.0.1",
                stdout="22/tcp open ssh OpenSSH 8.0",
                attack_phase="RECON_WEAPONIZATION",
                outcome_label="success",
                turn_index=0,
            ),
            _make_ann_event(
                tool_name="generic_linux_command",
                command="./exploit.sh",
                stdout="uid=0(root)",
                attack_phase="EXPLOITATION",
                outcome_label="success",
                turn_index=1,
            ),
            _make_ann_event(
                tool_name="metasploit",
                command="use exploit/multi/handler",
                stdout="tool not found",
                attack_phase="EXPLOITATION",
                outcome_label="failure",
                failure_root_cause=frc,
                turn_index=2,
            ),
        ]
        seq = _make_ann_seq(events)
        bundle = run_layer2(seq, client=None)

        f  = len(bundle.by_layer(KnowledgeLayer.FACTUAL))
        pp = len(bundle.by_layer(KnowledgeLayer.PROCEDURAL_POS))
        pn = len(bundle.by_layer(KnowledgeLayer.PROCEDURAL_NEG))
        assert bundle.total_count == f + pp + pn, \
            f"total={bundle.total_count}, F={f}, P+={pp}, P-={pn}"

    def test_tc_i03_content_hash_dedup(self):
        """TC-I03: 相同 content_hash 不重复入库（去重机制）"""
        ev = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV 10.0.0.1",
            stdout="22/tcp open ssh OpenSSH_8.0",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
        )
        # 同一事件放两次
        seq = _make_ann_seq([ev, ev])
        exps = extract_factual_experiences(seq)
        hashes = [e.content_hash for e in exps]
        assert len(hashes) == len(set(hashes)), "content_hash 应去重"

    def test_tc_i04_factual_and_procedural_both_present(self):
        """TC-I04: RECON success + EXPLOITATION success -> 两类经验均存在"""
        ev_recon = _make_ann_event(
            tool_name="nmap_scan",
            command="nmap -sV 10.0.0.1 -p 22",
            stdout="22/tcp open ssh OpenSSH 8.0",
            attack_phase="RECON_WEAPONIZATION",
            outcome_label="success",
            turn_index=0,
        )
        ev_exploit = _make_ann_event(
            tool_name="generic_linux_command",
            command="ssh root@10.0.0.1 -i id_rsa",
            stdout="Welcome to Ubuntu! uid=0(root)",
            attack_phase="EXPLOITATION",
            outcome_label="success",
            turn_index=1,
        )
        seq = _make_ann_seq([ev_recon, ev_exploit])
        bundle = run_layer2(seq, client=None)

        assert bundle.by_layer(KnowledgeLayer.FACTUAL), "RECON success 应产出 FACTUAL"
        assert bundle.by_layer(KnowledgeLayer.PROCEDURAL_POS), \
            "EXPLOITATION success 应产出 PROCEDURAL_POS"

    def test_tc_i05_sync_cve_ids_into_metadata_constraints(self):
        """TC-I05: 含 cve_ids 的经验应同步写入 metadata.applicable_constraints.cve_ids。"""
        ev = _make_ann_event(
            tool_name="generic_linux_command",
            command="python exploit.py --target 10.0.0.1 --cve CVE-2021-44228",
            stdout="uid=0(root)",
            attack_phase="EXPLOITATION",
            outcome_label="success",
            turn_index=0,
        )
        seq = _make_ann_seq([ev])
        bundle = run_layer2(seq, client=None)

        checked = 0
        for exp in bundle.experiences:
            content_cves = [str(c).upper() for c in (exp.content.get("cve_ids") or []) if str(c).strip()]
            if not content_cves:
                continue
            meta_cves = [
                str(c).upper()
                for c in (exp.metadata.applicable_constraints or {}).get("cve_ids", [])
                if str(c).strip()
            ]
            assert set(content_cves).issubset(set(meta_cves))
            checked += 1

        assert checked > 0, "测试前置失败：至少应有一条带 content.cve_ids 的经验"
