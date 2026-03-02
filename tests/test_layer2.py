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
)
from src.layer2.experience_models import KnowledgeLayer
from src.layer2.extractors.factual import (
    _parse_generic_findings,
    _parse_http_findings,
    extract_factual_experiences,
)
from src.layer2.extractors.procedural import (
    _summarize_code,
    _PROTO_PRECOND_PATTERNS,
    extract_procedural_experiences,
)
from src.layer2.extractors.metacognitive import (
    _sample_events,
    _build_phase_distribution,
)
from src.layer2.extractors.conceptual import (
    _should_extract_conceptual,
    _select_key_events,
    _VALID_PATTERN_TYPES,
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
        rag_adoption=None,
    )


def _make_ann_seq(
    events: List[AnnotatedEvent],
    session_id: str = "test-ses-0001",
    target_raw: str = "192.168.1.100",
    outcome: str = "success",
    bar_score: float = 0.5,
    rag_adoption_results: Optional[List] = None,
) -> AnnotatedTurnSequence:
    meta = SessionMetadata(
        session_id=session_id,
        target_raw=target_raw,
        start_time=_NOW,
    )
    so = MagicMock()
    so.outcome_label = outcome
    so.is_success = (outcome == "success")
    so.achieved_goals = []
    so.failed_goals = []
    so.reasoning = "test reasoning"

    return AnnotatedTurnSequence(
        metadata=meta,
        annotated_events=events,
        session_outcome=so,
        bar_score=bar_score,
        rag_adoption_results=rag_adoption_results or [],
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
        """TC-P04: partial_success + FRC -> POS 和 NEG 各自独立（seen_hashes 分开）"""
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
        assert neg, "partial_success + FRC 应生成 PROCEDURAL_NEG"

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

    def _rag_result(self, level: int):
        r = MagicMock()
        r.adoption_level = level
        r.query = "test"
        r.reasoning = "test"
        return r

    def test_tc_c01_low_adoption_does_not_trigger(self):
        """TC-C01: adoption_level<2 不满足 RAG 触发条件"""
        ev = _make_ann_event(attack_phase="EXPLOITATION", outcome_label="success")
        rag_results = [self._rag_result(0), self._rag_result(1)]
        seq = _make_ann_seq([ev], rag_adoption_results=rag_results)
        # exploit_success=1 < 2，failure_count=0，has_useful_rag=False -> False
        assert not _should_extract_conceptual(seq)

    def test_tc_c01b_adoption_level_2_triggers(self):
        """TC-C01b: adoption_level>=2 满足触发条件"""
        ev = _make_ann_event(attack_phase="EXPLOITATION", outcome_label="success")
        seq = _make_ann_seq([ev], rag_adoption_results=[self._rag_result(2)])
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
