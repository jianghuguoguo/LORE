"""
Procedural 经验提取器（Positive + Negative）
=============================================
从 Layer 1 标注事件中提取：
  PROCEDURAL_POS : 成功的攻击命令/代码，参数化为可复用模板
  PROCEDURAL_NEG : 失败的攻击命令/代码，记录根因和修正建议

设计决策：
- 所有 attack_phase（包括 EXPLOITATION/ESCALATION/LATERAL_MOVEMENT/EXFILTRATION）
  中的成功事件均提取 PROCEDURAL_POS
- 有 failure_root_cause 的任何事件均提取 PROCEDURAL_NEG
  （ENV/INV/DEF/INT/EFF 全部覆盖）
- CODE_WRITE 成功：提取代码模板（截断至 2000 chars）
- GENERIC_COMMAND_CALL 成功：提取命令模板

成功判定（PROCEDURAL_POS 筛选条件）：
  outcome_label in {success, partial_success}
  AND attack_phase NOT IN {RECON_WEAPONIZATION, ENV_PREPARATION}  (那些由 factual 处理)
  AND 事件有实质性输出（_raw_text 或 stdout_raw 非空）

失败判定（PROCEDURAL_NEG 筛选条件）：
  failure_root_cause is not None
  AND outcome_label in {failure, timeout, partial_success}
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ...models import (
    ActionCategory,
    AnnotatedEvent,
    AnnotatedTurnSequence,
    FailureRootCauseDimension,
)
from ..experience_models import (
    Experience,
    ExperienceMaturity,
    ExperienceMetadata,
    ExperienceSource,
    KnowledgeLayer,
)
from ..utils.parameterizer import (
    extract_cve_ids,
    extract_ip_addresses,
    extract_target_ports,
    generate_tags,
    parameterize_command,
)

# ─────────────────────────────────────────────────────────────────────────────
# 常量
# ─────────────────────────────────────────────────────────────────────────────

# PROCEDURAL_POS：关注的攻击阶段（已排除侦察和环境准备：那些由 factual 处理）
_POS_PHASES = {
    "EXPLOITATION",
    "ESCALATION",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
    "COMMAND_CONTROL",
}

_SUCCESS_OUTCOMES = {"success", "partial_success"}
_FAILURE_OUTCOMES = {"failure", "timeout", "partial_success"}

# 成功信号关键词（用于 success_indicators 提取）
_SUCCESS_SIGNALS = [
    r"uid=0\(root\)",
    r"root@[a-zA-Z0-9_\-]+",
    r"flag\{[^}]+\}",
    r"(?:^|\n)root\s*$",           # whoami 输出独占一行
    r"(?:^|\n)\$\s+\w",            # $ shell prompt 行首
    r"\bshell\b.*\broot\b",
    r"command execution successful",
    r"exploit\s+successful",
    r"access granted",
    r"authentication successful",
    r"login successful",
    r"(?:^|\n)#\s+(?:id|whoami|cat |ls |pwd|uname)\b",  # root shell 执行命令
    # 文件内容泵露：/etc/passwd 和 /etc/shadow 的 root 行
    r"root:x:0:0:",                # /etc/passwd root 行
    r"root:[*$!][^:]*:\d+:\d+:",   # /etc/shadow root 行
    # P2: 文件读取 / API 成功信号（Druid / Spring Actuator / 通用 JSON 成功响应）
    r"[a-zA-Z_][a-zA-Z0-9_\-]*:[^:]+:[0-9]+:[0-9]+:[^:]*:[/~]",  # /etc/passwd 任意用户行
    r"(?:daemon|nobody|www-data|sync|bin|sys|man|lp|mail|news)@[a-zA-Z0-9_\-]+",  # 非特权用户主机名
    r'"(?:status|code)"\s*:\s*(?:200|0|\"ok\"|\"success\"|\"SUCCESS\")',  # JSON 成功状态码
    r"(?:200 OK|HTTP/[12](?:\.\d)?\s+200)",      # HTTP 200 在输出中
    r"(?:Total disk|disk usage).*(?:MB|GB|KB)",   # 磁盘信息泄露
]
_SUCCESS_SIGNAL_RES = [re.compile(p, re.IGNORECASE) for p in _SUCCESS_SIGNALS]

# ─────────────────────────────────────────────────────────────────────────────
# 端口 → 通用服务名（IANA Well-Known 兜底映射，不枚举应用层产品名）
# ─────────────────────────────────────────────────────────────────────────────
_PORT_TO_SERVICE: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB",
    636: "LDAPS", 1433: "Microsoft SQL Server", 1521: "Oracle Database",
    2181: "ZooKeeper", 2379: "etcd", 3306: "MySQL", 3389: "RDP",
    4369: "Erlang Port Mapper", 5432: "PostgreSQL", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 7001: "HTTP (port 7001)",
    8009: "AJP", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
    8888: "HTTP (alt)", 9000: "PHP-FPM", 9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)", 11211: "Memcached",
    27017: "MongoDB", 50070: "Hadoop HDFS",
}

# 协议关键词 → 通用前置条件描述（不涉及具体产品名）
_PROTO_PRECOND_PATTERNS: List[tuple] = [
    (r'https?://|curl\b|wget\b|http_request|nikto|gobuster|dirsearch|ferox|wfuzz|ffuf',
     "目标 HTTP/HTTPS 服务可访问"),
    (r'\bssh\b|sshpass|paramiko|evil-winrm|Port 22\b',
     "SSH 服务端口可达（凭据或密钥已知）"),
    (r'\bftp\b|ftplib|vsftpd|Port 21\b',
     "FTP 服务可访问"),
    (r'\bsmb\b|samba|smbclient|enum4linux|rpcclient|crackmapexec|\b445\b',
     "SMB/445 端口可访问"),
    (r'redis-cli|\bredis\b|\b6379\b',
     "Redis 服务可访问（无认证或密码已知）"),
    (r'\bmongo\b|pymongo|\b27017\b',
     "MongoDB 服务可访问"),
    (r'\bmysql\b|pymysql|mariadb|\b3306\b',
     "MySQL/MariaDB 数据库可访问"),
    (r'psql|postgresql|asyncpg|\b5432\b',
     "PostgreSQL 数据库可访问"),
    (r'sqlmap|union select|\bsqli\b|sql injection',
     "目标存在 SQL 注入漏洞点"),
    (r'msfconsole|msfvenom|use exploit',
     "Metasploit Framework 已配置可用"),
    (r'execute_code|python3?\s.*\.py\b',
     "Python 脚本执行环境可用"),
    (r'payload|reverse.?shell|bind.?shell|meterpreter',
     "目标存在代码执行或命令注入入口"),
    (r'\bldap\b|ldapsearch|\b389\b',
     "LDAP 服务可访问"),
    (r'snmpwalk|snmpget|\b161\b',
     "SNMP 服务可访问（community string 已知）"),
    # 新增：WebLogic T3/IIOP
    (r'7001|t3://|iiop://|weblogic',
     "WebLogic T3/IIOP 服务可访问 (port 7001)"),
    # 新增：JNDI/Log4Shell
    (r'jndi:|log4shell|\b1389\b|log4j',
     "JNDI 注入入口可达（Log4Shell/JNDIExploit）"),
    # 新增：WinRM
    (r'\b5985\b|\b5986\b|winrm|evil-winrm|Enter-PSSession',
     "WinRM 服务可访问 (port 5985/5986)"),
    # 新增：Java 管理接口
    (r'druid|actuator|/api/index\.json|spring.boot',
     "Java 应用管理接口可访问（Druid/Actuator）"),
    # 新增：Jenkins
    (r'8080.*jenkins|jenkins.*8080|/jenkins(?:/|$)|jenkins.script',
     "Jenkins CI 服务可访问"),
    # 新增：Gitea/GitLab
    (r'gitea|gitlab|\.git(?:/api|/info)|/api/v4/',
     "Git 服务平台 API 可访问（Gitea/GitLab）"),
]
_PROTO_PRECOND_RES = [(re.compile(pat, re.IGNORECASE), desc)
                      for pat, desc in _PROTO_PRECOND_PATTERNS]


def _summarize_code(code: str, max_len: int = 2000) -> str:
    """对过长代码进行结构化摘要（提取 import/def/CVE 注释），避免硬截断破坏逻辑。"""
    if len(code) <= max_len:
        return code
    lines = code.splitlines()
    important: List[str] = []
    # 保留：import 行、def/class 定义行、CVE 注释行、入口点行 (main/if __name__)
    for line in lines:
        stripped = line.strip()
        if (
            stripped.startswith(("import ", "from ", "def ", "class ", "#", "if __name__"))
            or re.search(r'CVE-\d{4}-\d+', stripped, re.IGNORECASE)
            or re.search(r'\b(host|target|port|payload|lhost|lport)\s*=', stripped, re.IGNORECASE)
        ):
            important.append(line)
    summary = "\n".join(important)
    if len(summary) > max_len:
        summary = summary[:max_len]
    elif len(summary) < 100 and lines:
        # 摘要太短时尶量保留前 N 行
        summary = "\n".join(lines[:60])[:max_len]
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# P0: 自然语言字段清洁工具（IP 净化 + 软截断）
# ─────────────────────────────────────────────────────────────────────────────

_IP_SANITIZE_RE = re.compile(
    r'\b(?:127\.0\.0\.1'
    r'|(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+'
    r')\b'
)


def _sanitize_ip_text(text: str) -> str:
    """P0: 将自然语言字段中所有真实 IP 地址替换为 {TARGET}，防止跨会话"IP 毒化"。"""
    if not text:
        return text
    return _IP_SANITIZE_RE.sub('{TARGET}', text)


def _soft_truncate(text: str, max_chars: int) -> str:
    """P1: 在不超过 max_chars 的前提下，优先在句末（。！？）截断；如未找到则硬截断。"""
    if not text or len(text) <= max_chars:
        return text
    snippet = text[:max_chars]
    for punct in ('。', '！', '？', '.', '!', '?'):
        last = snippet.rfind(punct)
        if last > max_chars // 2:
            return snippet[:last + 1]
    return snippet


def _port_to_service_hint(text: str) -> Optional[str]:
    """从文本中提取端口号并返回服务名提示（优先 nmap 输出，其次 IANA 映射）。"""
    # 先从 nmap 输出中解析真实服务名
    m = re.search(r'(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', text, re.IGNORECASE)
    if m:
        svc = m.group(2).strip()
        ver_col = (m.group(3) or "").strip()[:60]
        return f"{svc} ({ver_col})" if ver_col else svc
    # 再尝试从 URL / -p 参数中提取端口号
    for m in re.finditer(r'(?:https?://[^/:]+:|(?:-p\s+|--port[=\s]+))(\d{2,5})\b', text, re.IGNORECASE):
        port = int(m.group(1))
        if port in _PORT_TO_SERVICE:
            return _PORT_TO_SERVICE[port]
    return None


def _get_raw_output(event: AnnotatedEvent) -> str:
    """获取事件原始输出（最多 3000 chars）。"""
    if event.base.result is None:
        return ""
    r = event.base.result
    stdout = r.stdout_raw or ""
    raw_text = (r.raw_result or {}).get("_raw_text", "") or ""
    combined = stdout or raw_text
    return combined[:3000]


def _get_command_text(event: AnnotatedEvent) -> str:
    """获取完整命令/代码文本。"""
    args = event.base.call.call_args or {}
    cmd = args.get("command", "") or args.get("code", "")
    return cmd or ""


def _extract_success_indicators(output: str) -> List[str]:
    """从输出文本中提取成功信号字符串（用于 PROCEDURAL_POS 的 success_indicators）。

    支持两种格式：
    1. 裸输出文本（curl/nmap/bash 等工具的直接输出）
    2. JSON 封装输出（如 Druid/Spring等的 API 返回中的 \"raw\" 字段）
    """
    indicators = []
    # 先尝试从 JSON \"raw\" 字段提取（Druid/Spring Actuator 模式）
    raw_content = output
    import json as _json
    try:
        # 搜索嵌套 JSON 中的 raw 字段
        for raw_match in re.finditer(r'"raw"\s*:\s*"((?:[^"\\]|\\.)*)"', output, re.DOTALL):
            raw_content = raw_match.group(1).replace('\\n', '\n').replace('\\t', '\t')
            break  # 只取第一个
    except Exception:
        pass
    # 同时在原始输出和 json raw 内容中搜索
    for text in {output, raw_content}:
        for rex in _SUCCESS_SIGNAL_RES:
            m = rex.search(text)
            if m:
                indicators.append(m.group(0)[:80])
    return list(dict.fromkeys(indicators))


# P-2：元操作过滤器——屏蔽 session管理/元操作命令进入 POS 知识库
_META_OP_PATTERNS = [
    re.compile(r'session\s+output', re.IGNORECASE),
    re.compile(r'session\s+terminate', re.IGNORECASE),
    re.compile(r'async\s+session', re.IGNORECASE),
    re.compile(r'check\s+session', re.IGNORECASE),
    re.compile(r'started\s+async', re.IGNORECASE),
    re.compile(r'^sessions\s+(?:-l|-i|-v|-k|-u|\d+)', re.IGNORECASE),
]


def _is_pos_worthy(
    command: str,
    success_indicators: List[str],
    target_service: str = "",
    event_outcome: str = "",
) -> bool:
    """P-2：判断一个成功事件是否值得作为 POS 经验存入知识库。

    过滤条件（返回 False = 不值得存）：
    1. 命令属于会话元操作（session output/terminate/async session 管理等）
    2. 没有成功信号 且 命令看起来是 session 管理短命令（sessions -l/-k/-i 等）
    3. P1: target_service 为空 且 命令较短（<=100字符）且 无成功信号
       → 无软件标识的纯端口连接测试/socket 测试，无检索价值
       例外：event_outcome == 'partial_success' 说明存在部分攻击成效，不过滤

    Args:
        command           : 原始命令/代码文本
        success_indicators: 已提取的成功信号列表
        target_service    : POS 提取器尝试推断的目标服务名（可为空字符串）
        event_outcome     : 事件级 outcome_label（'success'/'partial_success'/...）

    Returns:
        True = 有价值，False = 过滤掉
    """
    # 规则1：长字符串元操作（session output/terminate/async 等）
    for pat in _META_OP_PATTERNS:
        if pat.search(command):
            return False
    # 规则2：极短命令（<10字符）且无成功信号——几乎肯定是元操作残留
    if not success_indicators and len(command.strip()) < 10:
        return False
    # P1 规则3：无软件标识 + 短命令 + 无成功信号 = 纯连接测试，无实际攻击价值
    # partial_success 豁免：该事件本身表明存在部分攻击成效
    if (
        not target_service
        and len(command.strip()) <= 100
        and not success_indicators
        and event_outcome != "partial_success"
    ):
        return False
    return True


def _infer_preconditions(
    event: AnnotatedEvent,
    command: str,
    cve_ids: List[str],
    confirmed_cve: Optional[str] = None,
) -> List[str]:
    """推断操作的前置条件（基于协议/端口/上下文推断，不依赖固定产品名枚举）。

    设计原则：
    - 从命令文本、工具名、端口号等结构性特征推断通用协议级别前置条件
    - CVE ID 若存在则作为可选增强，不强依赖
    - 使用预编译正则 _PROTO_PRECOND_RES 匹配，覆盖主要协议和工具
    - P-3: confirmed_cve 若提供，用于约束 CVE 前置条件（避免 JNDI/Log4Shell 污染 Druid CVE 前置条件）
    """
    preconditions: List[str] = []
    tool = event.base.call.tool_name
    combined = f"{tool} {command}"

    # 1. CVE 前置条件（P-3: 优先使用 confirmed_cve 约束，避免跨 CVE 污染）
    effective_cves = [confirmed_cve] if confirmed_cve else cve_ids
    if effective_cves:
        cve_list = ", ".join(effective_cves[:3])
        preconditions.append(f"目标存在可利用漏洞（{cve_list}）")
    elif re.search(r'exploit|payload|\brce\b|code.?exec|command.?inject', combined, re.IGNORECASE):
        preconditions.append("目标存在可利用的远程代码执行/命令注入漏洞")

    # 2. 协议/工具前置条件（正则匹配，不依赖产品关键词枚举）
    for rex, desc in _PROTO_PRECOND_RES:
        if rex.search(combined):
            preconditions.append(desc)

    # 3. RAG 上下文
    if event.base.has_rag_context:
        preconditions.append("已通过 RAG 知识检索获取相关利用信息")

    # 4. 兜底：至少提供一条基于端口的通用条件
    if not preconditions:
        hint = _port_to_service_hint(combined)
        if hint:
            preconditions.append(f"{hint} 服务正常运行且可访问")
        else:
            preconditions.append("目标服务正常运行且可访问")

    return list(dict.fromkeys(preconditions))


def _infer_target_service(command: str, output: str, cve_ids: List[str]) -> Optional[str]:
    """从命令输出中动态提取目标服务名（不依赖固定产品名枚举）。

    优先级（按可信度排序）：
    1. nmap open 行 → 包含 service + version，最权威
    2. HTTP 响应头 Server / X-Powered-By
    3. "ProductName/Version" 或 "ProductName_Version" 版本字符串
    4. 端口号 IANA 映射（兜底，返回通用协议名）
    5. CVE 编号作为补充描述（可选，无 CVE 则不输出）
    """
    # 1. nmap 开放端口行（最直接的信息来源）
    m = re.search(
        r'\d+/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', output, re.IGNORECASE
    )
    if m:
        svc = m.group(1).strip()
        ver_col = (m.group(2) or "").strip()[:80]
        return f"{svc} {ver_col}".strip() if ver_col else svc

    # 2. HTTP 响应头（curl -I, netcat 手动请求等常见场景）
    for header in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
        m = re.search(rf'^{header}:\s*(.+)', output, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip()[:80]

    # 3. 版本字符串模式（Apache/2.4.41, PHP/7.4.3, OpenSSH_8.2p1）
    #    遍历所有候选，取第一个非噪声非URL行内的匹配
    _NOISE_WORDS = frozenset(('version', 'release', 'revision', 'edition', 'spec', 'patch'))
    for m in re.finditer(
        r'\b([A-Za-z][A-Za-z0-9_\-]{3,25})[/_ ](\d+\.\d[\d.]*)\b',
        output
    ):
        product_word = m.group(1).lower()
        if product_word in _NOISE_WORDS:
            continue
        line_s = output.rfind('\n', 0, m.start()) + 1
        line_e = output.find('\n', m.end())
        cur_line = output[line_s:(line_e if line_e != -1 else len(output))]
        if not re.search(r'https?://', cur_line, re.IGNORECASE):
            return m.group(0).strip()[:80]

    # 4. 端口号 IANA 映射（从命令中提取端口）
    hint = _port_to_service_hint(command)
    if hint:
        return hint

    # 5. CVE 编号（可选增强，不依赖静态产品映射表）
    if cve_ids:
        return f"目标存在 {cve_ids[0]} 漏洞的服务"

    return None


# ─────────────────────────────────────────────────────────────────────────────
# PROCEDURAL_POS 提取
# ─────────────────────────────────────────────────────────────────────────────

def _extract_pos_from_event(
    event: AnnotatedEvent,
    session_id: str,
    counter: int,
    session_outcome_str: str,
    target_raw: Optional[str],
) -> Optional[Experience]:
    """从单个成功事件提取 PROCEDURAL_POS 经验条目。"""
    command = _get_command_text(event)
    raw_output = _get_raw_output(event)
    tool_name = event.base.call.tool_name
    attack_phase = event.attack_phase or "EXPLOITATION"

    if not command.strip():
        return None

    # 从目标描述提取 IP 提示
    target_ips = extract_ip_addresses(target_raw or "")
    target_ip_hint = target_ips[0] if target_ips else None

    # 也从命令本身提取 IP（优先命令中的 IP 作为 hint）
    cmd_ips = extract_ip_addresses(command)
    if cmd_ips:
        target_ip_hint = cmd_ips[0]

    # 参数化命令
    template, extracted = parameterize_command(command, target_ip_hint=target_ip_hint)

    # 提取元信息
    cve_ids = extract_cve_ids(command + " " + raw_output)
    success_indicators = _extract_success_indicators(raw_output)
    # P-3: 取命令/输出中第一个 CVE 作为 confirmed_cve，约束前置条件生成
    confirmed_cve = cve_ids[0] if cve_ids else None
    preconditions = _infer_preconditions(event, command, cve_ids, confirmed_cve=confirmed_cve)
    target_service = _infer_target_service(command, raw_output, cve_ids)

    # P-2：过滤元操作/无价值的成功事件
    if not _is_pos_worthy(
        command, success_indicators,
        target_service=target_service,
        event_outcome=event.outcome_label or "",
    ):
        return None

    # P-4：短命令（<=50字符）+ 无目标服务推断 + 无成功信号 = 纯连接测试/socket 测试
    # 例外：partial_success 事件说明存在部分攻击成效，不应被过滤
    event_outcome = event.outcome_label or ""
    if (
        not target_service
        and len(command.strip()) <= 50
        and not success_indicators
        and event_outcome != "partial_success"
    ):
        return None  # 纯连接测试，无实际攻击价值

    # P-1 接口预留：当正则未提取到成功信号 且 为 execute_code 工具时，
    # 可调用 _extract_success_indicators_llm(raw_output, client) 提取。
    # 当前版本仍使用正则（_extract_success_indicators），LLM 版本在 Layer 3 时启用。
    # TODO: if not success_indicators and tool_name == "execute_code" and client:
    #     success_indicators = _extract_success_indicators_llm(raw_output, client)

    content: Dict[str, Any] = {
        "command_template": template[:2000],
        "original_command": command[:1000],
        "tool_name": tool_name,
        "attack_phase": attack_phase,
        "preconditions": preconditions,
        "success_indicators": success_indicators[:5],  # 最多 5 条
        "cve_ids": cve_ids,
        "target_service": target_service,
    }

    # 动态置信度：根据成功信号质量 + 会话结果 + 信号有无调整
    _HIGH_QUALITY_SIGNALS = ("uid=0", "root@", "flag{")
    strong_count = sum(
        1 for ind in success_indicators
        if any(k in ind for k in _HIGH_QUALITY_SIGNALS)
    )
    if success_indicators:
        # 有成功信号：正常基础分
        base_conf = 0.78 if session_outcome_str == "success" else 0.72
    elif len(command.strip()) <= 50:
        # 🟡 Fix: 短命令 + 无信号 = socket/连通性测试，大幅降低置信度
        base_conf = 0.35
    else:
        # 长命令 + 无信号：输出被 JSON 包裹等导致正则失效，适度降低
        base_conf = 0.50
    computed_confidence = min(0.95, base_conf + strong_count * 0.05)

    tags = generate_tags(
        command + " " + raw_output,
        tool_name=tool_name,
        attack_phase=attack_phase,
        target_ip_hint=target_ip_hint,
    )

    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=[event.event_id],
        source_turn_indices=[event.turn_index],
        extraction_source=ExperienceSource.RULE,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        tags=tags,
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{counter:04d}",
        knowledge_layer=KnowledgeLayer.PROCEDURAL_POS,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=computed_confidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PROCEDURAL_NEG 提取
# ─────────────────────────────────────────────────────────────────────────────

def _extract_neg_from_event(
    event: AnnotatedEvent,
    session_id: str,
    counter: int,
    session_outcome_str: str,
    target_raw: Optional[str],
) -> Optional[Experience]:
    """从单个失败事件提取 PROCEDURAL_NEG 经验条目。"""
    frc = event.failure_root_cause
    if frc is None:
        return None

    command = _get_command_text(event)
    tool_name = event.base.call.tool_name
    attack_phase = event.attack_phase

    if not command.strip():
        return None

    dim = frc.dimension.value if frc.dimension else "UNKNOWN"
    sub_dim = frc.sub_dimension or ""
    evidence = _sanitize_ip_text(frc.evidence or "")
    remediation = _sanitize_ip_text(frc.remediation_hint or "")
    reasoning = _sanitize_ip_text((frc.reasoning or ""))
    evidence_snippet = _soft_truncate(evidence, 150)

    # 生成 avoid_pattern：结合 frc.evidence 和 frc.reasoning 生成丰富描述
    avoid_base_map = {
        "ENV": f"工具 `{tool_name}` 在目标环境中不可用（{sub_dim}），应先验证环境",
        "INV": f"调用 `{tool_name}` 时参数/语法有误（{sub_dim}），应检查用法文档",
        "DEF": f"目标对 `{tool_name}` 攻击存在防御（{sub_dim}），应尝试绕过或换策略",
        "INT": f"对目标情报判断有误（{sub_dim}），应补充侦察后再行动",
        "EFF": f"`{tool_name}` 执行效果不符预期（{sub_dim}），应验证实际效果",
    }
    base_desc = avoid_base_map.get(dim, f"{tool_name} 调用失败（{dim}/{sub_dim}）")
    # 拼接证据和推理（如果非空）
    parts = [base_desc]
    if evidence_snippet:
        parts.append(f"证据：{evidence_snippet}")
    reasoning_snippet = _soft_truncate(reasoning, 200)
    if reasoning_snippet:
        parts.append(reasoning_snippet)
    avoid_pattern = "。".join(parts)

    content: Dict[str, Any] = {
        "failed_command": command[:500],
        "tool_name": tool_name,
        "attack_phase": attack_phase,
        "failure_dimension": dim,
        "failure_sub_dimension": sub_dim,
        "evidence": _soft_truncate(evidence, 500),
        "remediation_hint": _soft_truncate(remediation, 500) if remediation else None,
        "avoid_pattern": avoid_pattern,
        "frc_source": frc.source,
        "frc_reasoning": _soft_truncate(reasoning, 500),
    }

    tags = generate_tags(
        command,
        tool_name=tool_name,
        attack_phase=attack_phase or "",
    )
    tags.extend([dim, sub_dim.lower()] if sub_dim else [dim])

    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=[event.event_id],
        source_turn_indices=[event.turn_index],
        extraction_source=ExperienceSource.RULE if frc.source == "rule" else ExperienceSource.LLM,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        tags=list(dict.fromkeys(tags)),
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{counter:04d}",
        knowledge_layer=KnowledgeLayer.PROCEDURAL_NEG,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=0.78 if frc.source == "rule" else 0.72,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 公开 API
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# NEG 决策规则批量丰富（LLM 驱动）
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_neg_with_decision_rules(
    neg_results: List[Experience],
    client,
    session_id: str,
    session_target_software: str = "",
) -> None:
    """对本次会话的所有 NEG 经验，批量调用 LLM 生成 decision_rule + failure_pattern_detail。

    原地修改 neg_results（在 content 中添加新字段），失败时静默跳过。
    每批最多处理 5 条，避免 token 溢出导致 JSON 截断。

    Args:
        neg_results            : 已提取的 PROCEDURAL_NEG 经验列表（原地修改）
        client                 : LLMClient 实例
        session_id             : 日志用会话 ID
        session_target_software: 会话级 LLM 识别的软件名（P1: 作为 target_software 局失时的兢底）
    """
    from ...prompts import NEG_DECISION_RULE_SYSTEM, build_neg_batch_decision_rule_prompt

    if not neg_results:
        return

    BATCH_SIZE = 4  # 每批最多 4 条，防止 JSON 输出截断

    for batch_start in range(0, len(neg_results), BATCH_SIZE):
        batch = neg_results[batch_start: batch_start + BATCH_SIZE]

        failure_items: List[Dict[str, Any]] = []
        for exp in batch:
            c = exp.content
            failure_items.append({
                "failed_command": c.get("failed_command", "")[:200],
                "tool_name": c.get("tool_name", ""),
                "attack_phase": c.get("attack_phase", ""),
                "failure_dimension": c.get("failure_dimension", ""),
                "failure_sub_dimension": c.get("failure_sub_dimension", ""),
                "evidence": _soft_truncate(_sanitize_ip_text(c.get("evidence", "")), 250),
                "remediation_hint": _soft_truncate(_sanitize_ip_text(c.get("remediation_hint") or ""), 200),
                "avoid_pattern": _soft_truncate(_sanitize_ip_text(c.get("avoid_pattern", "")), 200),
                # N-1: target_software 用于生成具体 THEN（CVE/工具/路径相关）
                # P1: 若 content 中 target_service 为空，用会话级 LLM 识别的软件名兑底
                "target_software": c.get("target_service") or session_target_software,
            })

        user_prompt = build_neg_batch_decision_rule_prompt(failure_items)

        try:
            result = client.chat_json(
                [{"role": "user", "content": user_prompt}],
                system=NEG_DECISION_RULE_SYSTEM,
                temperature=0.2,
                max_tokens=3600,
            )
            if not result.success or not result.parsed:
                raise RuntimeError(result.error or "LLM 返回无内容")
            rules_list = result.parsed.get("rules", [])
            if not isinstance(rules_list, list):
                rules_list = []
        except (json.JSONDecodeError, Exception) as e:
            import logging
            logging.getLogger(__name__).warning(
                "[procedural] NEG decision_rule LLM 失败 batch=%d session=%s err=%s",
                batch_start // BATCH_SIZE, session_id[:8], e,
            )
            continue  # 跳过本批，继续下一批

        if not isinstance(rules_list, list):
            continue

        for i, rule_item in enumerate(rules_list[:len(batch)]):
            if not isinstance(rule_item, dict):
                continue
            exp = batch[i]

            fp = rule_item.get("failure_pattern", {})
            if isinstance(fp, dict) and fp.get("trigger_condition"):
                exp.content["failure_pattern_detail"] = {
                    "trigger_condition": _soft_truncate(_sanitize_ip_text(str(fp.get("trigger_condition", ""))), 350),
                    "interpretation":    _soft_truncate(_sanitize_ip_text(str(fp.get("interpretation", ""))), 350),
                    "certainty":         str(fp.get("certainty", "medium"))[:10],
                }

            dr = rule_item.get("decision_rule", {})
            if isinstance(dr, dict) and dr.get("IF") and dr.get("THEN"):
                then_raw = dr.get("THEN", [])
                if isinstance(then_raw, str):
                    then_list = [then_raw]
                elif isinstance(then_raw, list):
                    then_list = [str(t)[:200] for t in then_raw[:4]]
                else:
                    then_list = []
                decision_rule_entry: Dict[str, Any] = {
                    "IF":   _soft_truncate(_sanitize_ip_text(str(dr.get("IF", ""))), 300),
                    "THEN": [_soft_truncate(_sanitize_ip_text(str(t)), 250) for t in then_list],
                    "NOT":  _soft_truncate(_sanitize_ip_text(str(dr.get("NOT", ""))), 300),
                }
                # N-2: 解析 next_actions 字段（具体下一步操作列表）
                na_raw = dr.get("next_actions", [])
                if isinstance(na_raw, list) and na_raw:
                    next_actions = []
                    for j, step_item in enumerate(na_raw[:3]):
                        if not isinstance(step_item, dict):
                            continue
                        next_actions.append({
                            "step": int(step_item.get("step", j + 1)),
                            "tool": str(step_item.get("tool", ""))[:50],
                            "command": str(step_item.get("command", ""))[:300],
                            "expected_signal": str(step_item.get("expected_signal", ""))[:150],
                        })
                    # P3: 将 next_actions command 中的真实 IP 地址替换为占位符
                    _na_loopback = re.compile(r'\b127\.0\.0\.1\b')
                    _na_target   = re.compile(r'\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b')
                    for na_item in next_actions:
                        cmd = na_item.get("command", "")
                        cmd = _na_loopback.sub("{LOOPBACK}", cmd)
                        cmd = _na_target.sub("{TARGET}", cmd)
                        na_item["command"] = cmd
                    if next_actions:
                        decision_rule_entry["next_actions"] = next_actions
                exp.content["decision_rule"] = decision_rule_entry


def extract_procedural_experiences(
    ann_seq: AnnotatedTurnSequence,
    exp_counter_start: int = 1,
    client=None,
    session_target_software: str = "",
) -> Tuple[List[Experience], List[Experience]]:
    """从 AnnotatedTurnSequence 提取 Procedural 经验（正/负两类）。

    Args:
        ann_seq                : Layer 1 标注完成的会话序列
        exp_counter_start      : 经验 ID 计数器起始値
        client                 : LLMClient 实例（非 None 时为 NEG 批量生成 decision_rule）
        session_target_software: 会话级 LLM 识别的软件名（P0-B/P1 回填展通用服务类型）

    Returns:
        (pos_experiences, neg_experiences)
        - pos_experiences : PROCEDURAL_POS 经验列表
        - neg_experiences : PROCEDURAL_NEG 经验列表
    """
    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    session_outcome_str = "unknown"

    if ann_seq.session_outcome:
        session_outcome_str = ann_seq.session_outcome.outcome_label

    pos_results: List[Experience] = []
    neg_results: List[Experience] = []
    pos_seen_hashes: set = set()  # POS/NEG 分开去重，避免 partial_success 事件被静默丢弃
    neg_seen_hashes: set = set()
    counter = exp_counter_start

    for event in ann_seq.annotated_events:
        phase = event.attack_phase or ""
        outcome = event.outcome_label or ""

        # ── PROCEDURAL_POS ────────────────────────────────────────────────
        # 需要：事件级别成功 AND 会话级别成功（避免从失败会话的偶发成功事件提取 POS）
        if (
            outcome in _SUCCESS_OUTCOMES
            and phase in _POS_PHASES
            and session_outcome_str in _SUCCESS_OUTCOMES
        ):
            exp = _extract_pos_from_event(
                event, session_id, counter,
                session_outcome_str, target_raw,
            )
            if exp:
                # 语义去重：相同会话 + 相同工具 + 相同阆段 + 相同命令前缀 视为重复
                # （避免同一 exploit 脚本多次迭代修改参数产生多条重复 POS）
                pos_sem_key = (
                    session_id,
                    exp.content.get("tool_name", ""),
                    exp.content.get("attack_phase", ""),
                    exp.content.get("command_template", "")[:80],
                )
                if pos_sem_key not in pos_seen_hashes:
                    pos_seen_hashes.add(pos_sem_key)
                    pos_results.append(exp)
                    counter += 1

        # ── PROCEDURAL_NEG ────────────────────────────────────────────────
        if (
            event.failure_root_cause is not None
            and outcome in _FAILURE_OUTCOMES
        ):
            exp = _extract_neg_from_event(
                event, session_id, counter,
                session_outcome_str, target_raw,
            )
            if exp:
                # 语义去重：相同会话 + 相同失败维度大类 + 相同工具 + 相同命令前缀
                # 注意：不包含 sub_dimension，避免同一命令的不同子维度屏蔽去重
                sem_key = (
                    session_id,
                    exp.content.get("failure_dimension", ""),
                    exp.content.get("tool_name", ""),
                    exp.content.get("failed_command", "")[:50],
                )
                if sem_key not in neg_seen_hashes:
                    neg_seen_hashes.add(sem_key)
                    neg_results.append(exp)
                    counter += 1

    # ── NEG 决策规则丰富（LLM 批量，可选）────────────────────────────────────
    if client is not None and neg_results:
        _enrich_neg_with_decision_rules(
            neg_results, client, session_id,
            session_target_software=session_target_software,  # P1
        )

    return pos_results, neg_results
