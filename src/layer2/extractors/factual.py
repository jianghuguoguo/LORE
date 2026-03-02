"""
Factual 经验提取器
==================
从所有攻击阶段中提取结构化事实型知识，包括：
  - RECON_WEAPONIZATION: 端口、服务、路径、版本扫描结果
  - ENV_PREPARATION    : 环境信息、依赖状态
  - EXPLOITATION/ESCALATION 等: 已确认漏洞、root 凭据、flag、SUID 二进制等

设计要点：
1. 覆盖全阶段：RECON 和 EXPLOITATION 阶段都可能产生高价值 FACTUAL 信息
2. 按 tool 路由解析器：nmap/HTTP/通用三路，自动识别命令 argv[0]
3. CVE 出现 ≠ 已确认：区分 `cve_mentioned` 与 `cve_confirmed`（需上下文佐证）
4. 目标指示符支持 IP 和域名两种形式
5. 函数签名无冗余参数
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ...models import AnnotatedEvent, AnnotatedTurnSequence
from ..experience_models import (
    Experience,
    ExperienceMaturity,
    ExperienceMetadata,
    ExperienceSource,
    KnowledgeLayer,
)
from ..utils.parameterizer import (
    extract_cve_ids,
    extract_target_ports,
    generate_tags,
    parameterize_command,
)

# ─────────────────────────────────────────────────────────────────────────────
# 常量 / 辅助正则
# ─────────────────────────────────────────────────────────────────────────────

# RECON/ENV 阶段：提取端口/服务/路径等探测结果
_RECON_PHASES = {"RECON_WEAPONIZATION", "ENV_PREPARATION"}
# 全阶段均可产生 FACTUAL（EXPLOITATION 可验证 root/flag/SUID 等）
_ALL_PHASES_FACTUAL = _RECON_PHASES | {
    "EXPLOITATION", "ESCALATION", "LATERAL_MOVEMENT", "EXFILTRATION", "COMMAND_CONTROL"
}
_SUCCESS_OUTCOMES = {"success", "partial_success"}

# Nmap: "PORT   STATE   SERVICE   VERSION"
# [^\ S\n]+ 仅匹配水平空白，完全排除 \n 跨行捕获
_RE_NMAP_PORT = re.compile(
    r"(\d{1,5}/(?:tcp|udp))[^\S\n]+open[^\S\n]+(\S+)(?:[^\S\n]+([^\n]+))?",
    re.IGNORECASE | re.MULTILINE,
)

# HTTP 状态码（状态行或 curl -I 输出）
_RE_HTTP_STATUS = re.compile(r"HTTP/\d+(?:\.\d+)?\s+(\d{3})\b")

# Directory buster: gobuster/dirsearch/feroxbuster 常见格式
_RE_DIR_BUST = re.compile(
    r"(?:Found|Status[:=]\s*200|200 OK)\s.*?(/[^\s\"']{2,})", re.IGNORECASE
)
_RE_PATH_STATUS = re.compile(
    r"(/[a-zA-Z0-9_\-./]{2,})\s+[\[\(](?:Status:\s*)?(?:200|301|302)"
)

# Enum4linux / smbclient share
_RE_SMB_SHARE = re.compile(r"(?:Disk|IPC|ADMIN)\$?\s+\|.*\|", re.IGNORECASE)

# Nikto finding (simplified, 排除 OSVDB 开头的文献引用)
_RE_NIKTO_FINDING = re.compile(r"^\+\s+(?!.*OSVDB)(.{20,120})", re.MULTILINE)

# EXPLOITATION 阶段高价值 FACTUAL 信号（root 权限、flag、SUID、文件读取、认证绕过等）
_EXPLOIT_FACTUAL_SIGNALS = [
    (re.compile(r"uid=0\(root\)", re.IGNORECASE),            "privilege_root",   "uid=0(root) — 已获取 root 权限"),
    (re.compile(r"root@[a-zA-Z0-9_\-]+"),                   "shell_root",       "root shell 获取成功"),
    (re.compile(r"flag\{([^}]{1,80})\}"),                   "flag_captured",    None),  # value 动态填充
    # SUID 文件要求用户执行位为 s/S（位置⑤：-rwsr...)，-rw-r--r-- 等普通文件不匹配
    (re.compile(r"(-\S{2}[sS]\S{6}\s+\d+\s+\S+\s+root\b[^\n]*)", re.IGNORECASE), "suid_binary", None),
    (re.compile(r"/etc/shadow", re.IGNORECASE),              "file_shadow",      "/etc/shadow 可读"),
    (re.compile(r"/etc/passwd", re.IGNORECASE),              "file_passwd",      "/etc/passwd 可读"),
    # 文件内容泵露：通过 API 返回的 /etc/passwd 内容（Druid/Spring Actuator 模式）
    (re.compile(r"root:x:0:0:"),                             "file_read_passwd",  "成功读取 /etc/passwd 内容"),
    # /etc/shadow 内容（root 这行含哈希字段，标志資料泵露）
    (re.compile(r"root:[*$!][^:]*:\d+:\d+:"),               "file_read_shadow",  "成功读取 /etc/shadow 内容"),
    # 认证绕过 / 登录成功
    (re.compile(r"(?:authentication|login)\s+successful", re.IGNORECASE), "auth_bypass", "认证绕过/登录成功"),
    (re.compile(r"sudo.*NOPASSWD", re.IGNORECASE),           "sudo_nopasswd",    "sudo NOPASSWD 配置存在"),
]

# 服务版本字符串（Product/Version），排除误报：URL 路径、SHA 哈希、纯数字
_RE_SERVICE_VERSION = re.compile(
    r'\b([A-Za-z][A-Za-z0-9_\-]{2,25})/(\d+[\d.]{1,15})\b'
)


# 低价值 output_summary 过滤器（F-2）
# 滤掉纯噪声数据，如纯 HTTP 状态码、Nmap 启动行、本地网卡信息等
_OS_NOISE_PATTERNS = [
    re.compile(r'^\d{3}$'),                                    # 纯状态码 "200"
    re.compile(r'^Starting Nmap', re.IGNORECASE),              # Nmap 启动行
    re.compile(r'^inet\d?\s+\S+', re.IGNORECASE),             # 本机网卡信息 (inet/inet6)
    re.compile(r'^Started async session', re.IGNORECASE),      # 异步 session 启动
    re.compile(r'^\d+\.\d+\.\d+\.\d+:\d+'),                  # IP:port 格式
    re.compile(r'Nmap \d+\.\d+.*nmap\.org', re.IGNORECASE),  # Nmap 版本行
    re.compile(r'^lo\s+Link|^eth\d+\s+Link|^ens\d+', re.IGNORECASE),  # 网卡别名行
    re.compile(r'^\[\*\]\s+(Starting|Loading|Initializ)', re.IGNORECASE),  # 工具启动日志
    re.compile(r'^\[\*\]\s+(?:Creating|Building|Writing|Uploading|Compiling)', re.IGNORECASE),  # exploit 进度日志
    re.compile(r'^\[\*\]\s+Command to execute:', re.IGNORECASE),  # exploit 命令回显
    re.compile(r'^\d+ packets (transmitted|captured)', re.IGNORECASE),  # Ping/tcpdump 统计
    # F-2 增强：HTML 页面内容（非 HTTP 状态行）
    re.compile(r'^<!', re.IGNORECASE),                         # <!DOCTYPE, <!-- 等
    re.compile(r'^</?[a-z][a-z0-9]*[\s>/]', re.IGNORECASE),  # 任意 HTML 标签（<p>, </head>, <h1>, <a href 等）
    re.compile(r'^</?[a-z][a-z0-9]*>$', re.IGNORECASE),      # 纯 HTML 标签行（如 </head>）
    re.compile(r'^Usage:\s+\w', re.IGNORECASE),               # 工具 usage 帮助
    re.compile(r'^/usr/share/', re.IGNORECASE),               # 系统工具路径
    re.compile(r'^/usr/lib/', re.IGNORECASE),                  # 系统库路径
    re.compile(r'^creating\s+wordlist\s+for', re.IGNORECASE), # 工具进度日志
    re.compile(r'^const\s+\w|^var\s+\w|^function\s*\('),     # JS 代码片段
    re.compile(r'^//'),                                        # JS 单行注释
    re.compile(r'^\*\s+@\w'),                                  # NPM/JSDoc 包注释（* @vue/...）
    re.compile(r'^\.[a-zA-Z][\w-]*\s*[\{>]'),                 # CSS 选择器（.class { 或 .class >）
    re.compile(r'^[0-9a-f]{30,}$', re.IGNORECASE),           # 纯十六进制 dump
    re.compile(r'^(true|false|null|None|ok|yes|no|undefined)$', re.IGNORECASE),  # 布尔/空值
    re.compile(r'^\./\w'),                                     # 相对路径片段（./data, ./tmp 等）
    re.compile(r'^-[a-zA-Z]\s'),                               # CLI flag 残留（-e admin, -v 等）
    re.compile(r'^Trying\s+(password|credential|login)', re.IGNORECASE),  # 暴力破解进度
    # F-2 Round-3: CSS 元素选择器 + 裸 HTTP 状态行
    re.compile(r'^[a-z][a-z0-9\-]*\s*\{'),                   # CSS 元素选择器（html {, body {, div {）
    re.compile(r'^HTTP/\d+(?:\.\d+)?\s+\d{3}\b'),          # 裸 HTTP 状态行（HTTP/1.1 404 Not Found）
    # F-2 Round-2 新增：漏网的页面/框架内容
    re.compile(r'^if\s*\('),                                   # JS if 语句（如 if (top != self) ...）
    re.compile(r'^#[\w-]+\s*[\{,]'),                          # CSS ID 选择器（#app {）
    re.compile(r'^\*\s+\([Cc]\)'),                             # 版权注释（* (c) 2018-present...）
    re.compile(r'^[a-z][\w-]+\s*:\s+\S+.*;\s*$'),            # 小写 CSS 属性（transform: rotate(45deg);）
    re.compile(r'^[A-Z]{3,}[-A-Z]*:\s+\S'),                   # 全大写 CSS 属性（COLOR: white; BACKGROUND-COLOR: ...）
    re.compile(r'^~\s+Licensed', re.IGNORECASE),              # Apache/MIT 许可证头（~ Licensed to the...）
    # F-2 Round-4: HTTP 响应头时间戳 + 含 IP 的工具日志 + 许可证正文
    re.compile(r'^Date:\s+\w{3},\s+\d+\s+\w+\s+\d{4}', re.IGNORECASE),           # HTTP Date 头
    re.compile(r'^\[\*\].*\b(?:\d{1,3}\.){3}\d{1,3}\b.*:\d{3,5}', re.IGNORECASE),  # [*] IP:port 工具日志
    re.compile(r'^[~#]\s+(?:or more contributor|Licensed to)', re.IGNORECASE),    # Apache/MIT 正文
    re.compile(r'^X-Forwarded-For:\s+', re.IGNORECASE),       # 含 IP 的代理头
]


def _is_low_value_summary(value: str) -> bool:
    """F-2: 判断一个 output_summary 值是否是低价值噪声，应当过滤。

    过滤逻辑（返回 True = 低价值，应过滤）：
    - 小于 6 字符（太短几乎没有意义）
    - 匹配 _OS_NOISE_PATTERNS 中任一模式（行首 match）
    - HTML 内容特征检测（search 模式，捕获非行首出现的 HTML 标签密集内容）
    """
    stripped = value.strip()
    if len(stripped) < 6:  # 小于 6 字符的一定是噪声
        return True
    if any(p.match(stripped) for p in _OS_NOISE_PATTERNS):
        return True
    # 额外：内容超过50字符且主体是 HTML（含大量标签），表明是完整 HTML 页面片段
    if len(stripped) > 50 and stripped.count('<') > 3 and stripped.count('>') > 3:
        return True
    return False


def _get_raw_output(event: AnnotatedEvent) -> str:
    """安全获取事件的原始输出文本（综合 stdout_raw 和 _raw_text）。"""
    if event.base.result is None:
        return ""
    r = event.base.result
    stdout = r.stdout_raw or ""
    raw_text = (r.raw_result or {}).get("_raw_text", "") or ""
    return (stdout or raw_text)[:3000]  # 最多 3000 chars 避免 token 爆炸


def _get_command_text(event: AnnotatedEvent) -> str:
    """获取事件调用的命令/代码文本。"""
    args = event.base.call.call_args or {}
    # GENERIC_COMMAND_CALL: args["command"]
    cmd = args.get("command", "")
    # CODE_WRITE: args["code"]
    if not cmd:
        cmd = args.get("code", "")
    return cmd


def _parse_nmap_findings(output: str) -> List[Dict[str, str]]:
    """解析 nmap 输出中的开放端口信息。"""
    findings = []
    for m in _RE_NMAP_PORT.finditer(output):
        port_proto = m.group(1)
        service = m.group(2).strip()
        version = (m.group(3) or "").strip()
        findings.append({
            "key": "open_port",
            "value": port_proto,
            "service": service,
            "version": version[:100] if version else "",
        })
    return findings


def _parse_http_findings(output: str, command: str) -> List[Dict[str, str]]:
    """解析 HTTP 工具输出中的状态码/路径信息（含事件内路径去重）。"""
    findings = []
    seen_statuses: set = set()
    seen_paths: set = set()

    # HTTP 状态行（每种状态码只记录一次）
    for m in _RE_HTTP_STATUS.finditer(output):
        status = m.group(1)
        if status in ("200", "301", "302", "401", "403") and status not in seen_statuses:
            seen_statuses.add(status)
            findings.append({"key": "http_status", "value": status})

    # 路径发现（gobuster / dirsearch / feroxbuster 等），事件内去重
    for m in _RE_DIR_BUST.finditer(output):
        path = m.group(1)[:100]
        if path not in seen_paths:
            seen_paths.add(path)
            findings.append({"key": "accessible_path", "value": path})
    for m in _RE_PATH_STATUS.finditer(output):
        path = m.group(1)[:100]
        if path not in seen_paths:
            seen_paths.add(path)
            findings.append({"key": "accessible_path", "value": path})

    return findings


def _parse_generic_findings(output: str, tool_name: str) -> List[Dict[str, str]]:
    """通用输出解析：动态提取服务信息、版本信息、重要发现。

    策略（不依赖固定产品枚举）：
    1. SMB 共享枚举结果（enum4linux / smbclient 输出）
    2. CVE 提及（可选增强，若存在则记录）
    3. Nikto 发现（Nikto 工具专属格式）
    4. 服务版本字符串（Product/Version 格式，如 nginx/1.18）
    5. HTTP 响应头（Server / X-Powered-By）
    6. 监听端口（"open port X", "listening on X" 等通用模式）
    7. 兜底：取第一行非空输出作为摘要
    """
    findings = []

    # SMB 分享
    for m in _RE_SMB_SHARE.finditer(output):
        findings.append({"key": "smb_share", "value": m.group(0).strip()[:150]})

    # CVE 提及（上下文感知：仅当输出中有漏洞确认词时才标记 cve_confirmed）
    for cve in extract_cve_ids(output):
        m_pos = re.search(re.escape(cve), output, re.IGNORECASE)
        if m_pos:
            ctx_start = max(0, m_pos.start() - 120)
            ctx_end = min(len(output), m_pos.end() + 120)
            ctx = output[ctx_start:ctx_end].lower()
            confirmed_kws = ("vulnerable", "confirmed", "detected",
                             "affected", "exploitable", "exploited",
                             "pwned", "popped", "\u6f0f\u6d1e\u786e\u8ba4", "\u5df2\u88ab\u5229\u7528")
            key = "cve_confirmed" if any(k in ctx for k in confirmed_kws) else "cve_mentioned"
        else:
            key = "cve_mentioned"
        findings.append({"key": key, "value": cve})

    # Nikto 发现
    for m in _RE_NIKTO_FINDING.finditer(output[:2000]):
        findings.append({"key": "nikto_finding", "value": m.group(1).strip()[:150]})

    # 服务版本字符串（nmap output 中也可能被此 fallback 处理器捕获；
    #                 nmap 专用解析器优先，这里提供后备覆盖）
    # 排除误报：OS 发行版名称 (Ubuntu/20.04)、URL 路径 (http://...)、
    #           SHA/hash 路径 (abc123/v1.2)、系统路径 (/usr/bin/...)
    _OS_NAMES = frozenset(["ubuntu", "debian", "centos", "fedora", "alpine",
                           "windows", "macos", "kali", "arch", "mint"])
    for m in re.finditer(r'\b([A-Za-z][A-Za-z0-9_\-]{2,25})/(\d+[\d.]{1,15})\b', output):
        product = m.group(1).lower()
        version = m.group(2)
        # 过滤：OS 名称、哈希前缀（全小写十六进制）、过短版本号误匹配
        if product in _OS_NAMES:
            continue
        if re.fullmatch(r'[0-9a-f]{6,}', product):  # 纯十六进制——是哈希非产品名
            continue
        # 排除 HTTP 协议版本字符串：HTTP/1.0、HTTP/1.1、HTTP/2
        if product.upper() in ('HTTP', 'HTTPS'):
            continue
        # 排除 CIDR 子网掘码：/8 /16 /24 /32 /48 /64 /96 /128
        try:
            if int(version) in (8, 16, 24, 32, 48, 64, 96, 128):
                continue
        except ValueError:
            pass
        # 排除 URL 中的路径段：取当前行，若该行含 URL 则跳过
        line_start = output.rfind('\n', 0, m.start()) + 1
        line_end_idx = output.find('\n', m.end())
        cur_line = output[line_start:(line_end_idx if line_end_idx != -1 else len(output))]
        if re.search(r'https?://', cur_line, re.IGNORECASE):
            continue
        findings.append({"key": "service_version", "value": m.group(0)[:80]})

    # HTTP 响应头（curl -v / netcat 手动请求等）
    for header in ("Server", "X-Powered-By", "X-Generator"):
        m_h = re.search(rf'^{header}:\s*(.+)', output, re.IGNORECASE | re.MULTILINE)
        if m_h:
            findings.append({"key": f"http_header_{header.lower()}", "value": m_h.group(1).strip()[:100]})

    # 开放端口证据（非 nmap 工具也可能输出此类信息）
    for m in re.finditer(r'(?:open port|port\s+(\d{1,5})\s+(?:is\s+)?open|(\d{1,5})\s+open)', output, re.IGNORECASE):
        port_str = m.group(1) or m.group(2) or ""
        if port_str:
            findings.append({"key": "open_port_evidence", "value": port_str})

    # 去重（同 key+value 的条目只保留一条）
    unique: List[Dict[str, str]] = []
    seen_kv: set = set()
    for f in findings:
        kv = (f.get("key", ""), f.get("value", ""))
        if kv not in seen_kv:
            seen_kv.add(kv)
            unique.append(f)

    if not unique:
        # 兜底：取第一行不含噪声的输出行作为摘要（F-2: 应用低价值过滤）
        _SUMMARY_NOISE = re.compile(
            r'^(?:Starting \w|Nmap scan report|Host is up|NSE:|'
            r'PORT\s+STATE\s+SERVICE|Not shown:|'             # nmap 表头/统计行
            r'Creating |Checking (?:for|port)|[Ii]nitializ|Setting up|'
            r'Started |Loading |Waiting |'
            r'inet6? |lo\s|eth\d|ens\d|wlan|docker|br-|virbr|'  # 本地网络接口
            r'\d+ packets trans|\d+ packets cap|'
            r'\$\s*\{|const\s+\w|var\s+\w|function\s*\(|'    # JS 代码辨识
            r'\[\*\]\s*(?:Starting|Initializ|Loading))',
            re.IGNORECASE
        )
        # 剥除 ANSI 转义码
        _ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
        lines = [l.strip() for l in output.split("\n") if l.strip()]
        for line in lines:
            clean = _ANSI.sub('', line)            # P2: 将 output_summary 中的真实 IP 地址替换为占位符（降低隐私泄露）
            clean = re.sub(r'\b(?:127\.0\.0\.1)\b', '{LOOPBACK}', clean)
            clean = re.sub(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b', '{TARGET}', clean)            # F-2: 同时检查低价值摘要过滤（避免存储纯数字状态码等）
            if clean and not _SUMMARY_NOISE.match(clean) and not _is_low_value_summary(clean):
                unique.append({"key": "output_summary", "value": clean[:200]})
                break

    return unique


def _determine_service_type(tool_name: str, command: str, output: str) -> str:
    """推断目标服务的通用协议大类（http/ssh/smb/ftp/db/network_scan/generic）。

    策略（优先级降序）：
    1. nmap open 行中的 service 列（最权威）
    2. HTTP 响应头（Server/X-Powered-By 出现则必然是 http）
    3. 工具名/命令关键词（结构化映射到通用协议大类）
    4. 目标端口号（well-known 端口 → 协议类型）
    """
    # 1. nmap 输出行直接给出 service 列
    m = re.search(r'\d+/(?:tcp|udp)\s+open\s+(\S+)', output, re.IGNORECASE)
    if m:
        svc_name = m.group(1).lower()
        if svc_name.startswith("http"):
            return "http"
        if svc_name in ("ssh", "ftp", "smtp", "smb", "ldap", "rdp", "vnc", "dns"):
            return svc_name
        if any(k in svc_name for k in ("sql", "db", "oracle", "mysql", "postgres")):
            return "database"

    # 2. HTTP 响应头 → 必然是 http
    if re.search(r'^(?:Server|X-Powered-By):\s*.+', output, re.IGNORECASE | re.MULTILINE):
        return "http"

    # 3. 工具名/命令关键词 → 通用协议大类（非特定产品名）
    combined = f"{tool_name} {command} {output[:200]}".lower()
    if any(k in combined for k in ("http", "https", "curl", "wget", "web", "nikto",
                                    "gobuster", "dirsearch", "ferox", "burp", "wfuzz",
                                    "ffuf", "wpscan", "nuclei", "zaproxy")):
        return "http"
    if any(k in combined for k in ("ssh", "scp", "sftp", "paramiko", "evil-winrm")):
        return "ssh"
    if any(k in combined for k in ("smb", "samba", "enum4linux", "smbclient",
                                    "rpcclient", "crackmapexec", "impacket")):
        return "smb"
    if any(k in combined for k in ("ftp", "vsftpd", "ftplib")):
        return "ftp"
    if any(k in combined for k in ("sql", "mysql", "mariadb", "postgres", "psql",
                                    "mssql", "oracle", "sqlite", "sqlmap")):
        return "database"
    if any(k in combined for k in ("redis", "memcached", "mongo", "elasticsearch",
                                    "couchdb", "cassandra")):
        return "nosql"
    if any(k in combined for k in ("ldap", "ldapsearch", "kerberos", "kerbrute")):
        return "ldap"
    if any(k in combined for k in ("rdp", "rdesktop", "xfreerdp", "remmina")):
        return "rdp"
    if "nmap" in combined:
        return "network_scan"

    # 4. 端口号推断
    ports = extract_target_ports(command)
    proto_by_port = {
        22: "ssh", 21: "ftp", 23: "telnet", 25: "smtp",
        80: "http", 443: "http", 445: "smb", 3389: "rdp",
        3306: "database", 5432: "database", 1433: "database",
        6379: "nosql", 5984: "nosql", 27017: "nosql", 9200: "nosql",
        389: "ldap", 636: "ldap",
    }
    for p in ports:
        if p in proto_by_port:
            return proto_by_port[p]

    return "generic"


def _get_argv0(command: str) -> str:
    """从命令字符串中提取 argv[0]（可执行文件名，去路径、小写）。"""
    if not command.strip():
        return ""
    import shlex
    try:
        parts = shlex.split(command)
        if parts:
            return parts[0].split("/")[-1].split("\\")[-1].lower()
    except ValueError:
        pass
    return command.split()[0].split("/")[-1].lower() if command.split() else ""


def _extract_passwd_users(output: str) -> str:
    """F-3: 从 /etc/passwd 内容中提取用户列表摘要（发现系统用户）。"""
    users = re.findall(r'^([a-zA-Z0-9_\-]+):x?:[0-9]+:[0-9]+:', output, re.MULTILINE)
    if users:
        # 分类：root(uid=0), 系统用户(uid<1000), 普通用户(uid>=1000)
        root_users = [u for u in users if u == 'root']
        normal_users = []
        for m in re.finditer(r'^([a-zA-Z0-9_\-]+):x?:([0-9]+):[0-9]+:', output, re.MULTILINE):
            try:
                if int(m.group(2)) >= 1000 and m.group(1) not in ('nobody',):
                    normal_users.append(m.group(1))
            except ValueError:
                pass
        parts = []
        if root_users:
            parts.append("root")
        if normal_users:
            parts.append(f"普通用户: {', '.join(normal_users[:5])}")
        else:
            parts.append("无普通用户")
        return f"系统用户: {', '.join(parts)}"
    return "成功读取 /etc/passwd 内容"


def _parse_exploit_findings(output: str) -> List[Dict[str, str]]:
    """EXPLOITATION/ESCALATION 阶段：提取 root 凭据/flag/SUID 等高价值 FACTUAL 信号。

    F-3: file_read 类发现现在包含实际内容细节，而非仅记录元标签。
    """
    findings = []
    for pattern, key, static_val in _EXPLOIT_FACTUAL_SIGNALS:
        for m in pattern.finditer(output):
            if key == "flag_captured":
                value = f"flag{{{m.group(1)}}}"
            elif key == "suid_binary":
                value = m.group(1).strip()[:120]
            elif key == "file_read_passwd":
                # F-3: 提取更有意义的用户信息而非仅记录元标签
                value = _extract_passwd_users(output)
            elif key == "file_read_shadow":
                # F-3: 记录是否含哈希（不含哈希内容本身）
                value = "成功读取 /etc/shadow — 含密码哈希（root 账户可发现）"
            else:
                value = static_val or m.group(0)[:100]
            findings.append({"key": key, "value": value})
    return findings


def _make_factual_exp(
    event: AnnotatedEvent,
    session_id: str,
    counter: int,
    findings: List[Dict[str, Any]],
    service_type: str,
    raw_evidence: str,
    target_raw: Optional[str],
    bar_score: float,
    session_outcome_str: str,
) -> Experience:
    """构造单条 FACTUAL 经验条目。"""
    tool_name = event.base.call.tool_name
    attack_phase = event.attack_phase or "RECON_WEAPONIZATION"
    command = _get_command_text(event)

    # F-1: 从命令和原始输出中提取 CVE ids，供 RAG 检索匹配
    fact_cve_ids = extract_cve_ids(command + " " + raw_evidence)

    content: Dict[str, Any] = {
        "service_type": service_type,
        "discovered_facts": findings,
        # P0: 对 raw_evidence 中的真实 IP 进行参数化，防止泰露到向量库
        "raw_evidence": re.sub(
            r'\b(?:127\.0\.0\.1|(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+)\b',
            '{TARGET}',
            raw_evidence[:500],
        ),
        "tool_name": tool_name,
        "attack_phase": attack_phase,
        # F-1: 添加 cve_ids；target_service 由 pipeline.py Step 1.5 后通过 FACTUAL_LLM 结果回填
        "cve_ids": fact_cve_ids,
        "target_service": "",   # 占位符，将由 pipeline 回填 LLM 识别的软件名
    }

    tags = generate_tags(
        command + " " + raw_evidence,
        tool_name=tool_name,
        attack_phase=attack_phase,
        target_ip_hint=None,
    )

    metadata = ExperienceMetadata(
        source_session_id=session_id,
        source_event_ids=[event.event_id],
        source_turn_indices=[event.turn_index],
        extraction_source=ExperienceSource.RULE,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
        session_bar_score=bar_score,
        tags=tags,
    )

    return Experience(
        exp_id=f"exp_{session_id[:8]}_{counter:04d}",
        knowledge_layer=KnowledgeLayer.FACTUAL,
        content=content,
        metadata=metadata,
        maturity=ExperienceMaturity.RAW,
        confidence=0.75,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 公开 API
# ─────────────────────────────────────────────────────────────────────────────

def extract_factual_experiences(
    ann_seq: AnnotatedTurnSequence,
    exp_counter_start: int = 1,
) -> List[Experience]:
    """从 AnnotatedTurnSequence 提取 FACTUAL 经验条目列表。

    Args:
        ann_seq           : Layer 1 标注完成的会话序列
        exp_counter_start : 经验 ID 计数器起始值（便于批量连续编号）

    Returns:
        FACTUAL 经验条目列表（可能为空）
    """
    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    session_outcome_str = "unknown"
    bar_score = ann_seq.bar_score
    if ann_seq.session_outcome:
        session_outcome_str = ann_seq.session_outcome.outcome_label

    results: List[Experience] = []
    counter = exp_counter_start
    seen_hashes: set = set()
    # F-3: session 级别的 (key, value) 去重集合，避免同一发现在多个事件里重复出现
    seen_kv_global: set = set()

    # 定义各阶段的 outcome 门限：
    #   RECON/ENV：success / partial_success 均可
    #   EXPLOITATION 等：仅 success（避免纯失败事件误报高价值信号）
    _EXPLOIT_PHASES = _ALL_PHASES_FACTUAL - _RECON_PHASES

    for event in ann_seq.annotated_events:
        phase = event.attack_phase or ""
        outcome = event.outcome_label or ""

        # 阶段门限
        if phase not in _ALL_PHASES_FACTUAL:
            continue

        # outcome 门限：RECON 允许 partial_success；EXPLOITATION 仅 success
        if phase in _RECON_PHASES:
            if outcome not in _SUCCESS_OUTCOMES:
                continue
        else:
            if outcome != "success":
                continue

        # 必须有输出
        raw_output = _get_raw_output(event)
        if not raw_output.strip():
            continue

        command = _get_command_text(event)
        tool_name = event.base.call.tool_name

        # make_kb_search 返回的是知识库 prior knowledge，不是对目标的实证观察，排除出 FACTUAL
        if tool_name == "make_kb_search":
            continue

        argv0 = _get_argv0(command) or tool_name.lower()
        service_type = _determine_service_type(tool_name, command, raw_output)

        # 按阶段 + argv0 路由解析器
        if phase in _EXPLOIT_PHASES:
            # EXPLOITATION 阶段优先扫描高价值信号
            findings = _parse_exploit_findings(raw_output)
            # 同时也保留通用解析（CVE/版本等）作为补充
            generic = _parse_generic_findings(raw_output, argv0)
            # 合并，exploit 信号放前面
            findings = findings + [f for f in generic
                                   if f.get("key") in ("cve_confirmed", "cve_mentioned", "service_version")]
        elif "nmap" in argv0 or "nmap" in tool_name.lower() or "nmap" in command.lower():
            findings = _parse_nmap_findings(raw_output)
        elif argv0 in ("curl", "httpx", "wget", "gobuster", "dirsearch",
                       "feroxbuster", "nikto", "ffuf", "wfuzz", "wpscan"):
            findings = _parse_http_findings(raw_output, command)
        else:
            findings = _parse_generic_findings(raw_output, argv0)

        if not findings:
            # 无解析结果时保留通用摘要条目（F-2: 过滤低价值噪声）
            for ln in raw_output.split("\n"):
                first_line = ln.strip()
                if first_line and not _is_low_value_summary(first_line):
                    findings = [{"key": "output_summary", "value": first_line[:200]}]
                    break

        if not findings:
            continue

        # F-3: session 级别 (key, value) 去重 —— 跨事件过滤同一发现
        deduped_findings = []
        for _f in findings:
            _kv = (_f.get("key", ""), _f.get("value", ""))
            if _kv not in seen_kv_global:
                seen_kv_global.add(_kv)
                deduped_findings.append(_f)
        findings = deduped_findings
        if not findings:
            continue

        # P0: 过滤掉仅有 output_summary 的 HTTP RECON 经验（无结构化发现，质量过低）
        # EXPLOITATION 阶段保留（那里的 output_summary 可能含 root shell 证据）
        _STRUCTURAL_KEYS = {
            "open_port", "http_status", "service_version", "accessible_path",
            "cve_confirmed", "cve_mentioned", "nikto_finding", "smb_share",
            "url_found", "open_port_evidence",
        }
        only_summary = all(f.get("key") == "output_summary" for f in findings)
        if only_summary and phase in _RECON_PHASES and service_type == "http":
            continue  # 纯 HTML/文本输出无结构化信息，不入库

        exp = _make_factual_exp(
            event=event,
            session_id=session_id,
            counter=counter,
            findings=findings,
            service_type=service_type,
            raw_evidence=raw_output,
            target_raw=target_raw,
            bar_score=bar_score,
            session_outcome_str=session_outcome_str,
        )

        # 会话内去重
        if exp.content_hash not in seen_hashes:
            seen_hashes.add(exp.content_hash)
            results.append(exp)
            counter += 1

    return results
