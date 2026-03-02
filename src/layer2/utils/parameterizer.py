"""
命令/代码参数化工具（Parameterizer）
======================================
将渗透测试命令/代码中的具体实例值替换为语义化占位符，
生成可复用的「命令模板」（command template）。

设计原则（顶会质量要求）：
1. 保留命令/代码的语义骨架（工具名、选项、逻辑结构不变）
2. 仅替换「实例相关」的值：目标 IP/域名、端口号（在特定上下文）、CVE ID
3. 不替换：工具选项标志、固定路径（如 /etc/passwd）、通用端口（80/443）
4. 提取 CVE ID 列表、IP 列表、端口列表（用于 tag 生成）

占位符约定：
  {TARGET_IP}      : 目标主机 IP 地址（如 192.168.1.100）
  {TARGET_HOST}    : 目标域名/主机名（如 vulnapp.local）
  {TARGET_PORT}    : 非通用端口（非 80/443/22/21/3306/5432）
  {CVE_ID}         : CVE 编号（如 CVE-2017-10271）（仅在代码中出现时替换）
  {LHOST}          : 攻击机 IP（反弹 shell 监听地址）
  {LPORT}          : 攻击机监听端口
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 正则模式
# ─────────────────────────────────────────────────────────────────────────────

# RFC 1918 私有地址段 + 127.x
_RE_PRIVATE_IP = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# 任意合法 IPv4（用于更宽泛的匹配，但优先级低于私有段）
_RE_ANY_IP = re.compile(
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
)

# CVE 编号
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# 常用「已知端口」不做替换（保留语义信息）
_COMMON_PORTS: Set[int] = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443,
    445, 587, 993, 995, 1433, 1521, 3000, 3306, 3389,
    4369, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
}

# 目标端口：出现在命令行 -p / --port / :PORT 上下文的非通用端口
_RE_TARGET_PORT_DASH = re.compile(r"(-p\s+|--port[=\s]+)(\d{2,5})\b")
_RE_URL_PORT = re.compile(r"(https?://[^\s/:]+):(\d{2,5})(/|\s|$)")

# 反弹 shell 监听 IP/端口（LHOST/LPORT）
# 典型模式: LHOST=IP, lhost=IP, -LHOST IP
_RE_LHOST = re.compile(
    r"(?:LHOST|lhost)[=\s]+(" + _RE_ANY_IP.pattern[3:-3] + r")\b"
)
_RE_LPORT = re.compile(r"(?:LPORT|lport)[=\s]+(\d{2,5})\b")


# ─────────────────────────────────────────────────────────────────────────────
# 主函数
# ─────────────────────────────────────────────────────────────────────────────

def parameterize_command(
    text: str,
    target_ip_hint: Optional[str] = None,
) -> Tuple[str, Dict[str, List[str]]]:
    """对命令字符串/代码进行参数化，返回（模板, 提取信息字典）。

    Args:
        text           : 待参数化的命令字符串或代码文本
        target_ip_hint : 已知目标 IP（优先替换，可为 None）

    Returns:
        (template, extracted)
        - template  : 参数化后的模板字符串
        - extracted : {"ips": [...], "cve_ids": [...], "target_ports": [...]}
    """
    if not text or not isinstance(text, str):
        return text or "", {"ips": [], "cve_ids": [], "target_ports": []}

    out = text
    extracted: Dict[str, List[str]] = {"ips": [], "cve_ids": [], "target_ports": []}

    # ── 1. 提取并替换 CVE ID ────────────────────────────────────────────────
    cve_ids = list(dict.fromkeys(_RE_CVE.findall(out)))  # 保序去重
    extracted["cve_ids"] = [c.upper() for c in cve_ids]
    # CVE ID 保留（不替换），仅提取供 tag 生成

    # ── 2. 提取并替换 LHOST/LPORT（反弹 shell 监听地址）──────────────────
    lhost_match = _RE_LHOST.search(out)
    if lhost_match:
        lhost_ip = lhost_match.group(1)
        out = out.replace(lhost_ip, "{LHOST}", 1)
        # 剩余出现也替换
        out = re.sub(re.escape(lhost_ip), "{LHOST}", out)

    lport_match = _RE_LPORT.search(out)
    if lport_match:
        lport_val = lport_match.group(1)
        if int(lport_val) not in _COMMON_PORTS:
            out = _RE_LPORT.sub(f"LPORT={{{lport_val}}}", out, count=1)

    # ── 3. 提取并替换目标端口（-p/--port/URL 上下文中的非通用端口）────────
    for m in _RE_TARGET_PORT_DASH.finditer(out):
        flag_part, port_str = m.group(1), m.group(2)
        port_num = int(port_str)
        if port_num not in _COMMON_PORTS:
            extracted["target_ports"].append(port_str)
    for m in _RE_URL_PORT.finditer(out):
        port_str = m.group(2)
        port_num = int(port_str)
        if port_num not in _COMMON_PORTS:
            extracted["target_ports"].append(port_str)

    # 替换目标端口（-p 语境）
    def _replace_target_port_dash(m: re.Match) -> str:
        flag_part, port_str = m.group(1), m.group(2)
        port_num = int(port_str)
        if port_num not in _COMMON_PORTS:
            return f"{flag_part}{{TARGET_PORT}}"
        return m.group(0)

    def _replace_url_port(m: re.Match) -> str:
        proto_host, port_str, suffix = m.group(1), m.group(2), m.group(3)
        port_num = int(port_str)
        if port_num not in _COMMON_PORTS:
            return f"{proto_host}:{{TARGET_PORT}}{suffix}"
        return m.group(0)

    out = _RE_TARGET_PORT_DASH.sub(_replace_target_port_dash, out)
    out = _RE_URL_PORT.sub(_replace_url_port, out)

    # ── 4. 提取并替换目标 IP ──────────────────────────────────────────────
    # 优先使用 hint IP 精确替换
    all_ips: List[str] = []

    if target_ip_hint and _RE_ANY_IP.match(target_ip_hint.strip()):
        if target_ip_hint in out:
            out = out.replace(target_ip_hint, "{TARGET_IP}")
            all_ips.append(target_ip_hint)

    # 再替换所有私有 IP
    # 注意：LHOST IP 在步骤1中已被替换为 {LHOST}，不会出现在 findall 结果中
    remaining_ips = _RE_PRIVATE_IP.findall(out)
    for ip in dict.fromkeys(remaining_ips):  # 保序去重
        if ip not in all_ips:
            out = out.replace(ip, "{TARGET_IP}")
            all_ips.append(ip)

    extracted["ips"] = all_ips
    extracted["target_ports"] = list(dict.fromkeys(extracted["target_ports"]))

    return out, extracted


def extract_cve_ids(text: str) -> List[str]:
    """从文本中提取所有 CVE 编号（去重保序）。"""
    matches = _RE_CVE.findall(text)
    return list(dict.fromkeys(c.upper() for c in matches))


def extract_ip_addresses(text: str) -> List[str]:
    """从文本中提取所有私有 IP 地址（去重保序）。"""
    matches = _RE_PRIVATE_IP.findall(text)
    return list(dict.fromkeys(matches))


def extract_target_ports(text: str) -> List[int]:
    """从命令文本中提取非通用目标端口号。"""
    ports: List[int] = []
    for m in _RE_TARGET_PORT_DASH.finditer(text):
        p = int(m.group(2))
        if p not in _COMMON_PORTS:
            ports.append(p)
    for m in _RE_URL_PORT.finditer(text):
        p = int(m.group(2))
        if p not in _COMMON_PORTS:
            ports.append(p)
    return list(dict.fromkeys(ports))


# ─────────────────────────────────────────────────────────────────────────────
# 动态服务/技术名称提取（不依赖固定关键词枚举）
# ─────────────────────────────────────────────────────────────────────────────

# "Product/Version" 格式（nmap / curl / HTTP 响应常见）
_RE_PRODUCT_VERSION = re.compile(
    r'([A-Za-z][A-Za-z0-9_\-]{2,30})/(\d+[\.\d]*\b)',
)

# nmap open port line: "80/tcp   open  http   nginx 1.18.0"
_RE_NMAP_SERVICE_NAME = re.compile(
    r'\d+/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', re.IGNORECASE
)

# HTTP Server / X-Powered-By headers
_RE_HTTP_HEADER_VALUE = re.compile(
    r'^(?:Server|X-Powered-By|X-Generator|X-AspNet-Version):\s*(.+)',
    re.IGNORECASE | re.MULTILINE,
)

# 协议/工具名（从命令第一个词 + 常见 pentest 工具名中提取）
_RE_TOOL_WORD = re.compile(r'\b(nmap|sqlmap|metasploit|msfconsole|hydra|hashcat|'
                            r'nikto|gobuster|dirsearch|feroxbuster|wpscan|'
                            r'enum4linux|smbclient|rpcclient|crackmapexec|'
                            r'impacket|evil-winrm|kerbrute|bloodhound|'
                            r'burpsuite|zaproxy|ffuf|wfuzz|nuclei|'
                            r'curl|wget|netcat|nc|socat|python|perl|ruby)\b',
                            re.IGNORECASE)


def _extract_tech_names_from_text(text: str) -> List[str]:
    """从文本中动态提取技术/服务名称作为标签（不依赖固定枚举表）。

    优先来源（按可信度降序）：
    1. "Product/Version" 格式字符串（nginx/1.18, PHP/7.4, Apache/2.4）
    2. nmap open 行中的服务名称列
    3. HTTP 响应头（Server/X-Powered-By 等）
    4. 已知渗透测试工具名正则（工具本身即信息）

    Returns:
        去重后的技术名称列表（全小写）
    """
    names: List[str] = []

    # 1. Product/Version 格式：提取产品名（忽略版本号部分）
    for m in _RE_PRODUCT_VERSION.finditer(text):
        product = m.group(1).lower()
        # 过滤：排除纯路径片段（起始非 http/https 且不含斜杠之前的内容）
        if len(product) >= 3 and '/' not in product:
            names.append(product)

    # 2. nmap 服务列（service + version 列都取）
    for m in _RE_NMAP_SERVICE_NAME.finditer(text):
        svc = m.group(1).strip().lower()
        names.append(svc)
        ver_col = (m.group(2) or "").strip()
        if ver_col:
            # 版本列通常是 "nginx 1.18" 或 "Oracle WebLogic 10.3"
            # 提取所有长度 ≥ 4 的字母单词（过滤版本号和短词）
            meaningful_words = [
                w.lower() for w in ver_col.split()
                if len(w) >= 4 and not w[0].isdigit() and w.isalnum() or (len(w) >= 4 and '-' in w)
            ]
            names.extend(meaningful_words[:4])

    # 3. HTTP 头
    for m in _RE_HTTP_HEADER_VALUE.finditer(text):
        val = m.group(1).strip().lower()
        # 取第一个词（如 "apache" from "Apache/2.4.41"), 去掉版本
        first_word = re.split(r'[/\s]', val)[0]
        if len(first_word) >= 3:
            names.append(first_word)

    # 4. 已知渗透测试工具
    for m in _RE_TOOL_WORD.finditer(text):
        names.append(m.group(1).lower())

    return list(dict.fromkeys(n for n in names if n))


def generate_tags(
    text: str,
    tool_name: str = "",
    attack_phase: str = "",
    target_ip_hint: Optional[str] = None,
) -> List[str]:
    """为经验条目生成检索标签列表（全动态，不依赖固定枚举表）。

    标签来源：
    - CVE ID（可选，文本中若无则跳过）
    - 工具名（直接字段）
    - 攻击阶段（直接字段）
    - 动态提取的服务/技术名（Product/Version、nmap行、HTTP头、工具名正则）
    - 非通用目标端口（port:XXXX 格式）

    Args:
        text          : 命令/代码/输出文本
        tool_name     : 工具名称
        attack_phase  : 攻击阶段标签
        target_ip_hint: 目标 IP 提示（保留参数，当前未使用）

    Returns:
        标签列表（去重后，最多 20 条，避免过度膨胀）
    """
    tags: List[str] = []

    # CVE IDs（可选增强）
    tags.extend(extract_cve_ids(text))

    # 工具名
    if tool_name:
        tags.append(tool_name.lower())

    # 攻击阶段
    if attack_phase:
        tags.append(attack_phase.lower())

    # 动态提取服务/技术名
    tags.extend(_extract_tech_names_from_text(text))

    # 非通用目标端口（辅助检索）
    for port in extract_target_ports(text)[:3]:
        tags.append(f"port:{port}")

    # 去重保序，限制总数
    return list(dict.fromkeys(t for t in tags if t))[:20]
