# src/layer4/quality_filter.py
"""
渗透测试专项质量过滤。

评估一篇安全文章是否包含「可执行的技术内容」
（PoC 代码、shell 命令序列、CVE 利用步骤），
纯概念介绍文章（score < 0.3）应丢弃，不写入知识库。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class QualityResult:
    score:         float   # 0.0 ~ 1.0
    has_poc:       bool
    has_commands:  bool
    has_cve_ref:   bool
    reject_reason: str     # 空字符串 = 不拒绝


# ── 高价值来源域名（命中则加 0.3 分）────────────────────────────────────────
# BUG-7B 修复：去掉 CSDN / 先知 / 奇安信攻防社区——这些域名的页面
# 通常是学习资料、文章列表页或概念介绍，domain_bonus 会把它们错误拉过门槛。
# 保留真正包含可执行 PoC 的来源。
HIGH_VALUE_DOMAINS = [
    "github.com",
    "exploit-db.com",
    "nvd.nist.gov",
    "cve.mitre.org",
    "packetstormsecurity.com",
    "vulhub.org",
    "portswigger.net",
    "attackerkb.com",
    "seebug.org",
    # 保留 0day PoC 聚合站，移除泛技术博客
]

# ── PoC 特征正则 ─────────────────────────────────────────────────────────────
POC_PATTERNS = [
    re.compile(r"```(?:python|bash|sh|ruby|java|perl|go)[\s\S]{30,}```", re.I),
    re.compile(r"import\s+(?:requests|socket|struct|subprocess|base64)", re.I),
    re.compile(r"msfconsole|msfvenom|msf>|use exploit/", re.I),
    re.compile(r"curl\s+-[A-Za-z]|wget\s+http|nc\s+-[enlvp]", re.I),
    re.compile(r"<\?xml[\s\S]{20,}XMLDecoder|<beans[\s\S]{20,}class=", re.I),
    re.compile(r"exec\(|eval\(|os\.system\(|subprocess\.(?:run|Popen|call)\(", re.I),
    re.compile(r"(?:reverse|bind)\s+shell", re.I),
    re.compile(r"payload\s*=|shellcode\s*=|exploit\s*=", re.I),
]
_POC_PATTERNS = POC_PATTERNS  # 兼容

# ── 命令序列特征（BUG-7C 修复：要求命令出现在代码上下文中）────────────────────
# 旧版只要文章含 nmap/hydra 字样即命中，导致纯介绍文章也得分。
# 新版要求：命令在代码块（```bash）内，或有 $ / # 前缀的实际执行行。
CMD_PATTERNS = [
    # 代码围栏块（bash/sh/shell/console，至少 20 字符内容）
    re.compile(r"```(?:bash|sh|shell|console|terminal)[^`]{20,}```", re.I | re.S),
    # $ 前缀的攻击工具命令行（明确是在 shell 中执行）
    re.compile(
        r"(?:^|\n)\$\s+(?:nmap|gobuster|curl|wget|hydra|sqlmap|msfconsole"
        r"|nuclei|ffuf|feroxbuster|dirb|wfuzz|nikto|nc\b|netcat|john|hashcat)",
        re.M | re.I,
    ),
    # # 前缀（root shell）的攻击工具命令行
    re.compile(
        r"(?:^|\n)#\s+(?:nmap|gobuster|curl|wget|hydra|sqlmap|msfconsole"
        r"|nuclei|ffuf|feroxbuster|dirb|wfuzz|nikto|nc\b|netcat|john|hashcat)",
        re.M | re.I,
    ),
    # msfconsole 交互命令（use exploit/...）
    re.compile(r"msf[56]?>\s*(?:use|set|run|exploit)", re.I),
    # Python PoC 脚本中的 socket/requests 调用
    re.compile(r"python3?\s+\w+exploit\w*\.py|python3?\s+poc\.py", re.I),
]
_CMD_PATTERNS = CMD_PATTERNS  # 向后兼容


# ── GitHub URL 价值判断（BUG-7D）───────────────────────────────────────────────
def _github_url_tier(url: str) -> int:
    """返回 GitHub URL 的价值层级：
      2 = PoC 代码文件（blob/raw/releases） → 加分
      1 = 普通仓库页面（README）           → 中性
      0 = Issues / PR 讨论                → 不加分
    """
    if "github.com" not in url:
        return 1
    if "/issues/" in url or "/pull/" in url or "/discussions/" in url:
        return 0
    if "/blob/" in url or "/raw/" in url or "/releases/" in url:
        return 2
    return 1


def filter_content(text: str, url: str = "") -> QualityResult:
    """评估内容是否值得写入主知识库。"""
    if len(text) < 200:
        return QualityResult(0.0, False, False, False, "too_short")

    has_poc      = any(p.search(text) for p in POC_PATTERNS)
    cmd_hits     = sum(1 for p in CMD_PATTERNS if p.search(text))
    # BUG-7C 修复：需要命中 ≥2 个严格模式，或命中 1 个代码块模式（index 0）
    has_commands = cmd_hits >= 2 or bool(CMD_PATTERNS[0].search(text))
    has_cve_ref  = bool(re.search(r"CVE-\d{4}-\d{4,}", text))

    # 来源加分（BUG-7B：去掉了中文博客，只剩 PoC 聚合站）
    domain = urlparse(url).netloc.lstrip("www.")
    domain_bonus = 0.3 if any(hv in domain for hv in HIGH_VALUE_DOMAINS) else 0.0

    # BUG-7D：GitHub Issues/PR 扣 0.2 分；PoC 文件加 0.1 分
    gh_tier = _github_url_tier(url)
    if gh_tier == 0:
        domain_bonus = max(domain_bonus - 0.2, 0.0)
    elif gh_tier == 2:
        domain_bonus = min(domain_bonus + 0.1, 0.4)

    base_score = (
        (0.5 if has_poc      else 0.0)
        + (0.3 if has_commands else 0.0)
        + (0.2 if has_cve_ref  else 0.0)
    )
    score = min(base_score + domain_bonus, 1.0)

    reject_reason = ""
    if score < 0.3:
        reject_reason = "low_quality_no_actionable_content"
    elif gh_tier == 0 and not has_poc and not has_commands:
        reject_reason = "github_issue_no_poc"
    return QualityResult(score, has_poc, has_commands, has_cve_ref, reject_reason)
