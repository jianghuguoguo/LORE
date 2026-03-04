"""
Layer 1 – 确定性规则引擎（Deterministic Rules Engine）
======================================================
职责：对 AtomicEvent 应用不依赖 LLM 的确定性规则，输出 FailureRootCause。

技术方案明确："规则层（先行，确定性）：
    return_code=127 → ENV-BINARY_MISSING
    timed_out=true  → ENV-TIMEOUT
    return_code=126 → ENV-EXECUTE_PERMISSION_DENIED"
来自 技术方案 R-02 / 三.2.1 节。

设计约束：
    - 所有规则均为"确定性"规则，100% 可靠，不存在误判
    - 规则优先级严格有序（见 RULE_PRIORITY_ORDER）
    - 每个规则仅检查 ResultDescriptor 中的可靠字段（return_code / timed_out）
    - 不涉及任何工具名语义、stderr 内容匹配或其他推断
    - 规则层未覆盖的事件将由 Phase 3 LLM 层处理

已实现规则（Phase 2）：
    RC-127  return_code=127 → ENV-BINARY_MISSING
    RC-126  return_code=126 → ENV-EXECUTE_PERMISSION_DENIED
    RC-124  return_code=124 → ENV-TIMEOUT        （timeout 命令自身超时退出）
    RC-130  return_code=130 → ENV-INTERRUPTED    （SIGINT / Ctrl+C 中断）
    RC-137  return_code=137 → ENV-SIGKILL        （SIGKILL：OOM Killer / kill -9 / 系统关闭）
    RC-143  return_code=143 → ENV-SIGTERM        （SIGTERM：编排层主动终止）
    TOUT    timed_out=True  → ENV-TIMEOUT        （CAI 框架超时标志兜底）
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import (
    ActionCategory,
    AnnotatedEvent,
    AtomicEvent,
    FailureRootCause,
    FailureRootCauseDimension,
    ResultDescriptor,
)


# ─────────────────────────────────────────────────────────────────────────────
# 规则表（有序；每条规则：名称、谓词、五维 FailureRootCause 工厂）
# ─────────────────────────────────────────────────────────────────────────────

_ENV = FailureRootCauseDimension.ENV


class _Rule:
    """内部轻量规则描述符。"""
    __slots__ = ("name", "description", "_factory")

    def __init__(self, name: str, description: str, factory):
        self.name = name
        self.description = description
        self._factory = factory

    def matches(self, result: ResultDescriptor) -> bool:
        raise NotImplementedError

    def build(self) -> FailureRootCause:
        return self._factory()


class _ReturnCodeRule(_Rule):
    """基于 return_code 的精确匹配规则。"""
    def __init__(self, name: str, code: int, description: str, factory):
        super().__init__(name, description, factory)
        self._code = code

    def matches(self, result: ResultDescriptor) -> bool:
        return result.return_code == self._code

    def build_with_tool(self, tool_name: str, stderr_raw: str = "") -> FailureRootCause:
        """构建携带工具名的 FailureRootCause（evidence 包含 binary/tool_name）。"""
        return self._factory(tool_name, stderr_raw)


class _TimedOutRule(_Rule):
    """基于 timed_out=True 的规则。"""
    def matches(self, result: ResultDescriptor) -> bool:
        return bool(result.timed_out)


# ─────────────────────────────────────────────────────────────────────────────
# 确定性规则集（按优先级有序）
# 技术方案 R-02 / 三.2.1：先 return_code；timed_out 兜底
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Binary → 正确安装方式映射表
# 格式：binary_name → ("apt"|"manual", install_target, extra_note)
#   apt    : 通过 apt install <install_target> 安装
#   manual : 需手动下载/编译，install_target 为下载地址
# 未在表中的 binary 兜底使用 "apt install <binary>"（best-effort）
# ─────────────────────────────────────────────────────────────────────────────
_BINARY_INSTALL_MAP: dict[str, tuple[str, str, str]] = {
    # Metasploit：二进制 msfconsole，apt 包名 metasploit-framework
    "msfconsole":   ("apt",    "metasploit-framework",  ""),
    # 常见渗透工具（二进制名与包名一致，列出以明确支持）
    "dirb":         ("apt",    "dirb",                  ""),
    "nmap":         ("apt",    "nmap",                  ""),
    "nikto":        ("apt",    "nikto",                 ""),
    "gobuster":     ("apt",    "gobuster",              ""),
    "hydra":        ("apt",    "hydra",                 ""),
    "sqlmap":       ("apt",    "sqlmap",                ""),
    "wfuzz":        ("apt",    "wfuzz",                 ""),
    "ffuf":         ("apt",    "ffuf",                  ""),
    "john":         ("apt",    "john",                  ""),
    "hashcat":      ("apt",    "hashcat",               ""),
    "netcat":       ("apt",    "netcat",                ""),
    "nc":           ("apt",    "netcat",                ""),
    "curl":         ("apt",    "curl",                  ""),
    "wget":         ("apt",    "wget",                  ""),
    # Go 单体二进制：不在 apt，需手动下载
    "fscan":   ("manual", "https://github.com/shadow1ng/fscan/releases",
                "Go 单体二进制，无 apt 包，需从 GitHub Releases 手动下载"),
    "nuclei":  ("manual", "https://github.com/projectdiscovery/nuclei/releases",
                "Go 单体二进制，无 apt 包，需从 GitHub Releases 下载"
                "（或 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest）"),
    "subfinder": ("manual", "https://github.com/projectdiscovery/subfinder/releases",
                  "Go 单体二进制，需从 GitHub Releases 手动下载"),
    "httpx":   ("manual", "https://github.com/projectdiscovery/httpx/releases",
                "Go 单体二进制，需从 GitHub Releases 手动下载"),
}


def _install_hint(binary: str, tool_name: str) -> str:
    """根据映射表生成正确的安装建议；未知 binary 退回 apt install <binary>（best-effort）。"""
    tool_part = f"（工具 {tool_name} 依赖此二进制）" if tool_name else ""
    entry = _BINARY_INSTALL_MAP.get(binary)
    if entry is None:
        # 未知二进制，best-effort 提示
        return f"{binary} 未安装{tool_part}，请通过 apt install {binary} 安装"
    method, target, note = entry
    note_part = f"，{note}" if note else ""
    if method == "apt":
        return f"{binary} 未安装{tool_part}，请通过 apt install {target} 安装"
    else:
        return f"{binary} 未安装{tool_part}{note_part}，请手动下载安装：{target}"


def _rc127_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-127 工厂：优先从 stderr_raw 提取真实二进制名，再结合 tool_name 写入 evidence。

    evidence 格式：
        binary 已知时 → "return_code=127 (binary=dirb, tool=dirb_scan)"
        仅有 tool_name → "return_code=127 (tool=dirb_scan)"
        均未知         → "return_code=127"

    remediation_hint：通过 _BINARY_INSTALL_MAP 映射表生成正确的包名/安装方式，
    避免将二进制名直接用作 apt 包名（例如 msfconsole → metasploit-framework）。
    """
    # 从 stderr_raw 提取真实缺失的二进制文件名
    m = re.search(r'(\w+):\s*not found', stderr_raw)
    binary = m.group(1) if m else ""

    if binary and tool_name:
        evidence = f"return_code=127 (binary={binary}, tool={tool_name})"
        hint = _install_hint(binary, tool_name)
    elif binary:
        evidence = f"return_code=127 (binary={binary})"
        hint = _install_hint(binary, "")
    elif tool_name:
        evidence = f"return_code=127 (tool={tool_name})"
        hint = f"{tool_name} 依赖的二进制未安装，请检查工具安装情况（无法从 stderr 确定具体二进制名）"
    else:
        evidence = "return_code=127"
        hint = "确认目标环境中已安装该工具，或使用绝对路径调用"

    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="BINARY_MISSING",
        evidence=evidence,
        source="rule",
        remediation_hint=hint,
    )


def _rc126_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-126 工厂：evidence 包含工具名（stderr_raw 保留签名一致性，暂不解析）。"""
    tool_info = f" (tool={tool_name})" if tool_name else ""
    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="EXECUTE_PERMISSION_DENIED",
        evidence=f"return_code=126{tool_info}",
        source="rule",
        remediation_hint="检查文件权限（chmod +x），或以适当权限运行",
    )


def _rc124_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-124 工厂：`timeout N cmd` 的超时退出（exit 124 为 GNU coreutils timeout 约定）。"""
    tool_info = f" (tool={tool_name})" if tool_name else ""
    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="TIMEOUT",
        evidence=f"return_code=124{tool_info}",
        source="rule",
        remediation_hint="timeout 命令设定的时限已到期，建议增大 timeout 参数或将任务拆分为更小批次",
    )


def _rc130_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-130 工厂：进程收到 SIGINT（128+2），通常为 Ctrl+C 或脚本主动发送。"""
    tool_info = f" (tool={tool_name})" if tool_name else ""
    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="INTERRUPTED",
        evidence=f"return_code=130{tool_info}",
        source="rule",
        remediation_hint="前台进程被 SIGINT 中断（Ctrl+C / kill -2），如为误操作请重新运行；如为预期行为则可忽略",
    )


def _rc137_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-137 工厂：进程收到 SIGKILL（128+9）。可能原因：OOM Killer、手动 kill -9、系统关闭。

    使用 ENV-SIGKILL 而非 ENV-OOM_KILLED，以覆盖所有强制终止场景；
    OOM 场景在 remediation_hint 中作为优先排查项列出。
    """
    tool_info = f" (tool={tool_name})" if tool_name else ""
    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="SIGKILL",
        evidence=f"return_code=137{tool_info}",
        source="rule",
        remediation_hint=(
            "进程被 SIGKILL 强制终止（exit 137 = 128+9）。"
            "优先排查：① OOM Killer（dmesg | grep -i oom）；"
            "② 手动 kill -9；③ 系统关机/重启。"
            "内存密集型工具（如 hashcat）请限制内存用量或减小任务规模"
        ),
    )


def _rc143_factory(tool_name: str = "", stderr_raw: str = "") -> FailureRootCause:
    """RC-143 工厂：进程收到 SIGTERM（128+15），通常由编排层主动发出（如超时后清理）。"""
    tool_info = f" (tool={tool_name})" if tool_name else ""
    return FailureRootCause(
        dimension=_ENV,
        sub_dimension="SIGTERM",
        evidence=f"return_code=143{tool_info}",
        source="rule",
        remediation_hint="进程收到 SIGTERM 被正常终止，通常由编排层在超时后主动清理发出；可检查超时配置或编排策略",
    )


DETERMINISTIC_RULES: list[_Rule] = [
    _ReturnCodeRule(
        name="RC-127",
        code=127,
        description="shell 通用约定：命令不存在（binary not found）",
        factory=_rc127_factory,
    ),
    _ReturnCodeRule(
        name="RC-126",
        code=126,
        description="shell 通用约定：命令无执行权限",
        factory=_rc126_factory,
    ),
    _ReturnCodeRule(
        name="RC-124",
        code=124,
        description="GNU coreutils timeout 约定：timeout N cmd 超时退出",
        factory=_rc124_factory,
    ),
    _ReturnCodeRule(
        name="RC-130",
        code=130,
        description="POSIX 约定（128+2）：SIGINT / Ctrl+C 中断",
        factory=_rc130_factory,
    ),
    _ReturnCodeRule(
        name="RC-137",
        code=137,
        description="POSIX 约定（128+9）：SIGKILL 强制终止（OOM / kill -9 / 系统关闭）",
        factory=_rc137_factory,
    ),
    _ReturnCodeRule(
        name="RC-143",
        code=143,
        description="POSIX 约定（128+15）：SIGTERM 正常终止（编排层主动清理）",
        factory=_rc143_factory,
    ),
    _TimedOutRule(
        name="TOUT",
        description="工具自报告 timed_out=True，执行超时",
        factory=lambda _tool_name="": FailureRootCause(
            dimension=_ENV,
            sub_dimension="TIMEOUT",
            evidence="timed_out=true",
            source="rule",
            remediation_hint="增大 timeout 参数，或分批次执行",
        ),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# 公共接口
# ─────────────────────────────────────────────────────────────────────────────

def apply_deterministic_rules(
    event: AtomicEvent,
) -> tuple[Optional[FailureRootCause], Optional[str]]:
    """对单个 AtomicEvent 应用全部确定性规则，返回首个命中规则的结果。

    Args:
        event: Layer 0 输出的原子事件

    Returns:
        (failure_root_cause, rule_name)
        - failure_root_cause : FailureRootCause 对象，或 None（未命中任何规则）
        - rule_name          : 命中的规则名称，或 None

    Note:
        evidence 字段包含工具名（tool_name），便于 Layer 2 经验提取时区分
        不同工具的 ENV-BINARY_MISSING 失败，避免生成内容相同的负向 Procedural 条目。
    """
    if event.result is None:
        return None, None

    tool_name = event.call.tool_name if event.call else ""
    stderr_raw = event.result.stderr_raw if event.result else ""
    result = event.result
    for rule in DETERMINISTIC_RULES:
        if rule.matches(result):
            # 优先调用 build_with_tool（携带工具名 + stderr_raw 供二进制提取），降级到 build()
            if hasattr(rule, "build_with_tool"):
                return rule.build_with_tool(tool_name, stderr_raw), rule.name
            return rule.build(), rule.name

    return None, None


def should_flag_for_llm(
    event: AtomicEvent,
    failure_root_cause: Optional[FailureRootCause],
) -> bool:
    """判断该事件是否需要 Phase 3 LLM 语义分析。

    策略（Phase 2 修订版，根据审查问题 1 修正）：
    - **所有事件**（含 result=None）均 needs_llm=True。
    - 理由：即使工具没有返回结果（中断/前台进程不退出），该工具调用仍然是
      一次有意义的行为（如 EXPLOITATION 阶段的 weaponization），需要 LLM
      完成 attack_phase 分类。
    - 在 Phase 3 的 LLM prompt 中，result=None 的事件应明确标注：
      "该事件无执行结果，仅做行为功能分类（attack_phase），跳过失败根因判断"。

    此函数始终返回 True。needs_llm=True 的语义是：
      "Phase 3 LLM 必须处理此事件"，而非 "此事件的失败根因需要 LLM 判定"。
    后者通过 failure_root_cause=None + result 状态的组合体现。
    """
    return True  # 全量：所有事件（含 result=None）均需 Phase 3 LLM 处理


def annotate_event(event: AtomicEvent) -> AnnotatedEvent:
    """对单个 AtomicEvent 完成 Phase 2 全量标注（规则层）。

    Args:
        event: Layer 0 输出的原子事件

    Returns:
        AnnotatedEvent（failure_root_cause 由规则层填充；其余 Phase 3 字段留空）
    """
    failure_root_cause, rule_applied = apply_deterministic_rules(event)
    needs_llm = should_flag_for_llm(event, failure_root_cause)

    return AnnotatedEvent(
        base=event,
        failure_root_cause=failure_root_cause,
        attack_phase=None,        # Phase 3 填充
        outcome_label=None,       # Phase 3 填充
        rule_applied=rule_applied,
        needs_llm=needs_llm,
    )
