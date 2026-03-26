"""
Phase 1 — Semantic Equivalence Clustering (SEC)
================================================
将来自不同会话的经验按语义相似性分组，找出「说同一件事」的经验集合。

匹配策略（四层，优先级递减）：
  L1 硬键（必要条件）：knowledge_layer + target_service + failure_sub_dim
  L2 软键（强信号）  ：CVE IDs 交集 ≥ 1
  L3 语义（辅助）    ：decision_rule.IF 嵌入向量 cosine > 0.82【本版本 TODO：暂不启用】
  L4 版本约束（排除）：target_version 版本族差异 → 强制分入不同子集

关键实现说明（来自分析文档 §2.2 Bug 记录）：
  对于 PROCEDURAL_NEG 层，target_service 必须从
  metadata.applicable_constraints.target_service 读取，
  而不是 content.target_service（后者为空字符串）。
"""

from __future__ import annotations

import hashlib
import json
import re
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .models import EquivalenceSet
from ..utils.service_name_normalizer import normalize_service_name as shared_normalize_service_name
from ..utils.config_loader import get_config

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SSO 规范化映射（Security Semantic Ontology 小词典）
# 默认内建 + 可选外部配置文件（configs/sec_aliases.json）
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_SERVICE_ALIASES: Dict[str, str] = {
    # Oracle WebLogic 系列
    "oracle weblogic server":        "Oracle WebLogic Server",
    "oracle weblogic":               "Oracle WebLogic Server",
    "weblogic server":               "Oracle WebLogic Server",
    "weblogic":                      "Oracle WebLogic Server",
    "wls":                           "Oracle WebLogic Server",
    # Apache 系列
    "apache httpd":                  "Apache HTTP Server",
    "apache http server":            "Apache HTTP Server",
    "apache":                        "Apache HTTP Server",
    # CouchDB
    "couchdb":                       "CouchDB",
    "apache couchdb":                "CouchDB",
    # Tomcat
    "apache tomcat":                 "Apache Tomcat",
    "tomcat":                        "Apache Tomcat",
    # Nginx
    "nginx":                         "Nginx",
    # Redis
    "redis":                         "Redis",
    # Apache Druid
    "apache druid":                  "Apache Druid",
    "druid":                         "Apache Druid",
    # Apache ActiveMQ
    "apache activemq":               "Apache ActiveMQ",
    "activemq":                      "Apache ActiveMQ",
    # Apache Log4j
    "apache log4j":                  "Apache Log4j",
    "log4j":                         "Apache Log4j",
    # Spring
    "spring framework":              "Spring Framework",
    "spring":                        "Spring Framework",
    "spring boot":                   "Spring Framework",
    # Apache Shiro
    "apache shiro":                  "Apache Shiro",
    "shiro":                         "Apache Shiro",
    # Confluence
    "atlassian confluence":          "Atlassian Confluence",
    "confluence":                    "Atlassian Confluence",
    # Solr
    "apache solr":                   "Apache Solr",
    "solr":                          "Apache Solr",
    # Others
    "drupal":                        "Drupal",
    "gitlab":                        "GitLab",
    "grafana":                       "Grafana",
    "jenkins":                       "Jenkins",
    "metabase":                      "Metabase",
    # 靶场实例ID/内部编号
    "s350209713":                    "Atlassian Confluence",
}

# 设计约束：CVE 空间极大，默认不做内建别名枚举。
# 统一走 CVE 正则提取 + 格式归一（CVE-YYYY-NNNN...）。
# 如需项目私有别名，可在 configs/sec_aliases.json 的 cve_aliases 显式维护。
_DEFAULT_CVE_ALIASES: Dict[str, str] = {}

# CVE -> 服务名 兜底映射（仅用于 target_service 缺失时推断）
_DEFAULT_CVE_SERVICE_HINTS: Dict[str, str] = {
    "CVE-2014-4210": "Oracle WebLogic Server",
    "CVE-2016-3088": "Apache ActiveMQ",
    "CVE-2017-10271": "Oracle WebLogic Server",
    "CVE-2017-12635": "CouchDB",
    "CVE-2017-12636": "CouchDB",
    "CVE-2017-3506": "Oracle WebLogic Server",
    "CVE-2019-0192": "Apache Solr",
    "CVE-2019-0193": "Apache Solr",
    "CVE-2019-17558": "Apache Solr",
    "CVE-2019-2725": "Oracle WebLogic Server",
    "CVE-2020-14882": "Oracle WebLogic Server",
    "CVE-2020-1938": "Apache Tomcat",
    "CVE-2021-25646": "Apache Druid",
    "CVE-2021-26084": "Atlassian Confluence",
    "CVE-2021-27905": "Apache Solr",
    "CVE-2021-36749": "Apache Druid",
    "CVE-2022-26134": "Atlassian Confluence",
    "CVE-2023-22515": "Atlassian Confluence",
    "CVE-2023-22527": "Atlassian Confluence",
    "CVE-2023-46604": "Apache ActiveMQ",
}

_CVE_ID_RE = re.compile(r"CVE[-_\s]?(\d{4})[-_\s]?(\d{4,7})", re.IGNORECASE)
_RECON_PHASES_SET = {"RECON_WEAPONIZATION", "ENV_PREPARATION"}

_SERVICE_PLACEHOLDER_TOKENS = frozenset(
    {
        "none",
        "null",
        "unknown",
        "raw",
        "validated",
        "consolidated",
        "consolidates",
        "conflict",
        "conflicted",
        "active",
        "archived",
        "suspended",
        "deleted",
        "maturity",
        "anysvc",
        "service",
        "target",
        "http",
        "html",
        "trying",
    }
)

_SERVICE_ID_TOKEN_RE = re.compile(r"^s\d{6,}$", re.IGNORECASE)

_NEG_SUB_DIM_NORMALIZE_RULES: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"VERSION_MISMATCH|VERSION_MISJUDGMENT|ASSUMPTION_ERROR", re.IGNORECASE), "VERSION_OR_INTEL"),
    (re.compile(r"AUTHENTICATION|AUTHORIZATION|UNAUTHORIZED|FORBIDDEN|REDIRECT", re.IGNORECASE), "AUTH_OR_PERMISSION"),
    (re.compile(r"WAF|PATCH|DEFENSE|FILTER|VALIDATION", re.IGNORECASE), "DEFENSE_BLOCK"),
    (re.compile(r"PARAMETER|INPUT|SYNTAX|FORMAT|ARGUMENT", re.IGNORECASE), "INPUT_OR_USAGE"),
    (re.compile(r"TARGET_MISIDENTIFICATION|TARGET_MISJUDGMENT|PREMISE|INTEL", re.IGNORECASE), "TARGET_INTEL"),
    (re.compile(r"TOOL_MISSING|BINARY_MISSING|DEPENDENCY|ENV_", re.IGNORECASE), "TOOLING_ENV"),
    (re.compile(r"PARTIAL_SUCCESS_NO_EXPLOIT|NO_EXPLOIT|NO_EFFECT|INEFFECTIVE", re.IGNORECASE), "NO_EFFECT"),
]


def _normalize_neg_sub_dimension(raw_sub_dim: str, raw_dim: str) -> str:
    """将高基数 NEG 子维度收敛到可聚类的稳定桶。"""
    text = str(raw_sub_dim or "").strip().upper()
    if not text:
        dim = str(raw_dim or "UNKNOWN").strip().upper()
        return dim or "UNKNOWN"
    for pattern, normalized in _NEG_SUB_DIM_NORMALIZE_RULES:
        if pattern.search(text):
            return normalized
    return text


def _normalize_alias_mapping(raw: Any) -> Dict[str, str]:
    """将别名字典统一为 {lower_key: CanonicalName}。"""
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in raw.items():
        key = str(k).strip().lower()
        # 允许在配置中使用 null 显式标记“无效别名”，此处直接跳过。
        if v is None:
            continue
        val = str(v).strip()
        if key and val:
            out[key] = val
    return out


def _normalize_cve_service_hints(raw: Any) -> Dict[str, str]:
    """将 CVE->服务名映射归一化为 {CVE-XXXX-XXXX: CanonicalService}。"""
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in raw.items():
        if v is None:
            continue
        key = str(k).strip().upper()
        val = str(v).strip()
        m = _CVE_ID_RE.search(key)
        if not m or not val:
            continue
        out[f"CVE-{m.group(1)}-{m.group(2)}"] = val
    return out


def _load_external_aliases() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """从 configs/sec_aliases.json 加载别名；缺失或格式错误时降级为内建。"""
    try:
        cfg = get_config().sec_aliases_path
    except Exception:
        cfg = Path(__file__).resolve().parents[2] / "configs" / "sec_aliases.json"
    if not cfg.exists():
        return {}, {}, {}
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("SEC: 读取外部别名配置失败 path=%s err=%s", cfg, exc)
        return {}, {}, {}

    service_aliases = _normalize_alias_mapping(data.get("service_aliases", {}))
    cve_aliases = _normalize_alias_mapping(data.get("cve_aliases", {}))
    cve_service_hints = _normalize_cve_service_hints(data.get("cve_service_hints", {}))
    logger.info(
        "SEC: 已加载外部别名配置 service=%d cve=%d cve_service_hints=%d",
        len(service_aliases),
        len(cve_aliases),
        len(cve_service_hints),
    )
    if cve_aliases:
        logger.warning("SEC: 检测到项目自定义 cve_aliases=%d（仅建议用于局部数据集）", len(cve_aliases))
    return service_aliases, cve_aliases, cve_service_hints


_EXT_SERVICE_ALIASES, _EXT_CVE_ALIASES, _EXT_CVE_SERVICE_HINTS = _load_external_aliases()
_SERVICE_ALIASES: Dict[str, str] = {**_DEFAULT_SERVICE_ALIASES, **_EXT_SERVICE_ALIASES}
_CVE_ALIASES: Dict[str, str] = {**_DEFAULT_CVE_ALIASES, **_EXT_CVE_ALIASES}
_CVE_SERVICE_HINTS: Dict[str, str] = {**_DEFAULT_CVE_SERVICE_HINTS, **_EXT_CVE_SERVICE_HINTS}
_CANONICAL_SERVICE_NAMES = set(_SERVICE_ALIASES.values())


def normalize_service_name(raw: str) -> str:
    """将服务名规范化为 SEC 规范名（共享核心逻辑 + SEC 别名映射）。"""
    return shared_normalize_service_name(raw, aliases=_SERVICE_ALIASES)


def _compact_service_token(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(raw or "").strip().lower())


def _is_placeholder_service(raw: str) -> bool:
    token = _compact_service_token(raw)
    if not token:
        return True
    if token in _SERVICE_PLACEHOLDER_TOKENS:
        return True
    if token.startswith("consolidat") or token.startswith("validat"):
        return True
    if token.startswith("expconsolidated"):
        return True
    if _SERVICE_ID_TOKEN_RE.match(token):
        # 仅数字ID默认视为无效服务名；若在 alias 中有配置，会在 canonical_service_or_empty 前置映射掉。
        return token not in _SERVICE_ALIASES
    return False


def canonical_service_or_empty(raw: str) -> str:
    """服务名规范化并过滤占位词，无法确认时返回空字符串。"""
    if not raw:
        return ""
    raw_s = str(raw).strip()
    if _is_placeholder_service(raw_s):
        return ""
    normalized = normalize_service_name(raw_s)
    if _is_placeholder_service(normalized):
        return ""
    return normalized


def _infer_service_from_cves(cve_ids: List[str]) -> str:
    hints: Counter = Counter()
    for cve in cve_ids:
        key = str(cve).upper()
        svc = _CVE_SERVICE_HINTS.get(key, "")
        canonical = canonical_service_or_empty(svc)
        if canonical:
            hints[canonical] += 1
    if not hints:
        return ""
    return hints.most_common(1)[0][0]


def _infer_service_from_text(exp: Dict[str, Any]) -> str:
    """从文本上下文（content/target_raw/tags）中推断服务名。"""
    text_chunks: List[str] = []
    content = exp.get("content", {})
    metadata = exp.get("metadata", {})
    if content:
        try:
            text_chunks.append(json.dumps(content, ensure_ascii=False, sort_keys=True))
        except Exception:
            text_chunks.append(str(content))
    target_raw = metadata.get("target_raw", "")
    if target_raw:
        text_chunks.append(str(target_raw))
    tags = metadata.get("tags", [])
    if isinstance(tags, list) and tags:
        text_chunks.append(" ".join(str(t) for t in tags))

    if not text_chunks:
        return ""

    text = "\n".join(text_chunks).lower()
    score: Counter = Counter()
    for alias, canonical in _SERVICE_ALIASES.items():
        if not alias:
            continue
        canonical_svc = canonical_service_or_empty(canonical)
        if not canonical_svc:
            continue
        # 用非字母数字边界避免误匹配（例如 'solr' 命中 'consolr'）。
        pattern = rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"
        if re.search(pattern, text):
            score[canonical_svc] += max(1, len(alias))

    if not score:
        return ""
    return score.most_common(1)[0][0]


def resolve_target_service(exp: Dict[str, Any]) -> str:
    """为单条经验解析可用的 target_service（优先约束字段，失败再文本/CVE兜底）。"""
    meta_constraints = exp.get("metadata", {}).get("applicable_constraints", {})
    content = exp.get("content", {})

    # 1) 显式字段优先
    candidates = [
        meta_constraints.get("target_service", ""),
        content.get("target_service", ""),
    ]
    for cand in candidates:
        canonical = canonical_service_or_empty(str(cand))
        if canonical:
            return canonical

    # 2) 从文本上下文提取
    inferred_from_text = _infer_service_from_text(exp)
    if inferred_from_text:
        return inferred_from_text

    # 3) 通过 CVE 推断服务
    inferred_from_cve = _infer_service_from_cves(_extract_cve_ids(exp))
    if inferred_from_cve:
        return inferred_from_cve

    return ""


def _extract_cve_tokens(raw: str) -> List[str]:
    """从任意 token 中提取或映射到标准 CVE ID。"""
    token = str(raw).strip()
    if not token:
        return []

    matched = [f"CVE-{year}-{num}" for year, num in _CVE_ID_RE.findall(token)]
    if matched:
        return matched

    key = token.lower()
    alias = _CVE_ALIASES.get(key)
    if not alias:
        compact = re.sub(r"[^a-z0-9]+", "", key)
        alias = _CVE_ALIASES.get(compact)
    if not alias:
        return []

    alias_match = _CVE_ID_RE.search(alias)
    if alias_match:
        return [f"CVE-{alias_match.group(1)}-{alias_match.group(2)}"]
    return [alias.upper()]


def normalize_cve_ids(cve_list: List[str]) -> List[str]:
    """规范化 CVE 列表（正则提取 + 统一格式；可选项目私有别名）。"""
    normalized: List[str] = []
    seen: set = set()
    for cve in cve_list:
        for token in _extract_cve_tokens(str(cve)):
            canonical = token.upper()
            # 尝试别名映射（兼容 token 本身就是别名的场景）
            mapped = _CVE_ALIASES.get(canonical.lower())
            if mapped:
                canonical = mapped.upper()
            m = _CVE_ID_RE.search(canonical)
            if m:
                canonical = f"CVE-{m.group(1)}-{m.group(2)}"
            if canonical and canonical not in seen:
                seen.add(canonical)
                normalized.append(canonical)
    return sorted(normalized)


# ─────────────────────────────────────────────────────────────────────────────
# 版本族解析（L4 匹配用）
# ─────────────────────────────────────────────────────────────────────────────

def parse_version_family(version_str: str) -> str:
    """将具体版本号归入版本族，例如 '10.3.6.0' → '10.3.x'。

    规则：
      - 取主版本号 + 次版本号，第三位替换为 'x'
      - 无法解析时返回 ""（表示版本约束未知，不参与 L4 排除）
    """
    if not version_str:
        return ""
    # 匹配 major.minor(.patch(.build)?) 格式
    m = re.match(r"^(\d+)\.(\d+)(?:\.\d+)*", version_str.strip())
    if m:
        major, minor = m.group(1), m.group(2)
        return f"{major}.{minor}.x"
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# L1 键提取
# ─────────────────────────────────────────────────────────────────────────────

def _extract_l1_key(exp: Dict[str, Any]) -> Tuple[str, str, str]:
    """提取 L1 硬键：(knowledge_layer, target_service_normalized, failure_sub_dim)。

    注意 NEG Bug（分析文档 §2.2 §9）：
      PROCEDURAL_NEG 的 content.target_service 为空字符串，
      正确读取位置是 metadata.applicable_constraints.target_service。
    """
    raw_layer = exp.get("knowledge_layer", "")
    # 兼容历史数据：旧数据中 FACTUAL_* 统一映射回 FACTUAL。
    knowledge_layer = "FACTUAL" if str(raw_layer).startswith("FACTUAL_") else raw_layer

    # FACTUAL 仍保持单一 knowledge_layer，通过 sub_dim 子键区分 rule/llm 来源，
    # 既保证命名统一，也避免两种 schema 在同一等价集内被误融合。
    factual_source = ""
    if knowledge_layer == "FACTUAL":
        extraction_source = str(exp.get("metadata", {}).get("extraction_source", "")).lower()
        content = exp.get("content", {})
        has_cve_context = "cve_context" in content or "cve_exploitation_map" in content
        factual_source = "LLM" if (extraction_source == "llm" or has_cve_context) else "RULE"

    svc_normalized = resolve_target_service(exp)

    # 问题 2 优化：若当前 svc 规范化后为空（anysvc），
    # 但该等价集内其他证据或 CVE 关联了明确服务（通过 L2 CVE 交叉聚类），
    # 这里的 L1 key 虽然还是空，但我们可以尝试从 metadata.applicable_constraints.cve_ids 
    # 结合项目的 service_aliases 猜测一个隐含服务，防止完全丢失上下文。
    if not svc_normalized:
        cves = _extract_cve_ids(exp)
        if cves:
            svc_normalized = _infer_service_from_cves(cves)

    # failure_sub_dim：仅 PROCEDURAL_NEG 层有效。
    # FACTUAL 层用子键携带来源类型，避免 rule/llm schema 混淆。
    sub_dim = f"FACTUAL::{factual_source}" if knowledge_layer == "FACTUAL" else ""
    if knowledge_layer == "PROCEDURAL_NEG":
        content = exp.get("content", {})
        fsub = (
            content.get("failure_sub_dimension", "")
            or content.get("failure_sub_dim", "")
        )
        fdim = content.get("failure_dimension", "")
        fsub = _normalize_neg_sub_dimension(str(fsub), str(fdim))
        attack_phase = (
            exp.get("metadata", {}).get("attack_phase", "")
            or content.get("attack_phase", "")
        ).upper()
        phase_tier = "RECON" if attack_phase in _RECON_PHASES_SET else "ACTION"
        # 仅在 sub_dim 非空时携带阶段粗分桶，减少过度碎片化。
        sub_dim = f"{fsub}::{phase_tier}" if fsub else ""

    # Issue 2 修复：CONCEPTUAL 层 metadata.applicable_constraints = {} 导致 svc="" 全部落入同一 key。
    # 改为从 content.applicable_conditions.retrieval_triggers 提取服务名，
    # 同时用 content.pattern_type 区分漏洞型 vs 侦察型。
    if knowledge_layer == "CONCEPTUAL":
        c = exp.get("content", {})
        sub_dim = c.get("pattern_type", "")  # "vulnerability_pattern" | "recon_pattern"
        if not svc_normalized:
            rt = c.get("applicable_conditions", {}).get("retrieval_triggers", [])
            for trigger in rt:
                normalized = canonical_service_or_empty(str(trigger))
                if normalized and normalized in _CANONICAL_SERVICE_NAMES:
                    svc_normalized = normalized
                    break

    return (knowledge_layer, svc_normalized, sub_dim)


def _extract_cve_ids(exp: Dict[str, Any]) -> List[str]:
    """从经验中提取规范化 CVE IDs。优先读 applicable_constraints，再读 content。

    Issue 2 修复：CONCEPTUAL 层的 CVE 存放在
    content.applicable_conditions.retrieval_triggers 列表中，
    需额外扫描以正确提取并用于 SEC 集群签名。
    """
    meta = exp.get("metadata", {}).get("applicable_constraints", {})
    cves = meta.get("cve_ids", [])
    if not cves:
        # 兜底：内容层的 cve_ids（FACTUAL 层）
        content = exp.get("content", {})
        cves = content.get("cve_ids", [])
        if not cves:
            # cve_context.attempted（FACTUAL 的 LLM 来源记录）
            ctx = content.get("cve_context", {})
            cves = ctx.get("attempted", [])
        if not cves:
            # CONCEPTUAL 层：从 retrieval_triggers 中提取 CVE 格式的字符串
            ac = content.get("applicable_conditions") or {}
            rt = ac.get("retrieval_triggers", []) if isinstance(ac, dict) else []
            cves = [t for t in rt if re.match(r"CVE-\d{4}-\d+", t, re.IGNORECASE)]
        if not cves:
            # 全量兜底：从 content 文本中扫描 CVE（覆盖 PROCEDURAL_NEG 的 decision_rule/evidence 等字段）
            raw_blob = ""
            try:
                raw_blob = json.dumps(content, ensure_ascii=False, sort_keys=True)
            except Exception:
                raw_blob = str(content)
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", raw_blob, flags=re.IGNORECASE)
    if not cves:
        # 最终兜底：从整个经验对象里提取（兼容历史异构字段）
        raw_blob = ""
        try:
            raw_blob = json.dumps(exp, ensure_ascii=False, sort_keys=True)
        except Exception:
            raw_blob = str(exp)
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", raw_blob, flags=re.IGNORECASE)
    return normalize_cve_ids(cves)


def _extract_version_family(exp: Dict[str, Any]) -> str:
    """从经验中解析版本族。"""
    meta = exp.get("metadata", {}).get("applicable_constraints", {})
    ver = meta.get("target_version", "")
    if not ver:
        ver = exp.get("content", {}).get("target_version", "")
    return parse_version_family(ver)


def _make_cluster_id(
    knowledge_layer: str,
    target_service: str,
    sub_dim: str,
    version_family: str,
    cve_ids: List[str],
) -> str:
    """生成等价集唯一 ID。

    采用「可读前缀 + 稳定哈希后缀」避免截断引起的碰撞。
    """

    def _slug(text: str, max_len: int, fallback: str) -> str:
        s = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
        return s[:max_len] if s else fallback

    layer_slug = _slug(knowledge_layer, 20, "unknown")
    svc_slug = _slug(target_service, 24, "anysvc")
    sub_slug = _slug(sub_dim, 24, "any")
    ver_slug = _slug(version_family.replace(".", "_") if version_family else "", 18, "anyver")

    cve_sorted = sorted({str(c).upper() for c in cve_ids if str(c).strip()})
    cve_sig = _slug((cve_sorted[0] if cve_sorted else "nocve").replace("-", "_"), 20, "nocve")

    fingerprint = {
        "layer": str(knowledge_layer).upper(),
        "service": str(target_service).strip().lower(),
        "sub_dim": str(sub_dim).strip().lower(),
        "version_family": str(version_family).strip().lower(),
        "cve_ids": cve_sorted,
    }
    digest = hashlib.md5(
        json.dumps(fingerprint, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:8]

    return f"SEC_{layer_slug}_{svc_slug}_{sub_slug}_{ver_slug}_{cve_sig}_{digest}"


# ─────────────────────────────────────────────────────────────────────────────
# L2 软键：CVE 交集检测
# ─────────────────────────────────────────────────────────────────────────────

def _cve_overlap(cves_a: List[str], cves_b: List[str]) -> bool:
    """判断两个 CVE 列表是否有交集（L2 软键）。"""
    if not cves_a or not cves_b:
        return False
    return bool(set(cves_a) & set(cves_b))


# ─────────────────────────────────────────────────────────────────────────────
# L4 版本约束：版本族是否相同
# ─────────────────────────────────────────────────────────────────────────────

def _version_family_compatible(fam_a: str, fam_b: str) -> bool:
    """判断两个经验是否在同一版本族（L4 约束）。
    若任一版本族为空字符串，则视为兼容（不施加排除）。
    """
    if not fam_a or not fam_b:
        return True
    return fam_a == fam_b


# ─────────────────────────────────────────────────────────────────────────────
# 主入口：cluster_experiences()
# ─────────────────────────────────────────────────────────────────────────────

def cluster_experiences(
    experiences: List[Dict[str, Any]],
    enable_l4_version_split: bool = True,
) -> List[EquivalenceSet]:
    """对 Layer2 经验列表执行 SEC 分层聚类。

    算法流程：
      1. 为每条经验计算 L1 键（knowledge_layer, target_service, sub_dim）
      2. 按 L1 键分入候选组（dict[l1_key → list[exp]]）
      3. 在每个候选组内，按 L2 CVE 交集构建相似图
      4. 连通分量分析：CVE 有交集的经验归入同一 EquivalenceSet
      5. 按 L4 版本族进一步拆分（若启用）
      6. 过滤掉只有 1 条经验的等价集（无需融合）

    Args:
        experiences:             Layer2 输出的经验 dict 列表
        enable_l4_version_split: 是否按版本族拆分（默认 True）

    Returns:
        List[EquivalenceSet]，按 meets_fusion_threshold=True 的排前面
    """
    if not experiences:
        return []

    # ── 步骤 1：预计算每条经验的键
    exp_meta: List[Dict[str, Any]] = []
    for exp in experiences:
        l1_key = _extract_l1_key(exp)
        cve_ids = _extract_cve_ids(exp)
        ver_family = _extract_version_family(exp)
        lifecycle = exp.get("lifecycle_status", "active")
        exp_meta.append({
            "exp": exp,
            "exp_id": exp.get("exp_id", ""),
            "l1_key": l1_key,
            "cve_ids": cve_ids,
            "ver_family": ver_family,
            "lifecycle_status": lifecycle,
        })

    # 过滤非 active 的经验（archived/deleted 不参与新融合）
    active_meta = [m for m in exp_meta if m["lifecycle_status"] in ("active", "")]
    logger.info(f"SEC: 总经验数 {len(experiences)}，active 经验数 {len(active_meta)}")

    # ── 步骤 2：按 L1 键分组
    l1_groups: Dict[Tuple, List[Dict]] = defaultdict(list)
    for m in active_meta:
        l1_groups[m["l1_key"]].append(m)

    logger.info(f"SEC: L1 分组后得到 {len(l1_groups)} 个候选组")

    results: List[EquivalenceSet] = []

    for l1_key, group in l1_groups.items():
        knowledge_layer, target_service, sub_dim = l1_key

        if len(group) == 1:
            # 单条经验无需融合，但仍记录为大小=1的等价集
            m = group[0]
            cluster_id = _make_cluster_id(
                knowledge_layer, target_service, sub_dim,
                m["ver_family"], m["cve_ids"]
            )
            results.append(EquivalenceSet(
                cluster_id=cluster_id,
                knowledge_layer=knowledge_layer,
                target_service=target_service,
                failure_sub_dim=sub_dim,
                version_family=m["ver_family"],
                cve_ids=m["cve_ids"],
                exp_ids=[m["exp_id"]],
                experiences=[m["exp"]],
                trigger_level="L1",
                has_conflict=False,
            ))
            continue

        # ── 步骤 3：L2 CVE 交集 → 相似图（邻接表）
        n = len(group)
        adj: List[List[int]] = [[] for _ in range(n)]
        any_l2_match = False

        for i in range(n):
            for j in range(i + 1, n):
                cves_i = group[i]["cve_ids"]
                cves_j = group[j]["cve_ids"]

                # L4 版本族排除检查
                if enable_l4_version_split:
                    vi, vj = group[i]["ver_family"], group[j]["ver_family"]
                    if not _version_family_compatible(vi, vj):
                        # 版本族不同：不建立连边（强制分开）
                        logger.debug(
                            f"L4 版本族不兼容: {group[i]['exp_id']} ({vi}) "
                            f"vs {group[j]['exp_id']} ({vj})"
                        )
                        continue

                # L2 CVE 交集（BUG-2 修复：无CVE经验在同L1组内视为全联通）
                # 规则：若双方都有CVE，需交集非空才建边；
                #       若至少一方无CVE，无法通过CVE判断不同，视为可聚合。
                both_have_cve = bool(cves_i) and bool(cves_j)
                if both_have_cve:
                    if _cve_overlap(cves_i, cves_j):
                        adj[i].append(j); adj[j].append(i); any_l2_match = True
                else:
                    # METACOGNITIVE/CONCEPTUAL/RAG_EVAL/无CVE的NEG均走此分支
                    adj[i].append(j); adj[j].append(i); any_l2_match = True

        # ── 步骤 4：连通分量分析
        trigger_level = "L1+L2" if any_l2_match else "L1"
        visited = [False] * n
        components: List[List[int]] = []

        def _dfs(start: int) -> List[int]:
            stack, comp = [start], []
            while stack:
                node = stack.pop()
                if visited[node]:
                    continue
                visited[node] = True
                comp.append(node)
                stack.extend(adj[node])
            return comp

        for i in range(n):
            if not visited[i]:
                comp = _dfs(i)
                components.append(comp)

        logger.debug(
            f"L1 组 {l1_key}: {n} 条经验 → {len(components)} 个连通分量"
        )

        # ── 步骤 5：每个连通分量生成一个 EquivalenceSet
        for comp_indices in components:
            comp_metas = [group[idx] for idx in comp_indices]

            # 合并版本族（取最大公约）
            ver_families = set(m["ver_family"] for m in comp_metas if m["ver_family"])
            ver_family = list(ver_families)[0] if len(ver_families) == 1 else ""

            # 合并 CVE IDs（并集）
            all_cves: List[str] = []
            for m in comp_metas:
                for c in m["cve_ids"]:
                    if c not in all_cves:
                        all_cves.append(c)
            all_cves = sorted(all_cves)

            exp_ids = [m["exp_id"] for m in comp_metas]
            exp_list = [m["exp"] for m in comp_metas]

            cluster_id = _make_cluster_id(
                knowledge_layer, target_service, sub_dim, ver_family, all_cves
            )

            # 如果有多个版本族且启用 L4，标记 trigger_level
            tl = trigger_level
            if len(ver_families) > 1:
                tl = trigger_level  # 版本族不同的已被排除，到这里的都在同族

            eq_set = EquivalenceSet(
                cluster_id=cluster_id,
                knowledge_layer=knowledge_layer,
                target_service=target_service,
                failure_sub_dim=sub_dim,
                version_family=ver_family,
                cve_ids=all_cves,
                exp_ids=exp_ids,
                experiences=exp_list,
                trigger_level=tl,
                has_conflict=False,  # 冲突检测在 Phase 4 BCC 中处理
            )
            # 修复根因 2：注入 source_sessions 到 experiences 中供下层消费
            source_sessions = sorted(list(set(
                str(m["exp"].get("metadata", {}).get("source_session_id", "")).strip()
                for m in comp_metas if m["exp"].get("metadata", {}).get("source_session_id", "")
            )))
            for exp in eq_set.experiences:
                if "metadata" not in exp:
                    exp["metadata"] = {}
                exp["metadata"]["source_sessions"] = source_sessions

            results.append(eq_set)

    # ── 排序：满足层级融合阈值的排前面，然后按等价集大小降序
    results.sort(key=lambda s: (not s.meets_fusion_threshold, -len(s.experiences)))

    fusion_candidates = [s for s in results if s.meets_fusion_threshold]
    logger.info(
        f"SEC 完成: 共 {len(results)} 个等价集，"
        f"其中 {len(fusion_candidates)} 个满足层级融合阈值"
    )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：打印聚类摘要
# ─────────────────────────────────────────────────────────────────────────────

def summarize_clusters(clusters: List[EquivalenceSet]) -> str:
    """返回可读的聚类摘要字符串（用于日志/调试输出）。"""
    lines = [
        f"{'=' * 60}",
        f"SEC 聚类摘要  共 {len(clusters)} 个等价集",
        f"{'=' * 60}",
    ]
    for s in clusters:
        flag = "🔀 可融合" if s.meets_fusion_threshold else "  单条"
        lines.append(
            f"{flag}  [{s.cluster_id}]"
        )
        lines.append(
            f"      层级={s.knowledge_layer}  服务={s.target_service or '(未知)'}  "
            f"sub_dim={s.failure_sub_dim or '-'}  版本族={s.version_family or '-'}"
        )
        lines.append(
            f"      CVE={s.cve_ids}  经验数={len(s.experiences)}"
            f"  触发={s.trigger_level}"
        )
        for exp in s.experiences:
            lines.append(f"        · {exp.get('exp_id', '?')}")
    lines.append("=" * 60)
    return "\n".join(lines)
