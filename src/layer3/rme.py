"""
Phase 3 — Rule Merge Engine (RME)
==================================
对每个满足融合阈值的 WeightedEquivalenceSet 执行层特定的规则融合算法，
生成一条权威的 consolidated 级别经验（MergeResult）。

层特定融合策略（XPEC 实现流程文档 §7）：
  PROCEDURAL_NEG   — IF加权交集 + THEN多数投票(θ=0.4) + NOT并集 + next_actions步骤对齐
  PROCEDURAL_POS   — preconditions并集 + success_indicators加权Vote + next_actions权重最高版本
    FACTUAL          — 根据子键路由为 RULE/LLM 两类融合（统一层名，避免命名分裂）
  METACOGNITIVE    — key_lessons语义去重(rule_fingerprint) + decision_mistakes加权合并
  CONCEPTUAL       — core_insight LLM综合 + applicable_conditions频次加权

冲突检测（§10.2 矛盾评分）：
  outcome_diff：同一等价集内 success vs failure 经验的比例差
  Contra > 0.6 → has_conflict=True，仍融合但携带 minority_opinions

设计原则：
  - 确定性算法优先（不依赖LLM），LLM仅用于最终语言润色（可选）
  - 所有融合步骤记录到 merge_notes，支持审计
  - minority_opinions 保留未达阈值的少数意见，不丢失任何信息
"""

from __future__ import annotations

import hashlib
import logging
import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import (
    MergeResult,
    Provenance,
    EquivalenceSet,
    _fusion_threshold_for_layer,
)
from .sec import canonical_service_or_empty, resolve_target_service

logger = logging.getLogger(__name__)

# ── 融合阈值常量 ─────────────────────────────────────────────────────────────
_THETA_THEN    = 0.40   # THEN 建议的最低加权票数比例（§7 Step2）
_THETA_IF      = 0.35   # IF 条件的最低加权票数比例（weighted intersection）
_MINORITY_MAX  = 3      # 保留的少数意见最大数量


# ─────────────────────────────────────────────────────────────────────────────
# 辅助工具函数
# ─────────────────────────────────────────────────────────────────────────────




def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """按出现顺序去重，过滤空字符串。"""
    seen = set()
    out: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _weighted_vote(
    candidates: List[Any],
    weights: List[float],
    theta: float,
    total_w: float,
) -> Tuple[List[Any], List[Tuple[Any, float]]]:
    """对候选项执行加权多数投票。

    Returns:
        (winners, minorities)
        winners   — 加权票数比例 ≥ theta 的候选项列表
        minorities — 未达阈值的 (候选项, 加权比例) 列表（按比例降序）
    """
    vote_map: Dict[str, float] = defaultdict(float)
    item_map: Dict[str, Any]   = {}
    for item, w in zip(candidates, weights):
        key = str(item)
        vote_map[key] += w
        item_map[key] = item

    winners, minorities = [], []
    for key, w in sorted(vote_map.items(), key=lambda x: -x[1]):
        ratio = w / total_w
        if ratio >= theta:
            winners.append(item_map[key])
        else:
            minorities.append((item_map[key], round(ratio, 4)))
    return winners, minorities


def _weighted_union_top_n(
    candidates: List[Any],
    weights: List[float],
    total_w: float,
    min_weight_ratio: float = 0.03,
    top_n: int = 8,
) -> Tuple[List[Any], List[Tuple[Any, float]]]:
    """THEN/success_indicators 专用加权并集聚合（Issue 1/4 修复）。

    与 _weighted_vote 的区别：
      _weighted_vote  要求单项权重比例 ≥ θ（=0.40），多策略场景下极易全灭。
      _weighted_union_top_n 仅要求 ≥ min_weight_ratio（默认 3%），
      保留所有"有人提过"的项，按总支持权重降序排列，最多取 top_n 条为主列表，
      其余进入 alternatives。

    Args:
        candidates: 候选项列表（允许重复）
        weights: 对应每条候选项的经验权重
        total_w: 等价集总权重
        min_weight_ratio: 最低支持权重比例（默认 0.03，即 3%）
        top_n: 主列表最大保留数量（默认 8）

    Returns:
        (kept, alternatives)
        kept        — 支持权重 ≥ min_weight_ratio 且排名 ≤ top_n 的项
        alternatives — 超出 top_n 或低于阈值的 (项, 比例) 列表
    """
    vote_map: Dict[str, float] = defaultdict(float)
    item_map: Dict[str, Any] = {}
    for item, w in zip(candidates, weights):
        key = str(item)
        vote_map[key] += w
        item_map[key] = item

    sorted_items = sorted(vote_map.items(), key=lambda x: -x[1])
    kept: List[Any] = []
    alternatives: List[Tuple[Any, float]] = []
    for i, (key, w) in enumerate(sorted_items):
        ratio = w / total_w if total_w > 1e-9 else 0.0
        if ratio >= min_weight_ratio and i < top_n:
            kept.append(item_map[key])
        else:
            alternatives.append((item_map[key], round(ratio, 4)))
    return kept, alternatives


def _make_exp_id_hash(cluster_id: str) -> str:
    """为 consolidated 经验生成唯一 ID（问题⑥修复：统一使用10位哈希）。"""
    h = hashlib.md5(cluster_id.encode()).hexdigest()[:10]
    return f"exp_consolidated_{h}"


def _contradiction_score(wes: Any) -> float:
    """计算等价集内的矛盾评分 ∈ [0, 1]。

    策略：
      - PROCEDURAL_NEG：度量同一 cluster 内不同经验给出的 THEN 建议分歧度
      - FACTUAL：度量同一 CVE 的 exploitation_results 中 success vs failure 矛盾比
      - 其他层：度量 session_outcome 的 success/failure 混合程度

    返回值越大表示矛盾越严重。
    """
    # After refactor to session-vote model, contradiction scoring is moved out of
    # RME. Return 0.0 here to keep backward compatibility.
    return 0.0


def _build_provenance(cluster: EquivalenceSet) -> Provenance:
    """从 EquivalenceSet 构建简化的 Provenance 对象（不包含权重分布）。"""
    source_exp_ids = _dedupe_preserve_order(cluster.exp_ids or [])
    source_sessions = _dedupe_preserve_order(
        (e.get("metadata", {}).get("source_session_id", "")[:8] or "")
        for e in (cluster.experiences or [])
    )
    return Provenance(
        source_exp_ids=source_exp_ids,
        source_sessions=source_sessions,
        weight_distribution={},
        fusion_algorithm="XPEC-RME-v2.session_vote",
    )


def _resolve_wes_target_service(wes: Any) -> str:
    # Accept either WeightedEquivalenceSet or EquivalenceSet for backward compat.
    exps = []
    if hasattr(wes, "weighted_exps"):
        exps = [we.exp for we in wes.weighted_exps]
    elif hasattr(wes, "experiences"):
        exps = list(wes.experiences or [])

    vote: Dict[str, int] = defaultdict(int)
    for e in exps:
        svc = resolve_target_service(e)
        if svc:
            vote[svc] += 1
    if not vote:
        return ""
    return max(vote.items(), key=lambda kv: kv[1])[0]


# ─────────────────────────────────────────────────────────────────────────────
# PROCEDURAL_NEG 融合（§7.1.1）
# ─────────────────────────────────────────────────────────────────────────────

# CVE 模式（用于 THEN 意图去重时排除 CVE 条目）
_INTENT_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# P1 Fix 5: 动作意图分类规则（关键词 → 意图标签）
_INTENT_KEYWORDS: List[Tuple[str, List[str]]] = [
    # 规则顺序：越具体越靠前，匹配到就返回
    ("PORT_SCAN",        ["nmap", "端口扫描", "port scan", "port-scan"]),
    ("PATH_ENUM",        ["/console", "/wls-wsat", "/bea_wls", "/wls9",
                          "路径枚举", "endpoint", "端点枚举", "枚举路径"]),
    ("HTTP_FINGERPRINT", ["server header", "http 头", "http header", "版本探测", "-i http"]),
]


def _action_intent_category(then_str: str) -> str:
    """返回 THEN 条目的动作意图类别。空字符串 = 无法分类（保留原条目）。"""
    s = then_str.lower()
    for intent, kws in _INTENT_KEYWORDS:
        if any(kw in s for kw in kws):
            return intent
    return ""


def _action_intent_dedup(then_items: List[str]) -> List[str]:
    """对 THEN 条目做动作意图级去重（P1 Fix 5）。

    策略：
    - 含 CVE ID 的条目已在 Step 2b 去重，本步骤只处理不含 CVE 的泛化条目
    - 按动作意图分组，同组内保留「最具体」（最长）的一条
    - 无法分类的条目直接保留（不做去重）

    例：
      PORT_SCAN 组：「nmap 确认端口 7001/7002/9002」vs「nmap -sV -p 7000-7010,8000-8010 详细扫描」
      → 保留后者（更长、更具体）
      PATH_ENUM 组：三条路径枚举条目 → 保留含最多路径名的一条
    """
    intent_best: Dict[str, str] = {}   # intent → 当前最佳 then_str

    # 第一遍：找每个意图分组内最长的条目
    for t in then_items:
        if _INTENT_CVE_RE.search(t):
            continue   # CVE 条目跳过
        cat = _action_intent_category(t)
        if not cat:
            continue
        if cat not in intent_best or len(t) > len(intent_best[cat]):
            intent_best[cat] = t

    # 第二遍：重建结果，每个意图组只保留最佳版本（按原有顺序首次出现时插入）
    final: List[str] = []
    added_intents: set = set()
    for t in then_items:
        if _INTENT_CVE_RE.search(t):
            final.append(t)
            continue
        cat = _action_intent_category(t)
        if not cat:
            final.append(t)
        elif cat not in added_intents:
            final.append(intent_best[cat])   # 插入该组的最佳条目
            added_intents.add(cat)
        # else: 同组较差条目跳过
    return final


def _merge_procedural_neg(wes: Any) -> Tuple[Dict, List[Dict], List[str]]:
    """基于会话投票的 PROCEDURAL_NEG 融合实现。

    主要变更：抛弃经验权重，改为按独立 session 计票（每个 session 最多一票）。
    Returns: (fused_content, minority_opinions, merge_notes)
    """
    notes: List[str] = []

    # 支持 WeightedEquivalenceSet 或 EquivalenceSet 两种输入，向后兼容
    if hasattr(wes, "weighted_exps"):
        cluster = wes.cluster
        exps = [we.exp for we in wes.weighted_exps]
    else:
        cluster = wes
        exps = list(cluster.experiences or [])

    # 会话集合（独立会话数）
    def _session_id(exp: Dict[str, Any]) -> str:
        return (exp.get("metadata", {}).get("source_session_id", "") or "")[:8]

    sessions = _dedupe_preserve_order(_session_id(e) for e in exps if _session_id(e))
    n_sessions = max(1, len(sessions))

    # Step 1: IF — 选择被最多独立 session 支持的 IF 文本
    if_map: Dict[str, set] = defaultdict(set)
    for e in exps:
        dr = e.get("content", {}).get("decision_rule", {})
        if_text = (dr.get("IF", "") or "").strip()
        if if_text:
            if_map[if_text].add(_session_id(e))
    merged_if = ""
    if if_map:
        merged_if = max(if_map.items(), key=lambda kv: len(kv[1]))[0]
        notes.append(f"IF: 由 {len(if_map)} 个候选 IF，选取支持最多的版本")

    # Step 2: THEN — 按 session 支持度做 union_top_n（min_ratio=3%）
    then_support: Dict[str, set] = defaultdict(set)
    for e in exps:
        dr = e.get("content", {}).get("decision_rule", {})
        then_list = dr.get("THEN", [])
        if isinstance(then_list, str):
            then_list = [then_list]
        sid = _session_id(e)
        for t in then_list:
            if t:
                then_support[str(t)].add(sid)

    # 按支持会话数排序，保留支持率 >= min_ratio 且排名前 top_n
    min_ratio = 0.03
    top_n = 8
    sorted_then = sorted(then_support.items(), key=lambda kv: -len(kv[1]))
    merged_then: List[str] = []
    then_minorities: List[Tuple[str, float]] = []
    for i, (t, sids) in enumerate(sorted_then):
        ratio = len(sids) / n_sessions
        if ratio >= min_ratio and i < top_n:
            merged_then.append(t)
        else:
            then_minorities.append((t, round(ratio, 4)))
    notes.append(f"THEN: union_top_n 保留 {len(merged_then)} 条，{len(then_minorities)} 条进入 alternatives")

    # ── Step 2b：CVE 级去重（同一 CVE 多条 THEN 只保留权重最高那条）────────────
    # _weighted_union_top_n 已按支持权重降序排列，首次遇到某 CVE 的条目即为最高权重版本，
    # 后续含同一 CVE 的措辞变体直接跳过（加入 then_minorities 的 supporting_count 计数）。
    # 多 CVE 组合条目（如"CVE-2019-2725 或 CVE-2020-14882"）同时标记对应的所有 CVE 为已覆盖。
    _CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    seen_cves: set = set()
    # CVE 级去重（按出现顺序保留首次覆盖该 CVE 的条目）
    deduped_then: List[str] = []
    for t in merged_then:
        cves_in_t = {c.upper() for c in _CVE_RE.findall(t)}
        if cves_in_t:
            new_cves = cves_in_t - seen_cves
            if new_cves:
                deduped_then.append(t)
                seen_cves.update(cves_in_t)
        else:
            deduped_then.append(t)
    removed_count = len(merged_then) - len(deduped_then)
    if removed_count > 0:
        notes.append(f"THEN: CVE 级去重移除 {removed_count} 条重复 CVE 条目，最终 {len(deduped_then)} 条")
    merged_then = deduped_then

    # 动作意图级去重
    before_intent = len(merged_then)
    merged_then = _action_intent_dedup(merged_then)
    intent_removed = before_intent - len(merged_then)
    if intent_removed > 0:
        notes.append(f"THEN: 动作意图级去重移除 {intent_removed} 条近义条目，最终 {len(merged_then)} 条")

    # NOT: 按 session 支持度投票（theta=0.20）
    not_support: Dict[str, set] = defaultdict(set)
    for e in exps:
        dr = e.get("content", {}).get("decision_rule", {})
        not_val = dr.get("NOT", "")
        sid = _session_id(e)
        if isinstance(not_val, list):
            for n in not_val:
                if n:
                    not_support[str(n)].add(sid)
        elif not_val:
            not_support[str(not_val)].add(sid)

    not_set: List[str] = []
    not_minorities: List[Tuple[str, float]] = []
    theta = 0.20
    for t, sids in sorted(not_support.items(), key=lambda kv: -len(kv[1])):
        ratio = len(sids) / n_sessions
        if ratio >= theta:
            not_set.append(t)
        else:
            not_minorities.append((t, round(ratio, 4)))
    # Fallback：若为空则保留支持最多的一条
    if not not_set and not_support:
        best = max(not_support.items(), key=lambda kv: len(kv[1]))
        not_set = [best[0]]
        not_minorities.insert(0, (best[0], round(len(best[1]) / n_sessions, 4)))
    notes.append(f"NOT: 会话投票(θ=0.20)保留 {len(not_set)} 条共识项，丢弃 {len(not_minorities)} 条")

    # next_actions: 选取最高置信度经验作为主导版本，记录差异备选
    def _conf(e: Dict[str, Any]) -> float:
        try:
            return float(e.get("confidence", 0.0) or 0.0)
        except Exception:
            return 0.0

    best_exp = max(exps, key=_conf)
    merged_next_actions = (
        best_exp.get("content", {}).get("decision_rule", {}).get("next_actions", [])
    )
    alt_next: List[Dict] = []
    for e in exps:
        if e.get("exp_id") == best_exp.get("exp_id"):
            continue
        na = e.get("content", {}).get("decision_rule", {}).get("next_actions", [])
        if na and na != merged_next_actions:
            alt_next.append({
                "source_exp_id": e.get("exp_id"),
                "support_sessions": len({ _session_id(e) }),
                "next_actions": na,
            })
    notes.append(f"next_actions: 主导版本 from {best_exp.get('exp_id')}，{len(alt_next)} 个备选")

    dom_content = best_exp.get("content", {})
    source_counter = Counter(
        str((e.get("content", {}) or {}).get("decision_rule_source", "unknown"))
        for e in exps
    )

    fused_content = {
        "failure_sub_dimension": dom_content.get("failure_sub_dimension", ""),
        "failure_dimension": dom_content.get("failure_dimension", ""),
        "decision_rule_source_breakdown": {k: int(v) for k, v in source_counter.items() if k},
        "decision_rule": {
            "IF": merged_if,
            "THEN": merged_then,
            "NOT": not_set,
            "next_actions": merged_next_actions,
            "alternatives": alt_next[:3],
        },
        "failure_pattern_detail": dom_content.get("failure_pattern_detail", {}),
        "avoid_pattern": dom_content.get("avoid_pattern", ""),
        "fused_from_count": len(exps),
    }

    minority_opinions = [
        {"type": "THEN_minority", "value": item, "support_ratio": r}
        for item, r in then_minorities[:_MINORITY_MAX]
    ]

    return fused_content, minority_opinions, notes


# ─────────────────────────────────────────────────────────────────────────────
# PROCEDURAL_POS 融合
# ─────────────────────────────────────────────────────────────────────────────

def _merge_procedural_pos(wes: WeightedEquivalenceSet) -> Tuple[Dict, List[Dict], List[str]]:
    """preconditions并集 + success_indicators投票 + command_template取主导。"""
    notes: List[str] = []
    total_w = _total_weight(wes)

    # Issue 4 修复：preconditions 改用 weighted_union_top_n 过滤低权重噪声。
    # 避免纯并集将所有单经验冗余条件都堆入 preconditions，
    # 只保留支持权重 ≥ 15% 的条件（10条经验的集群中需被 ≥2 条支持）。
    pc_all, pc_w_all = [], []
    for we in wes.weighted_exps:
        w = _exp_weight(we)
        for p in we.exp.get("content", {}).get("preconditions", []):
            if p:
                pc_all.append(p)
                pc_w_all.append(w)
    precond_set, _ = _weighted_union_top_n(
        pc_all, pc_w_all, total_w, min_weight_ratio=0.15, top_n=10
    )
    # Fallback：若全部条件都因稀疏而被过滤，退化为权重最高的 top-3 并集
    if not precond_set and pc_all:
        precond_set, _ = _weighted_union_top_n(
            pc_all, pc_w_all, total_w, min_weight_ratio=0.0, top_n=3
        )

    # success_indicators 加权投票
    si_all, si_w_all = [], []
    for we in wes.weighted_exps:
        for si in we.exp.get("content", {}).get("success_indicators", []):
            si_all.append(si)
            si_w_all.append(_exp_weight(we))
    # Issue 4 修复：success_indicators 改用 weighted_union_top_n（min=5%，top=5），
    # 彻底解决 θ=0.40 高阈值导致所有成功信号被丢弃的问题。
    merged_si, si_min = _weighted_union_top_n(
        si_all, si_w_all, total_w, min_weight_ratio=0.05, top_n=5
    )

    # command_template：取主导经验版本
    best_we = max(wes.weighted_exps, key=_exp_weight)
    dom_content = best_we.exp.get("content", {})

    notes.append(f"preconditions: {len(precond_set)} 条并集")
    notes.append(f"success_indicators: {len(merged_si)} 条超阈值")

    # 收集所有唯一的 next_actions（POS层 next_actions 字段名为攻击步骤链）
    all_na = dom_content.get("next_actions", dom_content.get("decision_rule", {}).get("next_actions", []))

    fused_content = {
        "command_template":   dom_content.get("command_template", ""),
        "tool_name":          dom_content.get("tool_name", ""),
        "attack_phase":       dom_content.get("attack_phase", ""),
        "preconditions":      precond_set,
        "success_indicators": merged_si,
        "next_actions":       all_na,
        "fused_from_count":   len(wes.weighted_exps),
    }

    minority_opinions = [
        {"type": "success_indicator_minority", "value": item, "weight": w}
        for item, w in si_min[:_MINORITY_MAX]
    ]
    return fused_content, minority_opinions, notes


# ─────────────────────────────────────────────────────────────────────────────
# FACTUAL(RULE) 融合（端口/服务发现聚合）
# ─────────────────────────────────────────────────────────────────────────────

_FACTUAL_RULE_STRONG_KEYS = {
    "cve_confirmed",
    "cve_mentioned",
    "service_version",
    "nikto_finding",
    "smb_share",
    "http_header_server",
    "http_header_x-powered-by",
    "http_header_x-generator",
    "privilege_root",
    "shell_root",
    "flag_captured",
    "suid_binary",
    "file_shadow",
    "file_passwd",
    "file_read_passwd",
    "file_read_shadow",
    "auth_bypass",
    "sudo_nopasswd",
}


def _factual_rule_has_substance(fused_content: Dict[str, Any]) -> bool:
    """判断规则 FACTUAL 融合结果是否具备可复用的稳定事实。"""
    facts = fused_content.get("discovered_facts", [])
    if not isinstance(facts, list) or not facts:
        return False

    for fact in facts:
        if not isinstance(fact, dict):
            continue
        key = str(fact.get("key", "")).strip().lower()
        value = str(fact.get("value", "")).strip()
        version = str(fact.get("version", "")).strip()
        if not (value or version):
            continue
        if key in _FACTUAL_RULE_STRONG_KEYS:
            return True
        if "version" in key or "cve" in key or "vulnerab" in key:
            return True
    return False


def _factual_llm_has_substance(fused_content: Dict[str, Any]) -> bool:
    """判断 LLM FACTUAL 融合结果是否具备最小可验证语义。"""
    version = str(fused_content.get("target_version", "")).strip().lower()
    has_version = bool(version and version not in {"unknown", "none", "null", "n/a"})

    cve_context = fused_content.get("cve_context", {})
    attempted = []
    if isinstance(cve_context, dict):
        attempted = [str(c).strip() for c in cve_context.get("attempted", []) if str(c).strip()]

    cve_map = fused_content.get("cve_exploitation_map", {})
    has_cve_map = isinstance(cve_map, dict) and any(str(k).strip() for k in cve_map.keys())

    return has_version or bool(attempted) or has_cve_map


def _merge_factual_rule(wes: WeightedEquivalenceSet) -> Tuple[Optional[Dict[str, Any]], List[Dict], List[str]]:
    """将多个 session 的 discovered_facts 按 key 去重聚合，统计发现频次。"""
    notes: List[str] = []

    # 以 (key, value) 为聚合键，统计出现次数和支持权重
    fact_map: Dict[str, Dict] = {}   # key: str → {fact_dict, count, total_w}

    for we in wes.weighted_exps:
        facts = we.exp.get("content", {}).get("discovered_facts", [])
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            fkey = f"{fact.get('key','')}::{fact.get('value','')}"
            if fkey not in fact_map:
                fact_map[fkey] = {
                    "key":            fact.get("key", ""),
                    "value":          fact.get("value", ""),
                    "service":        fact.get("service", ""),
                    "version":        fact.get("version", ""),
                    "occurrence_count":   0,
                    "supporting_weight":  0.0,
                    "source_exp_ids":     [],
                }
            fact_map[fkey]["occurrence_count"] += 1
            fact_map[fkey]["supporting_weight"] += round(_exp_weight(we), 4)
            fact_map[fkey]["source_exp_ids"].append(we.exp_id)

    # 按支持权重降序排列
    merged_facts = sorted(
        fact_map.values(),
        key=lambda x: -x["supporting_weight"],
    )
    notes.append(f"discovered_facts: {len(merged_facts)} 个唯一发现，来自 {len(wes.weighted_exps)} 条经验")

    # 服务类型取主导经验
    best_we = max(wes.weighted_exps, key=_exp_weight)
    dom_content = best_we.exp.get("content", {})

    fused_content = {
        "service_type":      dom_content.get("service_type", ""),
        "discovered_facts":  merged_facts,
        "attack_phase":      dom_content.get("attack_phase", ""),
        "fused_from_count":  len(wes.weighted_exps),
    }
    if not _factual_rule_has_substance(fused_content):
        notes.append("FACTUAL-RULE: 全为瞬态事实（无稳定语义发现），跳过融合")
        return None, [], notes
    return fused_content, [], notes


# ─────────────────────────────────────────────────────────────────────────────
# FACTUAL(LLM) 融合（CVE 利用地图汇聚）（§7.1.2）
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_cve_status(status: str) -> str:
    """归并语义近似的CVE状态标签，防止 patched-HTTP500/patched-requires-auth 等
    变体分散投票，导致 failure-unknown 以单票多数赢得错误结论。

    归并规则（原始标签 → 语义类别）：
      包含 "patched"          → "patched"
      包含 "failure"/"failed" → "failure"
      包含 "partial"          → "partial"
      包含 "success"          → "success"

    投票时使用归并类别决定胜出方向，输出时保留原始最高权重标签作为展示值。
    """
    s = status.lower()
    if "patched" in s:
        return "patched"
    if "failure" in s or "failed" in s:
        return "failure"
    if "partial" in s:
        return "partial"
    if "success" in s:
        return "success"
    return status


def _build_cve_commands_map(
    wes_list: "List[WeightedEquivalenceSet]",
) -> Dict[str, List[str]]:
    """从所有 PROCEDURAL_NEG 等价集中提取 CVE → 可执行命令 映射（P0 Fix 3）。

    策略：
    1. 取每个 PROCEDURAL_NEG WES 的 cluster.cve_ids 确定该集群覆盖的 CVE
       若 cluster.cve_ids 为空，则从 THEN 条目中提取 CVE ID
    2. 取主导经验（weight_effective 最高）的 next_actions[].command
    3. 建立 cve_id → [command, ...] 映射，供 FACTUAL(LLM来源) 融合时回填
    """
    _cve_pat = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    cve_commands: Dict[str, List[str]] = defaultdict(list)

    for wes in wes_list:
        if wes.cluster.knowledge_layer != "PROCEDURAL_NEG":
            continue

        # 确定该集群覆盖的 CVE 列表
        cluster_cves: set = set(wes.cluster.cve_ids or [])
        if not cluster_cves:
            # fallback：从各经验的 THEN 条目中提取
            for we in wes.weighted_exps:
                dr = we.exp.get("content", {}).get("decision_rule", {})
                for t in dr.get("THEN", []):
                    for m in _cve_pat.findall(str(t)):
                        cluster_cves.add(m.upper())

        if not cluster_cves:
            continue

        # 取主导经验的 next_actions 命令
        best_we = max(wes.weighted_exps, key=lambda x: x.weight_effective)
        dr = best_we.exp.get("content", {}).get("decision_rule", {})
        for na in dr.get("next_actions", []):
            cmd = (na.get("command") or "").strip()
            if cmd and len(cmd) > 5:
                for cve in cluster_cves:
                    cve_upper = cve.upper()
                    if cmd not in cve_commands[cve_upper]:
                        cve_commands[cve_upper].append(cmd)

    return dict(cve_commands)


def _merge_factual_llm(
    wes: WeightedEquivalenceSet,
    cve_commands_map: Optional[Dict[str, List[str]]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[Dict], List[str]]:
    """CVE地图合并：exploitation_results按CVE加权投票（语义归并）+ ineffective_vectors并集。"""
    notes: List[str] = []
    total_w = _total_weight(wes)

    # ── cve_attempted 并集（含出现次数）────────────────────────────────
    cve_attempt_count: Counter = Counter()
    for we in wes.weighted_exps:
        ctx = we.exp.get("content", {}).get("cve_context", {})
        for cve in ctx.get("attempted", []):
            cve_attempt_count[cve] += 1
    cve_attempted = sorted(cve_attempt_count.keys())

    # ── exploitation_results：按 CVE 加权投票（语义归并多数票）──────────
    # 修复说明：原实现直接对原始标签字面量做最大值，导致 patched-HTTP500(31%)+
    # patched-requires-auth(24%) 合计 55% 却败给 failure-unknown(44%) 的单票多数。
    # 正确做法：先将标签归并为语义类别（_normalize_cve_status），用归并类别决定
    # 胜出方向，再从胜出类别中选权重最高的原始标签作为 consensus_status 展示值。
    #
    # 两套并行累计：
    #   cve_norm_votes — 以归并类别累计权重，用于决定胜出类别
    #   cve_orig_votes — 以原始标签累计权重，用于 vote_breakdown 展示及最优原始标签选取
    cve_norm_votes: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    cve_orig_votes: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for we in wes.weighted_exps:
        ctx = we.exp.get("content", {}).get("cve_context", {})
        for cve, status in ctx.get("exploitation_results", {}).items():
            w = _exp_weight(we)
            cve_norm_votes[cve][_normalize_cve_status(status)] += w
            cve_orig_votes[cve][status] += w

    merged_exploitation_results: Dict[str, Any] = {}
    for cve in cve_norm_votes:
        norm_vote = cve_norm_votes[cve]
        orig_vote = cve_orig_votes[cve]
        # 1. 胜出的语义类别（如 "patched"）
        winning_norm = max(norm_vote, key=norm_vote.__getitem__)
        all_norm_total = sum(norm_vote.values())
        # 2. 在胜出类别下，取权重最高的原始标签作为展示标签
        winning_orig = max(
            (s for s in orig_vote if _normalize_cve_status(s) == winning_norm),
            key=orig_vote.__getitem__,
            default=winning_norm,
        )
        all_orig_total = sum(orig_vote.values())
        merged_exploitation_results[cve] = {
            "consensus_status":   winning_orig,
            "consensus_category": winning_norm,
            "confidence":         round(norm_vote[winning_norm] / all_norm_total, 4),
            "vote_breakdown":     {k: round(v / all_orig_total, 4) for k, v in orig_vote.items()},
            "evidence_count":     sum(
                1 for we in wes.weighted_exps
                if cve in we.exp.get("content", {}).get("cve_context", {}).get("exploitation_results", {})
            ),
        }

    # ── known_ineffective_vectors 并集 + 验证计数 ──────────────────────
    vector_verify: Dict[str, Dict] = {}
    for we in wes.weighted_exps:
        ctx = we.exp.get("content", {}).get("cve_context", {})
        for v in ctx.get("known_ineffective_vectors",
                we.exp.get("content", {})
                .get("applicable_constraints", {})
                .get("known_ineffective_vectors", [])):
            if v not in vector_verify:
                vector_verify[v] = {"path": v, "verified_count": 0, "total_weight": 0.0}
            vector_verify[v]["verified_count"] += 1
            vector_verify[v]["total_weight"] += round(_exp_weight(we), 4)

    # ── unexplored CVE 并集（可供后续 Agent 探索）─────────────────────
    unexplored_set: List[str] = []
    for we in wes.weighted_exps:
        ctx = we.exp.get("content", {}).get("cve_context", {})
        for u in ctx.get("unexplored", []):
            if u not in unexplored_set and u not in cve_attempted:
                unexplored_set.append(u)

    notes.append(f"CVE尝试数: {len(cve_attempted)}，exploitation状态已投票合并")
    notes.append(f"known_ineffective_vectors: {len(vector_verify)} 条并集")

    best_we = max(wes.weighted_exps, key=_exp_weight)
    dom_content = best_we.exp.get("content", {})

    # P0 Fix 3a: 回填 exploit_commands 和 known_ineffective_endpoints 到每个 CVE 条目
    # exploit_commands 来自 PROCEDURAL_NEG 集群的 next_actions，由 _build_cve_commands_map 预构建
    # known_ineffective_endpoints 提升到 CVE 条目级别（每个 CVE 共享同一目标的无效端点列表）
    # P0 Fix 3b: 从 cve_context 中移除与 cve_exploitation_map CVE 条目重复的字段
    ineffective_endpoints_list = list(vector_verify.values())   # 共享端点列表
    _cmd_map = cve_commands_map or {}
    for cve, cve_data in merged_exploitation_results.items():
        cve_upper = cve.upper()
        cve_data["exploit_commands"]            = _cmd_map.get(cve_upper, [])
        cve_data["known_ineffective_endpoints"] = ineffective_endpoints_list

    notes.append(
        f"exploit_commands 回填: {sum(1 for d in merged_exploitation_results.values() if d.get('exploit_commands'))} 个 CVE 有命令"
    )

    # cve_exploitation_map：富信息顶层字段（同 cve_context.exploitation_results）
    # cve_context 保留向后兼容，但移除与 cve_exploitation_map 重复的子字段
    fused_content = {
        "target_service":       dom_content.get("target_service", ""),
        "target_version":       dom_content.get("target_version", ""),
        "cve_exploitation_map": merged_exploitation_results,    # 顶层：包含 exploit_commands + known_ineffective_endpoints
        "cve_unexplored":       unexplored_set,                 # 待探索 CVE 顶层字段
        "cve_context": {
            "attempted":        cve_attempted,
            "attempt_counts":   dict(cve_attempt_count),
            "unexplored":       unexplored_set,
            # 注：exploitation_results 和 known_ineffective_vectors 已提升到
            # cve_exploitation_map 的每个 CVE 条目下，此处删除以消除冗余
        },
        "exploitation_status": "fused",
        "fused_from_count":   len(wes.weighted_exps),
    }
    if not _factual_llm_has_substance(fused_content):
        notes.append("FACTUAL-LLM: 无版本且无CVE语义，跳过融合")
        return None, [], notes
    return fused_content, [], notes


def _is_factual_llm_wes(wes: WeightedEquivalenceSet) -> bool:
    """判断 FACTUAL 等价集是否应走 LLM 融合分支。"""
    # EquivalenceSet 当前字段名为 failure_sub_dim；兼容历史命名 failure_sub_dimension。
    sub_dim = str(
        getattr(wes.cluster, "failure_sub_dim", "")
        or getattr(wes.cluster, "failure_sub_dimension", "")
        or ""
    ).upper()
    if sub_dim.endswith("LLM"):
        return True
    if sub_dim.endswith("RULE"):
        return False

    # 兼容旧数据：若缺少 sub_dim，则从内容结构兜底判断
    for we in wes.weighted_exps:
        content = we.exp.get("content", {})
        extraction_source = str(we.exp.get("metadata", {}).get("extraction_source", "")).lower()
        if extraction_source == "llm":
            return True
        if "cve_context" in content or "cve_exploitation_map" in content:
            return True
    return False


def _merge_factual(
    wes: WeightedEquivalenceSet,
    cve_commands_map: Optional[Dict[str, List[str]]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[Dict], List[str]]:
    """FACTUAL 统一入口：按子键路由到 RULE 或 LLM 融合实现。"""
    if _is_factual_llm_wes(wes):
        return _merge_factual_llm(wes, cve_commands_map)
    return _merge_factual_rule(wes)


# ─────────────────────────────────────────────────────────────────────────────
# METACOGNITIVE 融合（§7.1.3）
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_fingerprint(fp: str) -> str:
    """规范化 rule_fingerprint 用于语义合并。

    处理策略：
    1. 转大写 + 去除多余空白
    2. 変体语义等价：如 RECON_BEFORE_EXPLOIT 和 VALIDATE_RECON 均归并到 RECON
    3. 保留颜粒度前缀，截断通用后缀
    """
    fp = fp.upper().strip()
    # 语义归一：将示意相同行为模式的工具查证指纹合并
    _SEMANTIC_MAP = {
        "VALIDATE_RECON":         "RECON_BEFORE_EXPLOIT",
        "VERSION_DETECT_FIRST":   "RECON_BEFORE_EXPLOIT",
        "VERSION_CHECK_FIRST":    "RECON_BEFORE_EXPLOIT",
        "VALIDATE_TOOL":          "TOOL_VALIDATION",
        "CHECK_TOOL_OUTPUT":      "TOOL_VALIDATION",
        "VERIFY_TOOL_RESULT":     "TOOL_VALIDATION",
        "AVOID_BLIND_EXECUTION":  "BLIND_EXECUTION_GUARD",
        "NO_BLINDEXEC":           "BLIND_EXECUTION_GUARD",
        # P1修复：META 近似重复规则组 ─ 触发条件几乎相同的规则合并到统一规范名
        # LOOPBACK 组（TOPO_NETCHECK ≈ LOOPBACK_NETWORK_TEST，90% 重复）
        "TOPO_NETCHECK":          "LOOPBACK_NETWORK_TEST",
        # FAILURE 响应组（三条规则 IF 相同，THEN 目的地不同 → 合并为带优先级列表的一条）
        "FAILURE_BREAKER":        "FAILURE_PIVOT_STRATEGY",
        "FAILURE_PIVOT":          "FAILURE_PIVOT_STRATEGY",
        "PIVOT_ON_DEFENSE":       "FAILURE_PIVOT_STRATEGY",
        # 无进展响应组（PATH_SWITCH ≈ COMMAND_PLANNING，触发条件「连续3次无进展」相同）
        "PATH_SWITCH":            "PATH_SWITCH_ON_FAILURE",
        "COMMAND_PLANNING":       "PATH_SWITCH_ON_FAILURE",
    }
    return _SEMANTIC_MAP.get(fp, fp)


# FULLWIDTH COLON（中文：）优先，ASCII colon 备用 — 与 Layer2 LLM 输出格式一致
_FP_SEPARATORS = ("\uff1a", ":")


def _extract_fp_from_lesson(lesson: str) -> str:
    """从 key_lesson 字符串前缀提取语义 rule_fingerprint 标签。

    Layer2 LLM 输出的 key_lessons 格式为：
      "FINGERPRINT_LABEL：IF ... THEN ..."
    其中 FINGERPRINT_LABEL 是全大写英文字母+下划线的规则名称。

    此函数独立于 decision_mistakes 下标对齐，直接从字符串解析，
    确保即使 decision_mistakes 为空或错位时去重仍可正确生效。
    """
    for sep in _FP_SEPARATORS:
        if sep in lesson:
            prefix = lesson.split(sep, 1)[0].strip()
            # 合法 fingerprint：全ASCII大写字母+下划线+连字符，长度在 [3, 50] 之间
            cleaned = prefix.replace("_", "").replace("-", "")
            if 3 <= len(prefix) <= 50 and cleaned.isalpha() and cleaned == cleaned.upper():
                return prefix.upper()
    return ""


def _merge_metacognitive(wes: WeightedEquivalenceSet) -> Tuple[Dict, List[Dict], List[str]]:
    """key_lessons按rule_fingerprint去重 + decision_mistakes加权合并。"""
    notes: List[str] = []
    total_w = _total_weight(wes)

    # ── key_lessons 按语义 fingerprint 去重，保留最具代表性的版本 ────
    # 修复说明：原实现依赖 decision_mistakes[i].rule_fingerprint 的下标对齐，
    # 但该字段存储的是随机哈希（如 "b01edae9a204"），导致每条都唯一、去重永远不触发。
    # 正确做法：从 key_lesson 字符串本身提取前缀标签（如 "RECON_BEFORE_EXPLOIT"），
    # 完全不依赖 decision_mistakes 的结构或对齐关系。
    fp_best: Dict[str, Dict] = {}   # normalized_fingerprint → {text, weight, source_exp_id}

    for we in wes.weighted_exps:
        content = we.exp.get("content", {})
        key_lessons_raw = content.get("key_lessons", [])
        w = _exp_weight(we)

        for lesson_text in key_lessons_raw:
            if not lesson_text:
                continue
            lesson_str = str(lesson_text)

            # 从字符串前缀提取语义指纹（如 "RECON_BEFORE_EXPLOIT"）
            # 不依赖 decision_mistakes[i].rule_fingerprint 的下标对齐
            fp_raw = _extract_fp_from_lesson(lesson_str)
            if not fp_raw:
                # 无法解析前缀时，用截断文本作 fallback（仍可去除完全重复的字面量）
                fp_raw = lesson_str[:40]
            fp = _normalize_fingerprint(fp_raw)

            if fp not in fp_best or fp_best[fp]["weight"] < w:
                fp_best[fp] = {
                    "rule_fingerprint": fp,
                    "rule":             lesson_str,
                    "lesson":           lesson_str,
                    "weight":           round(w, 4),
                    "source_exp_id":    we.exp_id,
                    "occurrence_count": 0,
                }
            fp_best[fp]["occurrence_count"] = fp_best[fp].get("occurrence_count", 0) + 1

    # 按出现次数✕权重排序
    merged_lessons = sorted(
        fp_best.values(),
        key=lambda x: -(x["occurrence_count"] * x["weight"]),
    )
    notes.append(f"key_lessons: {len(fp_best)} 个唯一规则（从 {len(wes.weighted_exps)} 条经验去重）")

    # ── decision_mistakes：取出现≥2次 或 权重最高的 ──────────────────
    mistake_votes: Dict[str, Dict] = {}
    for we in wes.weighted_exps:
        for m in we.exp.get("content", {}).get("decision_mistakes", []):
            fp = m.get("rule_fingerprint", m.get("mistake", "")[:20])
            if fp not in mistake_votes:
                mistake_votes[fp] = {**m, "vote_weight": 0.0, "vote_count": 0}
            mistake_votes[fp]["vote_weight"] += _exp_weight(we)
            mistake_votes[fp]["vote_count"]  += 1

    # 按投票权重降序，取 top-5
    merged_mistakes = sorted(
        mistake_votes.values(),
        key=lambda x: -x["vote_weight"],
    )[:5]
    notes.append(f"decision_mistakes: 保留 top-{len(merged_mistakes)} 个")

    # ── missed_opportunities 并集（去重）────────────────────────────
    missed_set: List[str] = []
    for we in wes.weighted_exps:
        for m in we.exp.get("content", {}).get("missed_opportunities", []):
            if m and m not in missed_set:
                missed_set.append(m)

    # ── optimal_decision_path：取主导经验版本 ────────────────────────
    best_we = max(wes.weighted_exps, key=_exp_weight)
    dom_content = best_we.exp.get("content", {})

    fused_content = {
        "decision_mistakes":     merged_mistakes,
        "key_lessons":           [x["lesson"] for x in merged_lessons],
        "key_lessons_structured": merged_lessons,
        "missed_opportunities":  missed_set,
        "optimal_decision_path": dom_content.get("optimal_decision_path", []),
        "failure_pattern":       dom_content.get("failure_pattern", ""),
        "fused_from_count":      len(wes.weighted_exps),
    }
    return fused_content, [], notes


# ─────────────────────────────────────────────────────────────────────────────
# CONCEPTUAL 融合（§7.1.4）
# ─────────────────────────────────────────────────────────────────────────────

def _merge_conceptual(wes: WeightedEquivalenceSet) -> Tuple[Dict, List[Dict], List[str]]:
    """core_insight 多文本聚合 + applicable_conditions频次加权。"""
    notes: List[str] = []
    total_w = _total_weight(wes)

    # ── core_insight：收集所有文本，以主导版本为基础，其余作为 supporting ──
    best_we = max(wes.weighted_exps, key=_exp_weight)
    dominant_insight = best_we.exp.get("content", {}).get("core_insight", "")

    all_insights = []
    for we in wes.weighted_exps:
        text = we.exp.get("content", {}).get("core_insight", "")
        if text and text != dominant_insight:
            all_insights.append({
                "text":       text,
                "weight":     round(_exp_weight(we), 4),
                "exp_id":     we.exp_id,
            })
    notes.append(f"core_insight: 主导版本 from {best_we.exp_id}，{len(all_insights)} 个补充视角")

    # ── applicable_conditions 频次加权 ───────────────────────────────
    pos_vote: Dict[str, float] = defaultdict(float)
    neg_vote: Dict[str, float] = defaultdict(float)
    retrieval_triggers: List[str] = []

    for we in wes.weighted_exps:
        cond = we.exp.get("content", {}).get("applicable_conditions", {})
        if isinstance(cond, dict):
            for c in cond.get("positive", []):
                pos_vote[c] += _exp_weight(we)
            for c in cond.get("negative", []):
                neg_vote[c] += _exp_weight(we)
            for t in cond.get("retrieval_triggers", []):
                if t not in retrieval_triggers:
                    retrieval_triggers.append(t)

    # 按频次排序（阈值：出现权重总和 ≥ 0.3 × total_w）
    thr = total_w * 0.30
    merged_positive = [c for c, w in sorted(pos_vote.items(), key=lambda x: -x[1]) if w >= thr]
    merged_negative = [c for c, w in sorted(neg_vote.items(), key=lambda x: -x[1]) if w >= thr]

    # ── supporting_evidence 累积 ──────────────────────────────────────
    all_evidence: List[str] = []
    for we in wes.weighted_exps:
        for ev in we.exp.get("content", {}).get("supporting_evidence", []):
            if ev and ev not in all_evidence:
                all_evidence.append(ev)

    fused_content = {
        "pattern_type":   best_we.exp.get("content", {}).get("pattern_type", ""),
        "core_insight":   dominant_insight,
        "supplementary_insights": all_insights[:5],
        "applicable_conditions": {
            "positive":           merged_positive,
            "negative":           merged_negative,
            "retrieval_triggers": retrieval_triggers,
            "condition_weights":  {
                "positive": {c: round(w/total_w, 4) for c, w in pos_vote.items()},
                "negative": {c: round(w/total_w, 4) for c, w in neg_vote.items()},
            },
        },
        "supporting_evidence":  all_evidence,
        "fused_from_count":     len(wes.weighted_exps),
    }
    return fused_content, [], notes


# ─────────────────────────────────────────────────────────────────────────────
# 层路由：按 knowledge_layer 分派到具体融合函数
# ─────────────────────────────────────────────────────────────────────────────

_MERGE_DISPATCH = {
    "PROCEDURAL_NEG":  _merge_procedural_neg,
    "PROCEDURAL_POS":  _merge_procedural_pos,
    "FACTUAL":         _merge_factual,
    "METACOGNITIVE":   _merge_metacognitive,
    "CONCEPTUAL":      _merge_conceptual,
}


# ─────────────────────────────────────────────────────────────────────────────
# 主入口：merge_equivalence_set()
# ─────────────────────────────────────────────────────────────────────────────

def merge_equivalence_set(
    wes: WeightedEquivalenceSet,
    cve_commands_map: Optional[Dict[str, List[str]]] = None,
) -> Optional[MergeResult]:
    """对单个 WeightedEquivalenceSet 执行 RME 融合。

    若等价集不满足层级融合阈值，返回 None（不融合单条经验）。

    Args:
        wes             : Phase 1+2 联合输出的带权重等价集
        cve_commands_map: CVE→命令列表映射（由 _build_cve_commands_map 预构建，
                  供 FACTUAL(LLM来源) 融合时回填 exploit_commands）

    Returns:
        MergeResult 或 None
    """
    cluster = wes.cluster
    if not cluster.meets_fusion_threshold:
        required = _fusion_threshold_for_layer(cluster.knowledge_layer)
        logger.debug(
            f"RME: 跳过 {cluster.cluster_id}（经验数={len(cluster.experiences)} < {required}）"
        )
        return None

    raw_layer = cluster.knowledge_layer
    layer = "FACTUAL" if str(raw_layer).startswith("FACTUAL_") else raw_layer
    merge_fn = _MERGE_DISPATCH.get(layer)
    if merge_fn is None:
        logger.warning(f"RME: 未知知识层 '{layer}'，跳过 {cluster.cluster_id}")
        return None

    logger.info(f"RME [{cluster.cluster_id}]: 融合 {len(wes.weighted_exps)} 条 {layer} 经验")

    # 计算矛盾评分
    contra_score = _contradiction_score(wes)

    # 执行层特定融合算法（FACTUAL 额外传入 cve_commands_map，供 LLM 来源分支使用）
    try:
        if layer == "FACTUAL":
            fused_content, minority_opinions, notes = merge_fn(wes, cve_commands_map)
        else:
            fused_content, minority_opinions, notes = merge_fn(wes)
    except Exception as e:
        logger.error(f"RME [{cluster.cluster_id}]: 融合失败 — {e}", exc_info=True)
        return None

    if fused_content is None:
        logger.info(f"RME [{cluster.cluster_id}]: FACTUAL 无实质内容，跳过写出")
        return None

    # 构建 Provenance
    provenance = _build_provenance(wes)
    provenance.minority_opinions = minority_opinions

    result = MergeResult(
        cluster.cluster_id,
        layer,
        "",
        cluster.version_family,
        cluster.cve_ids,
        len(provenance.source_exp_ids),
        fused_content,
        provenance,
        minority_opinions,
        contra_score,
        notes,
    )

    # 写出前最终净化：避免 consolidated/raw 等占位词或实例ID进入 target_service。
    cluster_svc = canonical_service_or_empty(cluster.target_service)
    fused_svc = ""
    if isinstance(fused_content, dict):
        fused_svc = canonical_service_or_empty(str(fused_content.get("target_service", "")))

    resolved_svc = cluster_svc or fused_svc or _resolve_wes_target_service(wes)
    result.target_service = resolved_svc

    if isinstance(result.fused_content, dict):
        if resolved_svc:
            result.fused_content["target_service"] = resolved_svc
        else:
            result.fused_content.pop("target_service", None)

    logger.info(
        f"RME [{cluster.cluster_id}]: 融合完成 "
        f"contra={contra_score:.3f}  "
        f"notes={len(notes)}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 批量融合：run_rme()
# ─────────────────────────────────────────────────────────────────────────────

def run_rme(
    wes_list: List[WeightedEquivalenceSet],
) -> List[MergeResult]:
    """对 Phase 1+2 输出的全部等价集执行 RME 融合。

    自动跳过不满足层级融合阈值的等价集。
    P0 Fix 3: 预构建 cve_commands_map，供 FACTUAL(LLM来源) 融合时回填 exploit_commands。

    Args:
        wes_list: weight_equivalence_sets() 的输出

    Returns:
        成功融合的 MergeResult 列表（只包含满足阈值的集合）
    """
    # 预构建 CVE → 命令 映射（来自所有 PROCEDURAL_NEG 集群的 next_actions）
    cve_commands_map = _build_cve_commands_map(wes_list)
    if cve_commands_map:
        logger.info(
            f"RME: 构建 CVE 命令映射，覆盖 {len(cve_commands_map)} 个 CVE，"
            f"共 {sum(len(v) for v in cve_commands_map.values())} 条命令"
        )

    results: List[MergeResult] = []
    skipped = 0

    for wes in wes_list:
        mr = merge_equivalence_set(wes, cve_commands_map=cve_commands_map)
        if mr is not None:
            results.append(mr)
        else:
            skipped += 1

    logger.info(
        f"RME 完成: 融合 {len(results)} 个等价集，跳过 {skipped} 个（不满阈值）"
    )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：摘要输出
# ─────────────────────────────────────────────────────────────────────────────

def summarize_merge_results(results: List[MergeResult]) -> str:
    """返回可读的融合结果摘要（用于调试/日志）。"""
    lines = [
        "=" * 70,
        f"RME 融合摘要  共 {len(results)} 个 MergeResult",
        "=" * 70,
    ]
    for mr in results:
        prov = mr.provenance
        lines.append(
            f"[{mr.cluster_id}]  层={mr.knowledge_layer}  "
            f"来源={mr.source_exp_count}条  contra={mr.contradiction_score:.3f}"
        )
        lines.append(
            f"  服务={mr.target_service or '(多服务)'}  CVE={mr.cve_ids}"
        )
        lines.append(
            f"  来源sessions={prov.source_sessions}  "
            f"少数意见={len(mr.minority_opinions)}"
        )
        for note in mr.merge_notes:
            lines.append(f"    · {note}")
    lines.append("=" * 70)
    return "\n".join(lines)
