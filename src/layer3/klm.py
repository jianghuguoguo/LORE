"""
Phase 5 — Knowledge Lifecycle Management (KLM)
===============================================
接受 Phase 4 BCC 输出的 ConsolidatedExp 列表，管理全经验库的生命周期状态。

执行三项核心操作：

操作 1 — 回流标记（Reflux Marking）：
  consolidated + should_reflux=True + lifecycle_status="active"
  → ce.refluxed = True，加入「回流就绪」清单（写入 phase5_reflux_ready.jsonl）
  → 对应源经验（provenance.source_exp_ids）：
      lifecycle_status = "archived"
      merged_into      = consolidated_exp_id

操作 2 — 冲突标记（Conflict Tagging）：
  consolidated + lifecycle_status="conflicted"
  → 对应源经验（仍 active 的）标记 lifecycle_status = "conflicted"
  → 生成冲突分析报告条目，供人工确认

操作 3 — 时效性衰减（Temporal Decay）：
  对所有 lifecycle_status="active" 的原始经验，按知识层λ值计算衰减后权重：
    W_effective(E,t) = W_base × exp(-λ × Δt_days)
  W_base = confidence × maturity_factor
  若 W_effective < 0.10 → lifecycle_status = "suspended"

输出：
  updated_raw_list  — 带生命周期更新的原始经验列表
  reflux_ready_list — 回流就绪的 consolidated 经验列表
  KlmResult         — 统计摘要 + 操作日志

衔接文档：
  XPEC Layer3 融合框架分析.md §6、§8（生命周期状态、Schema 修改）
  XPEC-Layer3 融合框架-实现流程.md §9（KLM 5 种状态、周期维护、回滚机制）
"""

from __future__ import annotations

import copy
import logging
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .models import ConsolidatedExp, LifecycleStatus
from .sec import canonical_service_or_empty, resolve_target_service

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 常量：时效性衰减率（λ）和挂起阈值
# 半衰期公式：t_half = ln(2) / λ（单位：天）
# 数据来源：分析文档 §3.2
# ─────────────────────────────────────────────────────────────────────────────

_DECAY_RATES: Dict[str, float] = {
    "FACTUAL":          0.003,   # ~231 天半衰期（版本/服务信息，随补丁缓慢失效）
    "PROCEDURAL_NEG":   0.005,   # ~139 天（CVE 利用路径，随补丁迭代）
    "PROCEDURAL_POS":   0.005,
    "METACOGNITIVE":    0.001,   # ~693 天（决策规则，极稳定）
    "CONCEPTUAL":       0.001,
}
_DECAY_DEFAULT      = 0.005   # 未知层使用默认值
_SUSPEND_THRESHOLD  = 0.10    # W_effective < 此值 → suspended（退出检索索引）


# ─────────────────────────────────────────────────────────────────────────────
# 数据结构：KLM 操作结果
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class KlmResult:
    """Phase 5 KLM 完整输出摘要。

    Attributes:
        total_raw_exps          : experience_raw.jsonl 中的原始经验总数
        consolidated_count      : Phase 4 输入的 consolidated 经验总数
        refluxed_count          : 成功回流（refluxed=True）的 consolidated 数量
        archived_source_count   : 被归档（archived）的原始源经验数量
        suspended_count         : 时效衰减后被挂起的原始经验数量
        conflicted_count        : 被标记为 conflicted 的原始经验数量
        active_raw_count        : 操作后仍处于 active 状态的原始经验数量
        active_consol_count     : active 的 consolidated 经验数量
        lifecycle_updates       : exp_id → new_lifecycle_status（实际变化的映射）
        merged_into_map         : source_exp_id → consolidated_exp_id（融合关系链）
        conflict_report         : 冲突分析报告条目列表
        suspension_log          : 衰减挂起明细列表（含 W_effective）
        generated_at            : ISO8601 生成时间戳
    """
    total_raw_exps:         int
    consolidated_count:     int
    refluxed_count:         int
    archived_source_count:  int
    suspended_count:        int
    conflicted_count:       int
    active_raw_count:       int
    active_consol_count:    int

    lifecycle_updates: Dict[str, str]       = field(default_factory=dict)
    merged_into_map:   Dict[str, str]       = field(default_factory=dict)
    conflict_report:   List[Dict[str, Any]] = field(default_factory=list)
    suspension_log:    List[Dict[str, Any]] = field(default_factory=list)

    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now(tz=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# 内部工具函数
# ─────────────────────────────────────────────────────────────────────────────

def _compute_temporal_w(exp: Dict[str, Any], now: datetime) -> float:
    """计算原始经验的时效衰减后权重 W_effective(E, t)。

    公式：
        W_base    = confidence × maturity_factor
        W_effective = W_base × exp(-λ × Δt_days)

    其中 maturity_factor: raw=0.4, validated=0.7, consolidated=1.0
    λ 由 knowledge_layer 决定（见 _DECAY_RATES）

    Args:
        exp : 原始经验 dict（含 metadata.confidence 等）
        now : 当前时间（用于计算 Δt）

    Returns:
        衰减后权重（float）
    """
    layer      = exp.get("knowledge_layer", "FACTUAL")
    if str(layer).startswith("FACTUAL_"):
        layer = "FACTUAL"
    lam        = _DECAY_RATES.get(layer, _DECAY_DEFAULT)

    confidence = float(exp.get("confidence", 0.5))
    maturity   = exp.get("maturity", "raw")
    mat_factor = {"raw": 0.4, "validated": 0.7, "consolidated": 1.0}.get(maturity, 0.4)

    w_base = confidence * mat_factor

    created_str = exp.get("metadata", {}).get("created_at", "")
    delta_days  = 0.0
    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            delta_days = max(0.0, (now - created).total_seconds() / 86400.0)
        except (ValueError, TypeError):
            delta_days = 0.0

    w_eff = w_base * math.exp(-lam * delta_days)
    return round(w_eff, 6)


def _get_source_exp_ids(ce: ConsolidatedExp) -> List[str]:
    """从 ConsolidatedExp.provenance 中解析源经验 ID 列表。

    provenance 可能是 dict（已序列化）或 Provenance dataclass 实例。
    """
    prov = ce.provenance
    if prov is None:
        return []
    if isinstance(prov, dict):
        return prov.get("source_exp_ids", [])
    # Provenance dataclass 实例
    return getattr(prov, "source_exp_ids", [])


def _normalize_raw_target_service_fields(exp: Dict[str, Any]) -> str:
    """规范化单条原始经验的 target_service，并回写 content/metadata 约束字段。"""
    resolved = resolve_target_service(exp)

    content = exp.get("content") if isinstance(exp.get("content"), dict) else {}
    metadata = exp.get("metadata") if isinstance(exp.get("metadata"), dict) else {}
    constraints = (
        metadata.get("applicable_constraints")
        if isinstance(metadata.get("applicable_constraints"), dict)
        else {}
    )

    if resolved:
        content["target_service"] = resolved
        constraints["target_service"] = resolved
    else:
        # 对无法解析的占位值清空，避免 raw/validated/consolidated 等污染字段。
        c_svc = str(content.get("target_service", ""))
        m_svc = str(constraints.get("target_service", ""))
        if c_svc and not canonical_service_or_empty(c_svc):
            content["target_service"] = ""
        if m_svc and not canonical_service_or_empty(m_svc):
            constraints["target_service"] = ""

    exp["content"] = content
    metadata["applicable_constraints"] = constraints
    exp["metadata"] = metadata
    return resolved


def _set_raw_target_service(exp: Dict[str, Any], service_name: str) -> None:
    """将推断出的服务名回填到原始经验的标准字段位置。"""
    if not service_name:
        return
    content = exp.get("content") if isinstance(exp.get("content"), dict) else {}
    metadata = exp.get("metadata") if isinstance(exp.get("metadata"), dict) else {}
    constraints = (
        metadata.get("applicable_constraints")
        if isinstance(metadata.get("applicable_constraints"), dict)
        else {}
    )
    content["target_service"] = service_name
    constraints["target_service"] = service_name
    metadata["applicable_constraints"] = constraints
    exp["content"] = content
    exp["metadata"] = metadata


def _normalize_consolidated_target_service(
    ce: ConsolidatedExp,
    source_exps: List[Dict[str, Any]],
) -> str:
    """规范化 consolidated 经验的 target_service，并在必要时从源经验回填。"""
    content = ce.content if isinstance(ce.content, dict) else {}
    metadata = ce.metadata if isinstance(ce.metadata, dict) else {}
    constraints = (
        metadata.get("applicable_constraints")
        if isinstance(metadata.get("applicable_constraints"), dict)
        else {}
    )

    merged_candidate = canonical_service_or_empty(str(constraints.get("target_service", "")))
    if not merged_candidate:
        merged_candidate = canonical_service_or_empty(str(content.get("target_service", "")))

    if not merged_candidate and source_exps:
        vote: Dict[str, float] = {}
        for src in source_exps:
            svc = resolve_target_service(src)
            if svc:
                vote[svc] = vote.get(svc, 0.0) + float(src.get("confidence", 0.5))
        if vote:
            merged_candidate = max(vote.items(), key=lambda kv: kv[1])[0]

    if merged_candidate:
        content["target_service"] = merged_candidate
        constraints["target_service"] = merged_candidate
    else:
        if "target_service" in content and not canonical_service_or_empty(str(content.get("target_service", ""))):
            content["target_service"] = ""
        if "target_service" in constraints and not canonical_service_or_empty(str(constraints.get("target_service", ""))):
            constraints["target_service"] = ""

    ce.content = content
    metadata["applicable_constraints"] = constraints
    ce.metadata = metadata
    return merged_candidate


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 核心入口：run_klm()
# ─────────────────────────────────────────────────────────────────────────────

def run_klm(
    consolidated_exps: List[ConsolidatedExp],
    exp_map:           Dict[str, Dict[str, Any]],
) -> Tuple[KlmResult, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """执行 Phase 5 知识生命周期管理（KLM）。

    不修改任何输入参数（内部使用深拷贝）。

    Args:
        consolidated_exps : Phase 4 BCC 完整 ConsolidatedExp 列表（包含所有成熟度）
        exp_map           : exp_id → experience dict（来自 experience_raw.jsonl）

    Returns:
        tuple(KlmResult, updated_raw_list, reflux_ready_list)

        KlmResult           — 统计摘要 + 操作日志
        updated_raw_list    — 带生命周期更新的原始经验 list（写出到 klm_registry.jsonl）
        reflux_ready_list   — 回流就绪的 consolidated 经验 list（写出到 reflux_ready.jsonl）
    """
    now = datetime.now(tz=timezone.utc)

    # 深拷贝原始经验，不修改输入
    working: Dict[str, Dict[str, Any]] = copy.deepcopy(exp_map)

    # 向后兼容：确保每条原始经验都有 lifecycle_status / merged_into 字段
    session_service_votes: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for exp in working.values():
        if "lifecycle_status" not in exp:
            exp["lifecycle_status"] = "active"
        if "merged_into" not in exp:
            exp["merged_into"] = None
        resolved = _normalize_raw_target_service_fields(exp)
        session_id = str(exp.get("metadata", {}).get("source_session_id", "")).strip()
        if resolved and session_id:
            session_service_votes[session_id][resolved] += float(exp.get("confidence", 0.5))

    # 会话级回填：同一 session 内，若部分经验未识别服务名，回填该 session 的主导服务。
    for exp in working.values():
        session_id = str(exp.get("metadata", {}).get("source_session_id", "")).strip()
        if not session_id:
            continue
        current = resolve_target_service(exp)
        if current:
            continue
        vote = session_service_votes.get(session_id, {})
        if not vote:
            continue
        inferred = max(vote.items(), key=lambda kv: kv[1])[0]
        if inferred:
            _set_raw_target_service(exp, inferred)

    # 追踪结构
    lifecycle_updates: Dict[str, str]       = {}
    merged_into_map:   Dict[str, str]       = {}
    conflict_report:   List[Dict[str, Any]] = []
    suspension_log:    List[Dict[str, Any]] = []
    reflux_ready:      List[Dict[str, Any]] = []

    n_refluxed        = 0
    n_archived_source = 0
    n_conflicted      = 0

    # ──────────────────────────────────────────────────────────────────────
    # 操作 1 + 2：遍历所有 consolidated 经验
    # ──────────────────────────────────────────────────────────────────────
    for ce in consolidated_exps:
        ce_id      = ce.exp_id
        ce_layer   = ce.knowledge_layer
        ce_status  = ce.lifecycle_status
        source_ids = _get_source_exp_ids(ce)

        source_exps = [working[sid] for sid in source_ids if sid in working]
        _normalize_consolidated_target_service(ce, source_exps)

        # should_reflux ≡ (maturity=="consolidated" and lifecycle_status=="active")
        # ConsolidatedExp 无独立的 should_reflux 字段，由此两条件直接推断
        if ce_status == "active" and ce.maturity == "consolidated":
            # ── 操作 1：回流标记 ─────────────────────────────────────────
            ce.refluxed = True
            n_refluxed += 1

            # 将源经验标记为 archived + 设 merged_into
            for src_id in source_ids:
                if src_id in working:
                    src = working[src_id]
                    if src.get("lifecycle_status") == "active":
                        src["lifecycle_status"] = "archived"
                        src["merged_into"]       = ce_id
                        lifecycle_updates[src_id] = "archived"
                        merged_into_map[src_id]   = ce_id
                        n_archived_source += 1
                        logger.debug(
                            f"KLM [归档] 源经验 {src_id} → archived  "
                            f"merged_into={ce_id}"
                        )
                    elif src.get("lifecycle_status") == "archived":
                        # 已被其他 consolidated 归档，仅更新 merged_into（取最新）
                        src["merged_into"] = ce_id
                        merged_into_map[src_id] = ce_id
                else:
                    logger.warning(
                        f"KLM: 源经验 {src_id} 不在 exp_map 中（可能尚未提取）"
                    )

            # 加入回流就绪列表（高优先级 RAG 索引候选）
            ce_dict = asdict(ce)
            ce_dict["klm_reflux_timestamp"] = now.isoformat()
            reflux_ready.append(ce_dict)

            logger.info(
                f"KLM [回流✓] {ce_id[:45]}  "
                f"layer={ce_layer}  conf={ce.confidence:.4f}  "
                f"n_src={len(source_ids)}  已归档源经验={n_archived_source}"
            )

        elif ce_status == "conflicted":
            # ── 操作 2：冲突标记 ─────────────────────────────────────────
            contra_threshold = (
                0.30 if ce_layer in ("METACOGNITIVE", "CONCEPTUAL") else 0.60
            )
            conflict_entry: Dict[str, Any] = {
                "consolidated_exp_id": ce_id,
                "knowledge_layer":     ce_layer,
                "contradiction_score": round(ce.contradiction_score, 4),
                "conflict_threshold":  round(contra_threshold, 2),
                "p_fused":             round(ce.p_fused, 4),
                "n_independent":       ce.n_independent_sessions,
                "source_exp_ids":      source_ids,
                "recommendation": (
                    "HIGH_PRIORITY_REVIEW"
                    if ce.contradiction_score > 0.70
                    else "MEDIUM_PRIORITY_REVIEW"
                ),
                "note": (
                    f"P_fused={ce.p_fused:.4f}，"
                    f"contradiction_score={ce.contradiction_score:.3f} 超过该层冲突阈值"
                    f"({contra_threshold:.2f})，阻止成熟度升级；"
                    f"需要人工核验冲突原因（可能是版本差异或环境差异导致的条件化矛盾）"
                ),
            }
            conflict_report.append(conflict_entry)

            # 对仍 active 的源经验标记 conflicted
            for src_id in source_ids:
                if src_id in working:
                    src = working[src_id]
                    if src.get("lifecycle_status") == "active":
                        src["lifecycle_status"] = "conflicted"
                        lifecycle_updates[src_id] = "conflicted"
                        n_conflicted += 1
                        logger.debug(
                            f"KLM [冲突] 源经验 {src_id} → conflicted  "
                            f"(contra={ce.contradiction_score:.3f})"
                        )

            logger.info(
                f"KLM [冲突⚠] {ce_id[:45]}  "
                f"layer={ce_layer}  contra={ce.contradiction_score:.3f}  "
                f"p_fused={ce.p_fused:.4f}  "
                f"优先级={conflict_entry['recommendation']}"
            )

        else:
            # validated / raw：未达到 consolidated 或 reflux 条件
            # 源经验保持 active，等待下一轮 sec→bcc 管道
            pass

    # ──────────────────────────────────────────────────────────────────────
    # 操作 3 前置：构建 source → consolidated 反向映射
    # 目的：时效性衰减挂起时若该经验曾参与融合，同步设置 merged_into（BUG-4 修复）
    # ──────────────────────────────────────────────────────────────────────
    source_to_consolidated: Dict[str, str] = {}
    for ce in consolidated_exps:
        for src_id in _get_source_exp_ids(ce):
            # 以最晚写入的 consolidated 为准（保留最新指针）
            source_to_consolidated[src_id] = ce.exp_id

    # ──────────────────────────────────────────────────────────────────────
    # 操作 3：时效性衰减
    # ──────────────────────────────────────────────────────────────────────
    n_suspended = 0
    for exp_id, exp in working.items():
        if exp.get("lifecycle_status") != "active":
            continue   # 已被归档/冲突/挂起，跳过

        w_eff = _compute_temporal_w(exp, now)
        if w_eff < _SUSPEND_THRESHOLD:
            exp["lifecycle_status"] = "suspended"
            lifecycle_updates[exp_id] = "suspended"
            # BUG-4 修复：若该经验是某个 consolidated 的来源，补写 merged_into
            merged_ce = source_to_consolidated.get(exp_id)
            if merged_ce and not exp.get("merged_into"):
                exp["merged_into"] = merged_ce
                merged_into_map[exp_id] = merged_ce
                logger.debug(
                    "KLM [衰减] %s merged_into=%s (补写)", exp_id, merged_ce
                )
            n_suspended += 1
            suspension_log.append({
                "exp_id":          exp_id,
                "knowledge_layer": exp.get("knowledge_layer", ""),
                "w_effective":     w_eff,
                "created_at":      exp.get("metadata", {}).get("created_at", ""),
                "confidence":      exp.get("confidence", 0.0),
                "maturity":        exp.get("maturity", "raw"),
            })
            logger.debug(
                f"KLM [衰减] {exp_id}  "
                f"W_eff={w_eff:.4f} < {_SUSPEND_THRESHOLD} → suspended"
            )

    if n_suspended:
        logger.info(f"KLM [时效衰减] {n_suspended} 条原始经验被挂起 (suspended)")

    # ──────────────────────────────────────────────────────────────────────
    # 统计最终状态分布
    # ──────────────────────────────────────────────────────────────────────
    status_counter: Dict[str, int] = {}
    for exp in working.values():
        s = exp.get("lifecycle_status", "active")
        status_counter[s] = status_counter.get(s, 0) + 1

    n_active_consol = sum(
        1 for ce in consolidated_exps
        if ce.lifecycle_status in ("active", "conflicted")   # conflicted 也算入（已生成但被标记）
    )
    # 严格 active 的 consolidated
    n_active_consol_strict = sum(
        1 for ce in consolidated_exps if ce.lifecycle_status == "active"
    )

    klm_result = KlmResult(
        total_raw_exps        = len(working),
        consolidated_count    = len(consolidated_exps),
        refluxed_count        = n_refluxed,
        archived_source_count = n_archived_source,
        suspended_count       = n_suspended,
        conflicted_count      = n_conflicted,
        active_raw_count      = status_counter.get("active", 0),
        active_consol_count   = n_active_consol_strict,
        lifecycle_updates     = lifecycle_updates,
        merged_into_map       = merged_into_map,
        conflict_report       = conflict_report,
        suspension_log        = suspension_log,
    )

    # 汇总日志
    logger.info(
        "KLM 完成: "
        f"原始经验={len(working)}  consolidated={len(consolidated_exps)}  "
        f"回流={n_refluxed}  归档源经验={n_archived_source}  "
        f"衰减挂起={n_suspended}  冲突={n_conflicted}  "
        f"active_raw={status_counter.get('active', 0)}  "
        f"active_consol={n_active_consol_strict}"
    )
    status_str = "  ".join(
        f"{k}={v}" for k, v in sorted(status_counter.items())
    )
    logger.info(f"KLM 状态分布（原始经验）: {status_str}")

    updated_raw_list = list(working.values())
    return klm_result, updated_raw_list, reflux_ready


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：可读摘要
# ─────────────────────────────────────────────────────────────────────────────

def summarize_klm_result(klm: KlmResult) -> str:
    """返回 Phase 5 KLM 结果的可读摘要字符串（用于日志/调试）。"""
    sep = "=" * 70
    lines = [
        sep,
        "Phase 5 — KLM 知识生命周期管理  摘要",
        sep,
        f"  原始经验总数           : {klm.total_raw_exps}",
        f"  Consolidated 经验数    : {klm.consolidated_count}",
        "",
        "  ─── 生命周期操作结果 ──────────────────────────────────",
        f"  回流完成 (refluxed)    : {klm.refluxed_count}",
        f"  归档的源经验            : {klm.archived_source_count}",
        f"  衰减挂起 (suspended)   : {klm.suspended_count}",
        f"  标记冲突 (conflicted)  : {klm.conflicted_count}",
        "",
        "  ─── 最终状态（操作后）─────────────────────────────────",
        f"  active  原始经验       : {klm.active_raw_count}",
        f"  active  consolidated  : {klm.active_consol_count}",
        f"  生命周期更新条目数      : {len(klm.lifecycle_updates)}",
    ]

    if klm.conflict_report:
        lines.append("")
        lines.append(
            f"  ─── 冲突分析报告 ({len(klm.conflict_report)} 条，需人工确认） ─────────"
        )
        for entry in klm.conflict_report:
            lines.append(
                f"  [{entry['consolidated_exp_id'][:42]}]"
            )
            lines.append(
                f"    layer={entry['knowledge_layer']}  "
                f"contra={entry['contradiction_score']:.3f}  "
                f"p_fused={entry['p_fused']:.4f}  "
                f"⚠ {entry['recommendation']}"
            )

    if klm.suspension_log:
        lines.append("")
        lines.append(
            f"  ─── 衰减挂起明细 ({len(klm.suspension_log)} 条） ──────────────────────"
        )
        for entry in klm.suspension_log[:8]:
            lines.append(
                f"  {entry['exp_id'][:40]}  "
                f"layer={entry['knowledge_layer']:<16}  "
                f"W_eff={entry['w_effective']:.4f}"
            )
        if len(klm.suspension_log) > 8:
            lines.append(f"  ... 还有 {len(klm.suspension_log) - 8} 条未显示")

    lines.append(sep)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 数据回填工具：修复已存在数据中 suspended.merged_into=None 的问题（BUG-4 修复）
# ─────────────────────────────────────────────────────────────────────────────

def backfill_merged_into(
    klm_entries: List[Dict[str, Any]],
    consolidated_entries: List[Dict[str, Any]],
) -> int:
    """
    回填 KLM 原始经验中 suspended 条目的 merged_into 字段。

    扫描 consolidated_entries 的 provenance.source_exp_ids，
    找到 klm_entries 中对应的 suspended/archived 经验，补写 merged_into。

    Parameters
    ----------
    klm_entries          : phase5_klm_registry.jsonl 的条目列表（直接修改）
    consolidated_entries : phase34_consolidated.jsonl 的条目列表

    Returns
    -------
    int: 完成回填的条目数
    """
    # 构建 source_id → consolidated_id 映射
    src_to_ce: Dict[str, str] = {}
    for ce in consolidated_entries:
        ce_id = ce.get("exp_id", "")
        if not ce_id:
            continue
        prov = ce.get("provenance", {})
        if isinstance(prov, dict):
            src_ids = prov.get("source_exp_ids", [])
        else:
            src_ids = []
        # 也尝试顶层 source_exp_ids（兼容不同版本的 schema）
        if not src_ids:
            src_ids = ce.get("source_exp_ids", [])
        for sid in src_ids:
            src_to_ce.setdefault(sid, ce_id)   # 以第一个 consolidated 为准

    if not src_to_ce:
        logger.warning("backfill_merged_into: consolidated_entries 中未找到任何 provenance 信息")
        return 0

    backfilled = 0
    for exp in klm_entries:
        exp_id = exp.get("exp_id", "")
        status = exp.get("lifecycle_status", "")
        # 只回填 suspended / archived 且 merged_into 为空的条目
        if status not in ("suspended", "archived"):
            continue
        if exp.get("merged_into"):
            continue
        if exp_id in src_to_ce:
            exp["merged_into"] = src_to_ce[exp_id]
            backfilled += 1
            logger.debug("backfill: %s merged_into=%s", exp_id, src_to_ce[exp_id])

    logger.info("backfill_merged_into: 回填 %d 条 merged_into 字段", backfilled)
    return backfilled
