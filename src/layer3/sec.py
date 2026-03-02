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

import re
import logging
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from .models import EquivalenceSet

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SSO 规范化映射（Security Semantic Ontology 小词典）
# 后续可从独立 JSON 文件加载；当前内建高频项
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_ALIASES: Dict[str, str] = {
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
}

_CVE_ALIASES: Dict[str, str] = {
    # WebLogic XMLDecoder 系列
    "weblogic xmldecoder":           "CVE-2017-10271",
    "wls-wsat xmldecoder":           "CVE-2017-10271",
    "cve-2017-10271":                "CVE-2017-10271",
    # 可扩展：在此添加更多别名
}


def normalize_service_name(raw: str) -> str:
    """将服务名规范化为 SSO 标准名称（不区分大小写查找）。"""
    if not raw:
        return ""
    key = raw.strip().lower()
    return _SERVICE_ALIASES.get(key, raw.strip())


def normalize_cve_ids(cve_list: List[str]) -> List[str]:
    """规范化 CVE ID 列表（转大写、去重、排序）。"""
    normalized = []
    for cve in cve_list:
        c = cve.strip().upper()
        # 尝试别名映射
        c = _CVE_ALIASES.get(c.lower(), c)
        if c and c not in normalized:
            normalized.append(c)
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
    knowledge_layer = exp.get("knowledge_layer", "")

    # ── BUG-1 修复：FACTUAL 子类型区分 ────────────────────────────────────────
    # FACTUAL_RULE：端口/服务发现（discovered_facts 结构）
    # FACTUAL_LLM ：CVE 利用地图（cve_context 结构，由 LLM 提取）
    # 两者 schema 完全不同，Phase 3 RME 需要走不同的融合算法，必须拆开。
    if knowledge_layer == "FACTUAL":
        extraction_source = exp.get("metadata", {}).get("extraction_source", "")
        has_cve_context   = "cve_context" in exp.get("content", {})
        if extraction_source == "llm" or has_cve_context:
            knowledge_layer = "FACTUAL_LLM"   # CVE 地图融合
        else:
            knowledge_layer = "FACTUAL_RULE"  # 端口/服务发现聚合
    # ─────────────────────────────────────────────────────────────────────────

    # target_service：优先从 metadata.applicable_constraints 读取
    meta_constraints = exp.get("metadata", {}).get("applicable_constraints", {})
    svc = meta_constraints.get("target_service", "")
    if not svc:
        # 兜底：部分 FACTUAL 层在 content 顶级也有 target_service
        svc = exp.get("content", {}).get("target_service", "")
    svc_normalized = normalize_service_name(svc)

    # failure_sub_dim：仅 PROCEDURAL_NEG 层有效，其他层为空字符串
    sub_dim = ""
    if knowledge_layer == "PROCEDURAL_NEG":
        fsub = exp.get("content", {}).get("failure_sub_dimension", "")
        # Issue 5 修复：加入 attack_phase 作为第二分量，防止不同攻击阶段的失败模式
        # 被错误融合（如 RECON阶段端口探测404 vs EXPLOITATION阶段文件读取失败）。
        attack_phase = (
            exp.get("metadata", {}).get("attack_phase", "")
            or exp.get("content", {}).get("attack_phase", "")
        )
        phase_slug = attack_phase.upper()[:20] if attack_phase else "any"
        sub_dim = f"{fsub}::{phase_slug}" if fsub else phase_slug

    # Issue 2 修复：CONCEPTUAL 层 metadata.applicable_constraints = {} 导致 svc="" 全部落入同一 key。
    # 改为从 content.applicable_conditions.retrieval_triggers 提取服务名，
    # 同时用 content.pattern_type 区分漏洞型 vs 侦察型。
    if knowledge_layer == "CONCEPTUAL":
        c = exp.get("content", {})
        sub_dim = c.get("pattern_type", "")  # "vulnerability_pattern" | "recon_pattern"
        if not svc_normalized:
            rt = c.get("applicable_conditions", {}).get("retrieval_triggers", [])
            for trigger in rt:
                # 直接查字典：只有 trigger 命中别名表才采用规范化服务名，
                # 避免未知字符串（nmap/gobuster 等工具名）被误当服务名。
                key = trigger.strip().lower()
                if key in _SERVICE_ALIASES:
                    svc_normalized = _SERVICE_ALIASES[key]
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
            # cve_context.attempted（FACTUAL_LLM 层）
            ctx = content.get("cve_context", {})
            cves = ctx.get("attempted", [])
        if not cves:
            # CONCEPTUAL 层：从 retrieval_triggers 中提取 CVE 格式的字符串
            ac = content.get("applicable_conditions") or {}
            rt = ac.get("retrieval_triggers", []) if isinstance(ac, dict) else []
            cves = [t for t in rt if re.match(r"CVE-\d{4}-\d+", t, re.IGNORECASE)]
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
    """生成等价集唯一 ID。"""
    # slug 化：小写 + 空格转下划线 + 截断
    svc_slug = re.sub(r"[^a-z0-9]+", "_", target_service.lower())[:20].strip("_")
    sub_slug = sub_dim.lower()[:20] if sub_dim else "any"
    ver_slug = version_family.replace(".", "") if version_family else "anyver"
    # CVE 签名（取首 CVE 或 "nocve"）
    cve_sig = cve_ids[0].replace("-", "") if cve_ids else "nocve"
    return f"SEC_{knowledge_layer}_{svc_slug}_{sub_slug}_{ver_slug}_{cve_sig}"


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
            results.append(eq_set)

    # ── 排序：满足融合阈值（≥3）的排前面，然后按等价集大小降序
    results.sort(key=lambda s: (not s.meets_fusion_threshold, -len(s.experiences)))

    fusion_candidates = [s for s in results if s.meets_fusion_threshold]
    logger.info(
        f"SEC 完成: 共 {len(results)} 个等价集，"
        f"其中 {len(fusion_candidates)} 个满足融合阈值（≥3条经验）"
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
