# src/layer4/conflict.py
"""
冲突检测与清理模块（Layer 4 核心）。

架构设计：双后端策略
  ┌─────────────────────────────────────────────────────────────┐
  │  ConflictDetector                                           │
  │    ├── LocalKLMBackend  ← 当前：操作 layer3 JSONL 文件      │
  │    └── RAGFlowBackend   ← 未来：接入 RAGFlow REST API       │
  └─────────────────────────────────────────────────────────────┘

两种触发场景（§9.1）：
  A. 新增 PROCEDURAL_NEG 体验 → process_neg_exp()
     - 搜索 KLM 中是否有「推荐该错误做法」的条目
     - 冲突者 lifecycle_status → "conflicted"
  B. P2 周任务：已修补 CVE 扫描 → check_patched_cves()
     - 找到 PROCEDURAL_POS/CONCEPTUAL 中仍推荐利用已补丁 CVE 的条目
     - 状态 → "suspended" + 加入 deprecated_reason

冲突判定策略（三层递进，降低误标率）：
  1. 快速规则过滤：token overlap ≥ RULE_OVERLAP_THRESHOLD
  2. 语义去噪：领域特异性关键词命中
  3. LLM 精判（可选，offline 模式跳过）

Reports:
  - data/layer3_output/conflict_report.jsonl  逐条审计日志
  - data/layer3_output/conflict_summary.json  本次运行统计

参考：RefPenTest · Layer 4 技术方案.md §9
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 路径常量（与 gap_queue.py 保持一致）
# ─────────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent  # RefPenTest/
_LAYER3_DIR = _PROJECT_ROOT / "data" / "layer3_output"

KLM_REGISTRY_FILE  = _LAYER3_DIR / "phase5_klm_registry.jsonl"
CONSOLIDATED_FILE  = _LAYER3_DIR / "phase34_consolidated.jsonl"
CONFLICT_REPORT_FILE = _LAYER3_DIR / "conflict_report.jsonl"
CONFLICT_SUMMARY_FILE = _LAYER3_DIR / "conflict_summary.json"

# ─────────────────────────────────────────────────────────────────────────────
# 冲突检测超参数
# ─────────────────────────────────────────────────────────────────────────────

# ── 三档重叠率阈值（BUG-1 修复：原单一阈值 0.15 导致 LLM gate 失效）─────────────
# overlap < LLM_GATE_THRESHOLD  → rule OK，直接跳过（相似度不足，不构成冲突）
# LLM_GATE_THRESHOLD ≤ overlap < RULE_CONFLICT_THRESHOLD → 进入 LLM 精判
# overlap ≥ RULE_CONFLICT_THRESHOLD  → rule CONFLICT，直接标记（高度重叠）
RULE_OVERLAP_THRESHOLD = 0.15    # 兼容旧代码引用，不再作为实际判断入口
LLM_GATE_THRESHOLD     = 0.20    # 低于此值直接 OK
RULE_CONFLICT_THRESHOLD = 0.50   # 高于此值直接 CONFLICT，无需 LLM

# 合法的冲突检测目标层（BUG-2 修复：仅 PROCEDURAL_POS 是真正的「推荐类」经验）
# 其他层说明：
#   CONCEPTUAL      → 描述「成功/失败条件」，NEG 是在证实其边界，非冲突，应触发条件强化
#   METACOGNITIVE   → 决策规则，不是对某技术的推荐
#   FACTUAL_*       → 事实描述/CVE上下文，不是操作建议
#   RAG_EVALUATION  → 对知识库的评价，不是操作建议
#   PROCEDURAL_NEG  → NEG vs NEG 无意义
CONFLICT_TARGET_LAYERS = frozenset(["PROCEDURAL_POS"])

# 层2语义过滤：若候选条目不含任意关键词则跳过（避免跨服务误标）
CONFLICT_SIGNAL_KEYWORDS = {
    "推荐", "建议", "可以", "should", "recommend", "try", "exploit",
    "尝试", "使用", "执行", "攻击", "利用", "漏洞利用",
}

# LLM 冲突判定 prompt
_CONFLICT_PROMPT = """\
你是渗透测试知识库管理员。
以下是一条「负向经验」（已确认的错误做法或无效操作）：
<negative_exp>
{neg_exp_content}
</negative_exp>

以下是知识库中一条潜在冲突的条目：
<kb_entry>
{kb_content}
</kb_entry>

请判断：该知识库条目是否「推荐」或「包含」了上述负向经验所描述的错误做法？
如果是，回答 CONFLICT；如果不是，回答 OK。
只输出 CONFLICT 或 OK，不要解释。\
"""

# ─────────────────────────────────────────────────────────────────────────────
# 数据结构
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConflictMatch:
    """单条冲突命中记录（审计用）。"""
    source_exp_id: str         # 触发检测的负向经验 ID
    target_exp_id: str         # 被标记的知识库条目 ID
    target_layer: str          # 被标记条目的 knowledge_layer
    conflict_type: str         # "neg_exp_conflict" | "cve_deprecated"
    old_status: str            # 变更前 lifecycle_status
    new_status: str            # 变更后 lifecycle_status
    rule_overlap: float        # token 重叠率
    judge_method: str          # "rule" | "llm"
    judge_result: str          # "CONFLICT" | "OK"
    reason: str                # 可读原因说明
    dry_run: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


@dataclass
class ConflictReport:
    """单次完整检测的总结。"""
    run_id: str
    triggered_by: str          # "neg_exp_batch" | "patched_cve" | "manual"
    dry_run: bool
    total_neg_exps_scanned: int = 0
    total_candidates_checked: int = 0
    total_rule_filtered: int = 0
    total_llm_judged: int = 0
    total_conflicts_found: int = 0
    total_entries_updated: int = 0
    by_sub_dimension: Dict[str, int] = field(default_factory=dict)
    by_knowledge_layer: Dict[str, int] = field(default_factory=dict)
    entries_updated: List[Dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())


# ─────────────────────────────────────────────────────────────────────────────
# 辅助：token 重叠率
# ─────────────────────────────────────────────────────────────────────────────

_NON_WORD = re.compile(r"[^\w\u4e00-\u9fff]+")

def _tokenize(text: str) -> set:
    """粗粒度分词：按非字符边界分割，保留汉字+英文单词。"""
    tokens = _NON_WORD.split(text.lower())
    return {t for t in tokens if len(t) >= 2}


def _overlap_ratio(text_a: str, text_b: str) -> float:
    """计算两文本 token 集合的 Jaccard 相似度。"""
    a, b = _tokenize(text_a), _tokenize(text_b)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _has_recommend_signal(text: str) -> bool:
    """判断文本是否含有「推荐/建议使用」语义信号。"""
    return any(kw in text for kw in CONFLICT_SIGNAL_KEYWORDS)


# ─────────────────────────────────────────────────────────────────────────────
# 后端抽象
# ─────────────────────────────────────────────────────────────────────────────

class LocalKLMBackend:
    """
    本地 JSONL 后端。

    操作范围：
      - phase5_klm_registry.jsonl  ← 原始/分层经验
      - phase34_consolidated.jsonl ← 融合后经验（额外候选）

    写操作：
      1. 修改内存中的 exp dict（lifecycle_status / deprecated_reason 字段）
      2. 整体原子写回（先写 .tmp 再 rename）
    """

    def __init__(
        self,
        klm_path: Path = KLM_REGISTRY_FILE,
        consolidated_path: Optional[Path] = CONSOLIDATED_FILE,
    ) -> None:
        self.klm_path = klm_path
        self.consolidated_path = consolidated_path
        self._entries: List[Dict[str, Any]] = []
        self._consolidated: List[Dict[str, Any]] = []
        self._loaded = False

    # ── 加载 ──────────────────────────────────────────────────────────────────

    def load(self) -> None:
        """从磁盘加载 KLM 数据，支持重复调用（幂等）。"""
        self._entries = list(_read_jsonl(self.klm_path)) if self.klm_path.exists() else []
        if self.consolidated_path and self.consolidated_path.exists():
            self._consolidated = list(_read_jsonl(self.consolidated_path))
        else:
            self._consolidated = []
        self._loaded = True
        logger.info(
            "LocalKLMBackend 已加载 %d 条 KLM + %d 条 consolidated",
            len(self._entries), len(self._consolidated),
        )

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ── 迭代器 ────────────────────────────────────────────────────────────────

    def iter_by_layer(self, layer: str, status: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """按 knowledge_layer （+ 可选 lifecycle_status）过滤迭代。"""
        self._ensure_loaded()
        for entry in self._entries:
            if entry.get("knowledge_layer") != layer:
                continue
            if status and entry.get("lifecycle_status") != status:
                continue
            yield entry

    def iter_all_active_pos(self) -> Iterator[Dict[str, Any]]:
        """迭代所有 active/conflicted PROCEDURAL_POS 和 CONCEPTUAL 条目（CVE 废弃检测用）。"""
        self._ensure_loaded()
        target_layers = {"PROCEDURAL_POS", "CONCEPTUAL", "FACTUAL_LLM"}
        target_statuses = {"active", "conflicted"}
        for entry in self._entries + self._consolidated:
            if entry.get("knowledge_layer") in target_layers:
                if entry.get("lifecycle_status") in target_statuses:
                    yield entry

    def iter_consolidated_candidates(self, layer: str) -> Iterator[Dict[str, Any]]:
        """从 consolidated 文件中迭代指定层候选。"""
        self._ensure_loaded()
        for entry in self._consolidated:
            if entry.get("knowledge_layer") == layer:
                yield entry

    # ── 候选搜索 ─────────────────────────────────────────────────────────────

    def search_candidates(
        self,
        query: str,
        top_k: int = 15,
        exclude_layers: Optional[List[str]] = None,
        allowed_layers: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        基于 token 重叠率搜索候选冲突条目（替代 RAGFlow 向量搜索）。

        候选来源：
          - KLM registry（active / conflicted 状态）
          - consolidated（active 状态）

        Parameters
        ----------
        allowed_layers : 若指定，则只返回这些 knowledge_layer 的条目。
                         与 exclude_layers 互斥；两者均指定时 allowed_layers 优先。
        """
        self._ensure_loaded()
        _allowed = frozenset(allowed_layers) if allowed_layers else None
        _excluded = set(exclude_layers or []) if not _allowed else set()
        exclude_ids = set(exclude_ids or [])

        scored: List[Tuple[float, Dict[str, Any]]] = []
        seen_ids: set = set()

        def _score_entry(entry: Dict[str, Any]) -> None:
            eid = entry.get("exp_id", "")
            if eid in seen_ids or eid in exclude_ids:
                return
            layer = entry.get("knowledge_layer", "")
            if _allowed is not None:
                if layer not in _allowed:
                    return
            elif layer in _excluded:
                return
            if entry.get("lifecycle_status") == "archived":
                return
            seen_ids.add(eid)

            # 构建候选文本：内容字段拼接
            candidate_text = _entry_to_searchable_text(entry)
            score = _overlap_ratio(query, candidate_text)
            if score > 0:
                scored.append((score, entry))

        for entry in self._entries:
            _score_entry(entry)
        for entry in self._consolidated:
            _score_entry(entry)

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:top_k]]

    # ── 更新 ─────────────────────────────────────────────────────────────────

    def update_lifecycle(
        self,
        exp_id: str,
        new_status: str,
        reason: str,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """更新单个条目的 lifecycle_status（内存）。"""
        self._ensure_loaded()
        for entry in self._entries:
            if entry.get("exp_id") == exp_id:
                entry["lifecycle_status"] = new_status
                entry["conflict_reason"] = reason
                entry["conflict_updated_at"] = datetime.now(tz=timezone.utc).isoformat()
                if extra_fields:
                    entry.update(extra_fields)
                return True
        # 也在 consolidated 中查找（标记但不回写 consolidated）
        for entry in self._consolidated:
            if entry.get("exp_id") == exp_id:
                entry["lifecycle_status"] = new_status
                entry["conflict_reason"] = reason
                entry["conflict_updated_at"] = datetime.now(tz=timezone.utc).isoformat()
                if extra_fields:
                    entry.update(extra_fields)
                return True
        return False

    # ── 持久化 ───────────────────────────────────────────────────────────────

    def commit(self, dry_run: bool = False) -> int:
        """
        将内存变更原子写回磁盘（先写 .tmp 再 rename）。
        同时保存 _entries（phase5_klm_registry.jsonl）和
        _consolidated（phase34_consolidated.jsonl），确保 reflux 元数据持久化。
        Returns: 已写入条目数（两个文件合计）。
        """
        self._ensure_loaded()
        if dry_run:
            logger.info("[dry-run] 跳过写回磁盘（%d 条 KLM + %d 条 consolidated）",
                        len(self._entries), len(self._consolidated))
            return len(self._entries)

        total = 0

        # ── 写回 KLM registry ─────────────────────────────────────────────
        if self.klm_path.exists():
            shutil.copy2(self.klm_path, self.klm_path.with_suffix(".jsonl.bak"))
            logger.debug("已备份 KLM 文件 → %s", self.klm_path.with_suffix(".jsonl.bak"))

        tmp_path = self.klm_path.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                for entry in self._entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            tmp_path.replace(self.klm_path)
            logger.info("KLM 文件已更新：%s（%d 条）", self.klm_path, len(self._entries))
            total += len(self._entries)
        except Exception as exc:
            if tmp_path.exists():
                tmp_path.unlink()
            raise RuntimeError(f"KLM 写回失败: {exc}") from exc

        # ── 写回 consolidated ─────────────────────────────────────────────
        if self._consolidated and self.consolidated_path:
            if self.consolidated_path.exists():
                shutil.copy2(self.consolidated_path,
                             self.consolidated_path.with_suffix(".jsonl.bak"))
            tmp_c = self.consolidated_path.with_suffix(".jsonl.tmp")
            try:
                with open(tmp_c, "w", encoding="utf-8") as f:
                    for entry in self._consolidated:
                        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                tmp_c.replace(self.consolidated_path)
                logger.info("Consolidated 文件已更新：%s（%d 条）",
                            self.consolidated_path, len(self._consolidated))
                total += len(self._consolidated)
            except Exception as exc:
                if tmp_c.exists():
                    tmp_c.unlink()
                raise RuntimeError(f"Consolidated 写回失败: {exc}") from exc

        return total

    # ── 查询 ─────────────────────────────────────────────────────────────────

    def get(self, exp_id: str) -> Optional[Dict[str, Any]]:
        """按 exp_id 获取单条经验（优先 KLM registry，其次 consolidated）。"""
        self._ensure_loaded()
        for entry in self._entries:
            if entry.get("exp_id") == exp_id:
                return entry
        for entry in self._consolidated:
            if entry.get("exp_id") == exp_id:
                return entry
        return None

    def query(
        self,
        lifecycle: Optional[str] = None,
        maturity: Optional[str] = None,
        should_reflux: Optional[bool] = None,
        refluxed: Optional[bool] = None,
        not_ragflow_uploaded: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        多条件过滤查询 KLM 条目。

        Parameters
        ----------
        lifecycle          : 过滤 lifecycle_status（如 "active"）
        maturity           : 过滤 maturity（如 "consolidated"）
        should_reflux      : True = should_reflux=True 或 klm_reflux_timestamp 存在
        refluxed           : True = ragflow_doc_id 非空，False = ragflow_doc_id 为空
        not_ragflow_uploaded: True 时等同于 refluxed=False（语义糖）
        """
        self._ensure_loaded()
        # 合并来源：KLM registry + consolidated（合并时去重）
        all_entries: List[Dict[str, Any]] = []
        seen: set = set()
        for e in self._entries + self._consolidated:
            eid = e.get("exp_id", "")
            if eid not in seen:
                seen.add(eid)
                all_entries.append(e)

        result = []
        for entry in all_entries:
            if lifecycle and entry.get("lifecycle_status") != lifecycle:
                continue
            if maturity and entry.get("maturity") != maturity:
                continue
            if should_reflux is not None:
                # 判断逻辑：should_reflux 字段=True，或存在 klm_reflux_timestamp，
                # 或（consolidated + active）时自动视为 should_reflux=True
                sr = entry.get("should_reflux")
                ts = entry.get("klm_reflux_timestamp")
                auto_reflux = (
                    entry.get("maturity") == "consolidated"
                    and entry.get("lifecycle_status") == "active"
                )
                effective_should_reflux = bool(sr) or bool(ts) or auto_reflux
                if effective_should_reflux != should_reflux:
                    continue
            if refluxed is not None or not_ragflow_uploaded:
                target_refluxed = False if not_ragflow_uploaded else refluxed
                has_doc_id = bool(entry.get("ragflow_doc_id"))
                if has_doc_id != target_refluxed:
                    continue
            result.append(entry)
        return result

    # ── 回流相关 ─────────────────────────────────────────────────────────────

    def mark_refluxed(self, exp_id: str, ragflow_doc_id: str) -> bool:
        """记录经验已成功写入 RAGFlow，填写 doc_id 和时间戳。"""
        self._ensure_loaded()
        now = datetime.now(tz=timezone.utc).isoformat()
        for entry in self._entries + self._consolidated:
            if entry.get("exp_id") == exp_id:
                entry["ragflow_doc_id"] = ragflow_doc_id
                entry["refluxed"] = True
                entry["reflux_at"] = now
                return True
        return False

    def clear_ragflow_doc_id(self, exp_id: str) -> bool:
        """清除经验的 RAGFlow doc_id（当文档被删除后调用）。"""
        self._ensure_loaded()
        for entry in self._entries + self._consolidated:
            if entry.get("exp_id") == exp_id:
                entry["ragflow_doc_id"] = None
                entry["ragflow_chunk_ids"] = []
                entry["refluxed"] = False
                entry["reflux_at"] = None
                return True
        return False

    # ── 字段更新 ─────────────────────────────────────────────────────────────

    def update_fields(self, exp_id: str, **fields: Any) -> bool:
        """通用字段更新：对指定 exp_id 批量设置字段值。"""
        self._ensure_loaded()
        for entry in self._entries + self._consolidated:
            if entry.get("exp_id") == exp_id:
                entry.update(fields)
                return True
        return False

    def update_p_fused(self, exp_id: str, p_fused: float) -> bool:
        """更新融合置信度。"""
        return self.update_fields(exp_id, p_fused=p_fused)

    def update_maturity(self, exp_id: str, maturity: str) -> bool:
        """更新 maturity 级别（raw → validated → consolidated）。"""
        return self.update_fields(exp_id, maturity=maturity)

    def set_conflict_fields(
        self,
        exp_id: str,
        reason: str,
        triggered_by: Optional[str] = None,
    ) -> bool:
        """将经验标记为 conflicted 并记录原因和触发者。"""
        return self.update_fields(
            exp_id,
            lifecycle_status="conflicted",
            conflict_reason=reason,
            conflict_triggered_by=triggered_by,
            conflict_updated_at=datetime.now(tz=timezone.utc).isoformat(),
        )

    # ── 写入新经验 ───────────────────────────────────────────────────────────

    def add_experiences(
        self,
        exps: List[Dict[str, Any]],
        lifecycle: str = "active",
        maturity: str = "raw",
    ) -> List[str]:
        """
        批量写入新的原始经验（Layer2 产出）到内存，commit() 后持久化。

        Returns: 已写入的 exp_id 列表。
        """
        self._ensure_loaded()
        added_ids: List[str] = []
        existing_ids = {e.get("exp_id") for e in self._entries}
        now = datetime.now(tz=timezone.utc).isoformat()
        for exp in exps:
            eid = exp.get("exp_id", "")
            if eid in existing_ids:
                logger.debug("add_experiences: 跳过重复 exp_id=%s", eid)
                continue
            new_entry = dict(exp)
            new_entry.setdefault("lifecycle_status", lifecycle)
            new_entry.setdefault("maturity", maturity)
            new_entry.setdefault("ragflow_doc_id", None)
            new_entry.setdefault("ragflow_chunk_ids", [])
            new_entry.setdefault("refluxed", False)
            new_entry.setdefault("reflux_at", None)
            new_entry.setdefault("conflict_reason", None)
            new_entry.setdefault("conflict_triggered_by", None)
            new_entry.setdefault("merged_into", None)
            new_entry.setdefault("added_at", now)
            self._entries.append(new_entry)
            existing_ids.add(eid)
            added_ids.append(eid)
        logger.info("add_experiences: 写入 %d 条（含重复跳过 %d 条）",
                    len(added_ids), len(exps) - len(added_ids))
        return added_ids

    def add_consolidated(self, consolidated: Dict[str, Any]) -> bool:
        """
        将 consolidated 经验写入 KLM registry（Phase3-4 融合后调用）。
        同时确保新增字段已初始化。
        """
        self._ensure_loaded()
        eid = consolidated.get("exp_id", "")
        existing_ids = {e.get("exp_id") for e in self._entries}
        if eid in existing_ids:
            logger.debug("add_consolidated: 跳过重复 exp_id=%s", eid)
            return False
        entry = dict(consolidated)
        entry.setdefault("lifecycle_status", "active")
        entry.setdefault("ragflow_doc_id", None)
        entry.setdefault("ragflow_chunk_ids", [])
        entry.setdefault("refluxed", False)
        entry.setdefault("reflux_at", None)
        entry.setdefault("conflict_reason", None)
        entry.setdefault("conflict_triggered_by", None)
        entry.setdefault("merged_into", None)
        entry.setdefault("added_at", datetime.now(tz=timezone.utc).isoformat())
        self._entries.append(entry)
        logger.debug("add_consolidated: 写入 exp_id=%s", eid)
        return True

    def suspend_source_exps(self, source_ids: List[str], merged_into: str) -> int:
        """
        将源经验（被 consolidated 消耗的）状态改为 suspended，
        并填写 merged_into 字段（BUG-4 修复）。
        Returns: 实际更新的条目数。
        """
        self._ensure_loaded()
        count = 0
        source_set = set(source_ids)
        for entry in self._entries:
            if entry.get("exp_id") in source_set:
                entry["lifecycle_status"] = "suspended"
                if not entry.get("merged_into"):
                    entry["merged_into"] = merged_into
                count += 1
        logger.info("suspend_source_exps: merged_into=%s  suspended %d 条", merged_into, count)
        return count

    # ── 融合阈值检测 ─────────────────────────────────────────────────────────

    def find_clusters_above_threshold(
        self,
        maturity: str = "raw",
        min_count: int = 3,
    ) -> List[str]:
        """
        返回满足融合门槛的 cluster_id 列表。

        cluster_id 从 metadata.cluster_id 或 content.failure_sub_dimension
        等字段推断（当前简化版：将同 knowledge_layer + target_service + cve_ids
        的经验归为同一 cluster）。

        仅扫描 lifecycle_status='active' 且 maturity=maturity 的原始经验。
        """
        self._ensure_loaded()
        from collections import Counter

        cluster_counter: Counter = Counter()
        for entry in self._entries:
            if (entry.get("lifecycle_status") == "active"
                    and entry.get("maturity") == maturity):
                # 以 knowledge_layer + target_service 作为简化 cluster key
                layer = entry.get("knowledge_layer", "UNKNOWN")
                svc = (
                    entry.get("target_service")
                    or entry.get("metadata", {}).get(
                        "applicable_constraints", {}
                    ).get("target_service", "")
                    or "UNKNOWN"
                )
                cluster_key = f"{layer}::{svc}"
                cluster_counter[cluster_key] += 1

        return [k for k, v in cluster_counter.items() if v >= min_count]


class RAGFlowBackend:
    """
    RAGFlow 后端占位符（TODO: 接入 RAGFlow REST API）。

    当 RAGFlow URL 配置后，替换 LocalKLMBackend 即可，
    外部接口保持一致（search_candidates / update_lifecycle / commit）。
    """

    def __init__(self, ragflow_client: Any = None) -> None:
        self._client = ragflow_client

    def load(self) -> None:
        # TODO: 初始化 RAGFlow 连接，拉取 dataset 元数据
        raise NotImplementedError(
            "RAGFlowBackend 尚未就绪 — 请先配置 ragflow_url 并调用 "
            "ragflow_client.RAGFlowClient()，然后将本类实例传入 ConflictDetector"
        )

    def search_candidates(self, query: str, top_k: int = 15, **kwargs) -> List[Dict[str, Any]]:
        # TODO: self._client.search(query, top_k=top_k)
        raise NotImplementedError("RAGFlowBackend.search_candidates 尚未实现")

    def update_lifecycle(self, exp_id: str, new_status: str, reason: str, **kwargs) -> bool:
        # TODO: self._client.add_warning_tag(chunk_id, doc_id, reason)
        raise NotImplementedError("RAGFlowBackend.update_lifecycle 尚未实现")

    def commit(self, dry_run: bool = False) -> int:
        # TODO: 批量提交 tag 更新到 RAGFlow
        raise NotImplementedError("RAGFlowBackend.commit 尚未实现")


# ─────────────────────────────────────────────────────────────────────────────
# 核心：ConflictDetector
# ─────────────────────────────────────────────────────────────────────────────

class ConflictDetector:
    """
    冲突检测器。

    用法（本地 KLM 模式）::

        detector = ConflictDetector(backend=LocalKLMBackend())
        detector.load()
        report = detector.process_all_neg_exps()
        detector.commit()

    用法（RAGFlow 模式，待接入）::

        from .ragflow_client import RAGFlowClient
        client = RAGFlowClient(base_url=..., api_key=..., dataset_id=...)
        detector = ConflictDetector(backend=RAGFlowBackend(client), llm_client=my_llm)
        detector.load()
        report = detector.process_all_neg_exps()
        detector.commit()
    """

    def __init__(
        self,
        backend: LocalKLMBackend | RAGFlowBackend | None = None,
        llm_client: Any = None,
        dry_run: bool = False,
        overlap_threshold: float = RULE_OVERLAP_THRESHOLD,
        use_llm: bool = True,
    ) -> None:
        self.backend  = backend or LocalKLMBackend()
        self.llm      = llm_client
        self.dry_run  = dry_run
        self.overlap_threshold = overlap_threshold
        # 仅当 llm_client 存在且 use_llm=True 时启用 LLM 精判
        self.use_llm  = use_llm and (llm_client is not None)
        self._matches: List[ConflictMatch] = []
        self._loaded  = False

    # ── 初始化 ────────────────────────────────────────────────────────────────

    def load(self) -> None:
        """加载后端数据。"""
        self.backend.load()
        self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ─────────────────────────────────────────────────────────────────────────
    # 场景 A：新增负向经验触发
    # ─────────────────────────────────────────────────────────────────────────

    def process_neg_exp(self, exp: Dict[str, Any]) -> int:
        """
        处理单条 PROCEDURAL_NEG 经验，检测并标记知识库中的冲突条目。

        检测逻辑（三层递进）：
          层1 Rule: token overlap ≥ threshold  → 进入层2
          层2 Signal: 候选包含「推荐」语义      → 进入层3（或直接标记）
          层3 LLM:   可选精判（offline 可跳过）

        Returns: 本次标记的条目数。
        """
        self._ensure_loaded()

        content  = exp.get("content", {})
        exp_id   = exp.get("exp_id", "unknown")
        sub_dim  = content.get("failure_sub_dimension", "")
        fail_dim = content.get("failure_dimension", "")

        # ── 构建搜索查询 ──────────────────────────────────────────────────────
        query_parts = []
        avoid = content.get("avoid_pattern", "")
        if avoid:
            query_parts.append(avoid[:200])
        failed_cmd = content.get("failed_command", "")
        if failed_cmd:
            query_parts.append(failed_cmd[:100])
        decision_if = ""
        dr = content.get("decision_rule", {})
        if isinstance(dr, dict):
            decision_if = str(dr.get("IF", ""))[:150]
            if decision_if:
                query_parts.append(decision_if)
        # 追加 CVE IDs
        cve_ids: List[str] = []
        constraints = exp.get("metadata", {}).get("applicable_constraints", {})
        if isinstance(constraints, dict):
            cve_ids = constraints.get("cve_ids", [])
        query_parts.extend(cve_ids)
        query = " ".join(query_parts).strip()
        if not query:
            logger.debug("neg_exp %s 无有效 query，跳过", exp_id)
            return 0

        # ── 候选搜索（BUG-2：只在 PROCEDURAL_POS 中查找，其余层不检测）────────
        candidates = self.backend.search_candidates(
            query=query,
            top_k=20,
            allowed_layers=list(CONFLICT_TARGET_LAYERS),
            exclude_ids=[exp_id],
        )

        tagged = 0
        for candidate in candidates:
            c_id   = candidate.get("exp_id", "")
            c_text = _entry_to_searchable_text(candidate)

            # ── 约束门：服务名 + CVE 硬性过滤（BUG-3 修复）─────────────────
            if not _constraint_gate(exp, candidate):
                logger.debug(
                    "  [SKIP-CONSTRAINT] %s vs %s 服务/CVE不匹配，跳过",
                    exp_id[:14], c_id[:14],
                )
                continue

            # ── 三档重叠率阈值（BUG-1 修复）────────────────────────────
            overlap = _overlap_ratio(query, c_text)
            logger.debug(
                "  [score] %s(%s) overlap=%.3f",
                c_id[:16], candidate.get("knowledge_layer", ""), overlap,
            )

            if overlap < LLM_GATE_THRESHOLD:
                # 相似度不足：rule OK，直接跳过
                continue

            # ── 推荐语义过滤（仍保留，PROCEDURAL_POS 应含有推荐信号）───
            if not _has_recommend_signal(c_text):
                continue

            # ── 判定：高重叠直接 CONFLICT；中等重叠走 LLM ───────────────
            if overlap >= RULE_CONFLICT_THRESHOLD:
                judge_method = "rule"
                verdict = "CONFLICT"
            elif self.use_llm:
                verdict = self._llm_judge(
                    neg_exp_content=str(content)[:600],
                    kb_content=c_text[:900],
                )
                judge_method = "llm"
            else:
                # 无 LLM 且 overlap 处于中间带：保守跳过，不标记
                logger.debug(
                    "  [SKIP] overlap=%.3f 处于 LLM 区间但无 LLM 客户端，跳过 %s",
                    overlap, c_id[:12],
                )
                continue

            if verdict != "CONFLICT":
                continue

            # ── 执行标记 ─────────────────────────────────────────────────
            old_status = candidate.get("lifecycle_status", "active")
            new_status = "conflicted"
            reason = (
                f"neg_exp_conflict: [{sub_dim}/{fail_dim}] "
                f"triggered by {exp_id}"
            )
            match = ConflictMatch(
                source_exp_id=exp_id,
                target_exp_id=c_id,
                target_layer=candidate.get("knowledge_layer", ""),
                conflict_type="neg_exp_conflict",
                old_status=old_status,
                new_status=new_status,
                rule_overlap=round(overlap, 4),
                judge_method=judge_method,
                judge_result=verdict,
                reason=reason,
                dry_run=self.dry_run,
            )
            self._matches.append(match)

            if not self.dry_run:
                self.backend.update_lifecycle(c_id, new_status, reason)

            tagged += 1
            logger.info(
                "  [%s] 标记冲突: %s(%s) → %s  overlap=%.3f  method=%s",
                "DRY" if self.dry_run else "ACT",
                c_id[:12], candidate.get("knowledge_layer", ""),
                new_status, overlap, judge_method,
            )

        return tagged

    def process_all_neg_exps(
        self,
        klm_path: Optional[Path] = None,
        run_id: Optional[str] = None,
    ) -> ConflictReport:
        """
        批量处理 KLM 中所有 active 的 PROCEDURAL_NEG 条目。

        Parameters
        ----------
        klm_path : 覆盖默认 KLM 路径（调试/测试用）
        run_id   : 可读标识符；默认自动生成

        Returns
        -------
        ConflictReport 本次运行统计
        """
        self._ensure_loaded()
        run_id = run_id or f"neg_exp_{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        report = ConflictReport(
            run_id=run_id,
            triggered_by="neg_exp_batch",
            dry_run=self.dry_run,
        )

        # 迭代所有 active 负向经验（consolidated 中的也包含）
        neg_exps: List[Dict[str, Any]] = []
        if isinstance(self.backend, LocalKLMBackend):
            for e in self.backend.iter_by_layer("PROCEDURAL_NEG", status="active"):
                neg_exps.append(e)
            # 也扫描 consolidated 中的 PROCEDURAL_NEG
            for e in self.backend.iter_consolidated_candidates("PROCEDURAL_NEG"):
                if e.get("lifecycle_status") == "active":
                    neg_exps.append(e)
        else:
            raise TypeError("process_all_neg_exps 当前仅支持 LocalKLMBackend")

        report.total_neg_exps_scanned = len(neg_exps)
        logger.info(
            "[ConflictDetector] 开始批量冲突检测：%d 条 PROCEDURAL_NEG，dry_run=%s",
            len(neg_exps), self.dry_run,
        )

        sub_dim_counts: Dict[str, int] = {}
        layer_counts: Dict[str, int] = {}

        for exp in neg_exps:
            sub_dim = exp.get("content", {}).get("failure_sub_dimension", "UNKNOWN")
            tagged = self.process_neg_exp(exp)
            if tagged > 0:
                report.total_conflicts_found += tagged
                sub_dim_counts[sub_dim] = sub_dim_counts.get(sub_dim, 0) + tagged
                for m in self._matches[-tagged:]:
                    layer_counts[m.target_layer] = layer_counts.get(m.target_layer, 0) + 1
                    report.entries_updated.append({
                        "source": m.source_exp_id,
                        "target": m.target_exp_id,
                        "layer": m.target_layer,
                        "old_status": m.old_status,
                        "new_status": m.new_status,
                        "method": m.judge_method,
                        "reason": m.reason,
                    })

        report.total_candidates_checked = len(self._matches)  # 粗估
        report.total_entries_updated    = report.total_conflicts_found
        report.by_sub_dimension         = sub_dim_counts
        report.by_knowledge_layer       = layer_counts

        return report

    # ─────────────────────────────────────────────────────────────────────────
    # 场景 B：P2 周任务 — 已修补 CVE 扫描
    # ─────────────────────────────────────────────────────────────────────────

    def check_patched_cves(
        self,
        patched_cves: List[str],
        run_id: Optional[str] = None,
    ) -> ConflictReport:
        """
        P2 周任务：将仍推荐「已修补 CVE」利用的条目标记为 suspended。

        判定规则（无需 LLM）：
          - 条目关联的 cve_ids 与 patched_cves 有交集
          - 条目的 content 包含利用意图词（exploit/payload/poc/利用/执行命令）
          - 条目 lifecycle_status 为 active

        Parameters
        ----------
        patched_cves : 已确认修补的 CVE 列表（从 NVD 或手工维护）

        Returns
        -------
        ConflictReport 本次运行统计
        """
        self._ensure_loaded()
        run_id = run_id or f"patched_cve_{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        report = ConflictReport(
            run_id=run_id,
            triggered_by="patched_cve",
            dry_run=self.dry_run,
        )

        patched_set = set(c.strip().upper() for c in patched_cves)
        _EXPLOIT_SIGNALS = re.compile(
            r"exploit|payload|poc|reverse shell|利用|执行命令|getshell|rce|反弹",
            re.IGNORECASE,
        )

        tagged = 0
        for entry in self.backend.iter_all_active_pos():
            exp_id = entry.get("exp_id", "")
            constraints = entry.get("metadata", {}).get("applicable_constraints", {})
            if not isinstance(constraints, dict):
                constraints = {}
            entry_cves = {c.upper() for c in constraints.get("cve_ids", [])}
            # 也检查 tags 中的 CVE
            for tag in entry.get("metadata", {}).get("tags", []):
                if tag.upper().startswith("CVE-"):
                    entry_cves.add(tag.upper())

            common_cves = entry_cves & patched_set
            if not common_cves:
                continue

            # 检查条目内容是否含「利用」意图
            content_text = _entry_to_searchable_text(entry)
            if not _EXPLOIT_SIGNALS.search(content_text):
                continue

            old_status = entry.get("lifecycle_status", "active")
            new_status = "suspended"
            cvelist_str = ", ".join(sorted(common_cves))
            reason = f"CVE_DEPRECATED: {cvelist_str} 已确认修补，推荐利用不再有效"

            # 记录匹配
            match = ConflictMatch(
                source_exp_id="patched_cve_scanner",
                target_exp_id=exp_id,
                target_layer=entry.get("knowledge_layer", ""),
                conflict_type="cve_deprecated",
                old_status=old_status,
                new_status=new_status,
                rule_overlap=1.0,  # 规则精确匹配
                judge_method="rule",
                judge_result="CONFLICT",
                reason=reason,
                dry_run=self.dry_run,
            )
            self._matches.append(match)
            report.entries_updated.append({
                "source": "patched_cve_scanner",
                "target": exp_id,
                "layer": entry.get("knowledge_layer", ""),
                "old_status": old_status,
                "new_status": new_status,
                "matched_cves": sorted(common_cves),
                "method": "rule",
                "reason": reason,
            })

            if not self.dry_run:
                self.backend.update_lifecycle(
                    exp_id, new_status, reason,
                    extra_fields={"deprecated_cves": sorted(common_cves)},
                )

            tagged += 1
            logger.info(
                "  [%s] CVE废弃标记: %s ← {%s} → %s",
                "DRY" if self.dry_run else "ACT",
                exp_id[:12], cvelist_str, new_status,
            )

        report.total_neg_exps_scanned = 0
        report.total_conflicts_found  = tagged
        report.total_entries_updated  = tagged
        report.by_knowledge_layer = _count_by_key(report.entries_updated, "layer")

        return report

    # ─────────────────────────────────────────────────────────────────────────
    # LLM 调用封装
    # ─────────────────────────────────────────────────────────────────────────

    def _llm_judge(self, neg_exp_content: str, kb_content: str) -> str:
        """
        调用 LLM 判断是否冲突，返回 'CONFLICT' 或 'OK'。
        如果 LLM 调用失败则 fallback 返回 'CONFLICT'（保守策略）。
        """
        prompt = _CONFLICT_PROMPT.format(
            neg_exp_content=neg_exp_content,
            kb_content=kb_content,
        )
        try:
            raw = self.llm.complete(prompt)
            verdict = raw.strip().upper()
            if "CONFLICT" in verdict:
                return "CONFLICT"
            if "OK" in verdict:
                return "OK"
            # 模糊输出：保守处理
            logger.debug("LLM 输出不明确：%r，回退为 CONFLICT", raw[:80])
            return "CONFLICT"
        except Exception as exc:
            logger.warning("LLM 判断失败（%s），保守回退为 CONFLICT", exc)
            return "CONFLICT"

    # ─────────────────────────────────────────────────────────────────────────
    # 持久化与报告
    # ─────────────────────────────────────────────────────────────────────────

    def commit(self) -> int:
        """将后端的内存变更写回磁盘。"""
        return self.backend.commit(dry_run=self.dry_run)

    def write_report(
        self,
        report: ConflictReport,
        report_path: Path = CONFLICT_REPORT_FILE,
        summary_path: Path = CONFLICT_SUMMARY_FILE,
    ) -> None:
        """
        将审计记录追加到 conflict_report.jsonl，
        并将本次统计写入 conflict_summary.json（覆盖）。
        """
        report_path.parent.mkdir(parents=True, exist_ok=True)

        if report.dry_run:
            logger.info("[dry-run] 跳过报告写磁盘（conflict_report / conflict_summary）")
            return

        # 追加审计条目
        with open(report_path, "a", encoding="utf-8") as f:
            for m in self._matches:
                rec = asdict(m)
                rec["run_id"] = report.run_id
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        # 覆盖统计摘要
        summary_data = asdict(report)
        summary_data.pop("entries_updated", None)  # 摘要不需要明细列表
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, ensure_ascii=False, indent=2)

        logger.info(
            "冲突报告已写入: %s  统计: %s",
            report_path.name, summary_path.name,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _extract_service_cve(exp: Dict[str, Any]) -> tuple:
    """从经验条目中提取 (target_service_lower, cve_ids_upper_set)。"""
    constraints = exp.get("metadata", {}).get("applicable_constraints", {})
    if not isinstance(constraints, dict):
        constraints = {}
    service = constraints.get("target_service", "").strip().lower()
    # 同时也从 metadata.tags 中收集 CVE
    cves: set = {c.upper() for c in constraints.get("cve_ids", []) if c}
    for tag in exp.get("metadata", {}).get("tags", []):
        if str(tag).upper().startswith("CVE-"):
            cves.add(str(tag).upper())
    return service, cves


def _constraint_gate(neg_exp: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    """
    服务名 + CVE 硬性前置过滤门（BUG-3 修复）。

    返回 False 意味着两条经验属于不同服务/漏洞领域，
    文本相似纯属「都是 Python 脚本」等偶然相似，不构成语义冲突。

    判定规则（保守策略：信息不足时放行）：
      1. 双方均有 target_service 且不同   → False（不同服务）
      2. 双方均有 cve_ids 且无交集        → False（不同漏洞）
      其余情况                            → True（允许进入 overlap 计算）
    """
    svc_a, cves_a = _extract_service_cve(neg_exp)
    svc_b, cves_b = _extract_service_cve(candidate)

    # 规则 1：服务名硬性门
    if svc_a and svc_b and svc_a != svc_b:
        return False

    # 规则 2：CVE 硬性门
    if cves_a and cves_b and not (cves_a & cves_b):
        return False

    return True


def _read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    """逐行读取 JSONL，容忍空行和格式错误。"""
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("JSONL 解析失败 %s:%d — %s", path.name, lineno, exc)


def _entry_to_searchable_text(entry: Dict[str, Any]) -> str:
    """
    将 KLM 经验条目的关键字段拼接为单一检索字符串。

    覆盖字段：
      - content 中的 avoid_pattern / failed_command / decision_rule / key_lessons
      - metadata.tags
    """
    parts: List[str] = []
    content = entry.get("content", {})

    if isinstance(content, dict):
        # PROCEDURAL_NEG
        for k in ("avoid_pattern", "failed_command", "failure_sub_dimension"):
            v = content.get(k, "")
            if v:
                parts.append(str(v)[:200])

        dr = content.get("decision_rule", {})
        if isinstance(dr, dict):
            if_cond = str(dr.get("IF", ""))[:150]
            if if_cond:
                parts.append(if_cond)
            for then_item in dr.get("THEN", [])[:5]:
                parts.append(str(then_item)[:100])

        # PROCEDURAL_POS
        cmd_tpl = content.get("command_template", "")
        if cmd_tpl:
            parts.append(str(cmd_tpl)[:200])

        # METACOGNITIVE
        for lesson in content.get("key_lessons", [])[:5]:
            parts.append(str(lesson)[:100])

        # FACTUAL_LLM / CONCEPTUAL
        core = content.get("core_insight", "")
        if core:
            parts.append(str(core)[:200])

    # metadata tags
    tags = entry.get("metadata", {}).get("tags", [])
    if tags:
        parts.append(" ".join(str(t) for t in tags[:10]))

    return " ".join(parts)


def _count_by_key(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    """统计列表中某字段的分布。"""
    counts: Dict[str, int] = {}
    for item in items:
        v = item.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts
