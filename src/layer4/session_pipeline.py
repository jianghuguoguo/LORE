"""
src/layer4/session_pipeline.py
================================
on_session_complete() — 每次渗透测试 Session 结束后触发的主流程。

流程（来自文档 §2.4）：
  Step 1: Layer2 → 写入原始经验到 KLM（lifecycle=active, maturity=raw）
  Step 2: 阈值检测 — 哪些 cluster 已满足融合门槛（≥ 3 条 raw 经验）
  Step 3: 对满足阈值的 cluster 执行 Layer3 Phase1-4 融合
  Step 4: 更新 KLM（写入 consolidated，挂起 suspended 源经验）
  Step 5: 冲突检测 — 对新增的 PROCEDURAL_NEG 经验运行 ConflictDetector
  Step 6: 生成 reflux_ready 候选列表
  Step 7: 写入 RAGFlow（flush_reflux_ready_to_ragflow）
  Step 8: 若有新 conflicted，从 RAGFlow 删除

关键设计原则：
  - 本地 KLM JSONL 是唯一 SoT（Source of Truth）
  - RAGFlow 只接收 active+consolidated 的经验
  - 冲突检测在本地完成，通过后才写入 RAGFlow
  - conflicted/suspended 永远不写入 RAGFlow

用法（集成模式）：
    from src.layer4.session_pipeline import on_session_complete, SessionPipelineConfig
    from src.ragflow.client import RAGFlowExpClient

    ragflow = RAGFlowExpClient()
    cfg = SessionPipelineConfig(ragflow_client=ragflow)
    result = on_session_complete("session_abc123", new_raw_exps, cfg=cfg)

用法（仅本地模式，不写 RAGFlow）：
    result = on_session_complete("session_abc123", new_raw_exps)
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ragflow.client import RAGFlowExpClient

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 路径常量
# ─────────────────────────────────────────────────────────────────────────────

_DATA_L3 = ROOT / "data" / "layer3_output"
_KLM_FILE        = _DATA_L3 / "phase5_klm_registry.jsonl"
_CONSOLIDATED    = _DATA_L3 / "phase34_consolidated.jsonl"
_REFLUX_READY    = _DATA_L3 / "phase5_reflux_ready.jsonl"
_EXPERIENCES_RAW = ROOT / "data" / "layer2_output" / "experience_raw.jsonl"

# ─────────────────────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionPipelineConfig:
    """on_session_complete 的可配置参数。"""

    # RAGFlow 客户端（None 时跳过 RAGFlow 写入）
    ragflow_client: Optional["RAGFlowExpClient"] = None

    # 融合触发门槛：同一 cluster 达到 min_fusion_count 条 raw 经验才触发 Layer3
    min_fusion_count: int = 3

    # 冲突检测阈值（三档）
    llm_gate_threshold: float = 0.20
    rule_conflict_threshold: float = 0.50

    # 是否开启 LLM 仲裁（需要有效的 llm_client）
    llm_client: Optional[Any] = None

    # dry_run: True 时全流程不写磁盘、不写 RAGFlow
    dry_run: bool = False

    # KLM 文件路径（测试时可覆盖）
    klm_path: Optional[Path] = None
    consolidated_path: Optional[Path] = None


@dataclass
class SessionPipelineResult:
    """on_session_complete 执行结果摘要。"""
    session_id:           str  = ""
    new_exps_added:       int  = 0
    clusters_fused:       int  = 0
    consolidated_added:   int  = 0
    source_exps_suspended: int = 0
    conflicts_found:      int  = 0
    newly_conflicted_ids: List[str] = field(default_factory=list)
    reflux_uploaded:      int  = 0
    reflux_failed:        int  = 0
    reflux_deleted_conflicted: int = 0
    error:                Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def on_session_complete(
    session_id: str,
    new_raw_exps: List[Dict[str, Any]],
    cfg: Optional[SessionPipelineConfig] = None,
) -> SessionPipelineResult:
    """
    每次 Session 结束后调用的主入口。

    Parameters
    ----------
    session_id   : 当前会话 ID（用于日志 + 溯源）
    new_raw_exps : Layer2 产出的原始经验列表（list of dict，尚未写 KLM）
    cfg          : 流程配置（含 RAGFlow 客户端、阈值等）

    Returns
    -------
    SessionPipelineResult : 各步骤计数摘要
    """
    cfg = cfg or SessionPipelineConfig()
    result = SessionPipelineResult(session_id=session_id)

    # 延迟导入避免循环依赖
    from src.layer4.conflict import LocalKLMBackend, ConflictDetector, CONFLICT_TARGET_LAYERS
    from src.layer4.reflux import flush_reflux_ready_to_ragflow, remove_conflicted_from_ragflow

    klm_path = cfg.klm_path or _KLM_FILE
    cons_path = cfg.consolidated_path or _CONSOLIDATED

    # ── Step 1: 写入原始经验到 KLM ──────────────────────────────────────────
    logger.info("[session %s] Step 1 — 写入 %d 条原始经验到 KLM", session_id, len(new_raw_exps))
    backend = LocalKLMBackend(klm_path=klm_path, consolidated_path=cons_path)
    backend.load()

    added_ids = backend.add_experiences(new_raw_exps, lifecycle="active", maturity="raw")
    result.new_exps_added = len(added_ids)

    if not cfg.dry_run and added_ids:
        backend.commit()

    # ── Step 2: 阈值检测 ─────────────────────────────────────────────────────
    logger.info("[session %s] Step 2 — 检测融合门槛（min=%d）", session_id, cfg.min_fusion_count)
    clusters_ready = backend.find_clusters_above_threshold(
        maturity="raw",
        min_count=cfg.min_fusion_count,
    )
    logger.info("[session %s] 满足阈值 cluster：%d 个 → %s",
                session_id, len(clusters_ready), clusters_ready[:5])

    # ── Step 3-4: Layer3 融合 ─────────────────────────────────────────────────
    if clusters_ready:
        result.clusters_fused = len(clusters_ready)
        logger.info("[session %s] Step 3-4 — 对 %d 个 cluster 执行 Layer3 融合",
                    session_id, len(clusters_ready))
        _run_layer3_for_clusters(session_id, clusters_ready, backend, result, cfg)
    else:
        logger.info("[session %s] Step 3-4 — 无满足阈值的 cluster，跳过 Layer3", session_id)

    # ── Step 5: 冲突检测 ─────────────────────────────────────────────────────
    new_neg_exps = [
        e for e in new_raw_exps
        if e.get("knowledge_layer") == "PROCEDURAL_NEG"
    ]
    if new_neg_exps:
        logger.info("[session %s] Step 5 — 冲突检测（%d 条 PROCEDURAL_NEG）",
                    session_id, len(new_neg_exps))
        newly_conflicted = _run_conflict_detection(
            session_id, new_neg_exps, backend, result, cfg
        )
    else:
        newly_conflicted = []
        logger.info("[session %s] Step 5 — 无 PROCEDURAL_NEG 经验，跳过冲突检测", session_id)

    result.newly_conflicted_ids = newly_conflicted

    # ── Step 6-7: 回流到 RAGFlow ─────────────────────────────────────────────
    if cfg.ragflow_client is not None:
        logger.info("[session %s] Step 6-7 — 写入 RAGFlow", session_id)
        reflux_result = flush_reflux_ready_to_ragflow(
            klm_backend=backend,
            ragflow_client=cfg.ragflow_client,
            llm_client=cfg.llm_client,
            dry_run=cfg.dry_run,
            commit=not cfg.dry_run,
        )
        result.reflux_uploaded = reflux_result.uploaded
        result.reflux_failed   = reflux_result.failed

        # ── Step 8: 删除 conflicted 文档 ─────────────────────────────────────
        if newly_conflicted:
            logger.info("[session %s] Step 8 — 删除 %d 条 conflicted 文档",
                        session_id, len(newly_conflicted))
            del_result = remove_conflicted_from_ragflow(
                klm_backend=backend,
                ragflow_client=cfg.ragflow_client,
                newly_conflicted_ids=newly_conflicted,
                dry_run=cfg.dry_run,
                commit=not cfg.dry_run,
            )
            result.reflux_deleted_conflicted = del_result.deleted_conflicted
    else:
        logger.info("[session %s] Step 6-7 — ragflow_client=None，跳过 RAGFlow 写入", session_id)

    logger.info(
        "[session %s] 完成 | "
        "新增=%d 融合=%d consolidated=%d suspended=%d "
        "冲突=%d 上传=%d 删除=%d",
        session_id,
        result.new_exps_added, result.clusters_fused,
        result.consolidated_added, result.source_exps_suspended,
        result.conflicts_found,
        result.reflux_uploaded, result.reflux_deleted_conflicted,
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 内部辅助：Layer3 融合
# ─────────────────────────────────────────────────────────────────────────────

def _run_layer3_for_clusters(
    session_id: str,
    clusters_ready: List[str],
    backend: Any,
    result: SessionPipelineResult,
    cfg: SessionPipelineConfig,
) -> None:
    """
    对满足阈值的 cluster 执行 Layer3 Phase1-4，将结果写回 KLM。

    Layer3 各 Phase 接受经验列表作为输入，当前实现调用现有脚本中的函数。
    若 Layer3 流程尚未模块化为可增量调用的接口，此处做最小封装：
    收集当前所有 raw+active 经验，运行完整 Layer3，将新 consolidated 写入 KLM。
    """
    try:
        from src.layer3 import (
            cluster_experiences,
            weight_equivalence_sets,
            run_rme,
            run_bcc,
            run_klm,
        )
    except ImportError as e:
        logger.error("[session %s] Layer3 导入失败: %s，跳过融合", session_id, e)
        result.error = f"Layer3 import error: {e}"
        return

    # 收集所有 active raw 经验（Layer3 需要全量数据做 SEC 聚类）
    all_raw = [
        e for e in backend._entries
        if e.get("lifecycle_status") == "active"
        and e.get("maturity") in ("raw", "validated")
    ]
    if not all_raw:
        logger.warning("[session %s] 无 active raw 经验可融合", session_id)
        return

    logger.info("[session %s] Layer3 输入: %d 条 active raw 经验", session_id, len(all_raw))

    try:
        # Phase 1: SEC 聚类
        eq_sets = cluster_experiences(all_raw)
        logger.info("[session %s] SEC 完成: %d 个等价集", session_id, len(eq_sets))

        # Phase 2: EWC 权重
        w_eq_sets = weight_equivalence_sets(eq_sets)

        # Phase 3: RME 合并
        merge_results = run_rme(w_eq_sets)

        # Phase 4: BCC 置信度校正
        # run_bcc 返回 (List[BccResult], List[ConsolidatedExp])
        wes_map = {wes.cluster.cluster_id: wes for wes in w_eq_sets}
        bcc_results, consolidated_exps = run_bcc(merge_results, wes_map)
        logger.info("[session %s] BCC 完成: %d 条 consolidated", session_id, len(consolidated_exps))

        # 写入 KLM：consolidated 经验 + 挂起源经验
        import dataclasses as _dc
        for ce in consolidated_exps:
            ce_dict = _dc.asdict(ce) if _dc.is_dataclass(ce) else dict(ce)

            if backend.add_consolidated(ce_dict):
                result.consolidated_added += 1

                # 挂起源经验
                prov = ce_dict.get("provenance") or {}
                src_ids = (
                    ce_dict.get("source_exp_ids")
                    or (prov.get("source_exp_ids") if isinstance(prov, dict) else [])
                    or []
                )
                if src_ids and ce_dict.get("exp_id"):
                    n = backend.suspend_source_exps(
                        source_ids=src_ids,
                        merged_into=ce_dict["exp_id"],
                    )
                    result.source_exps_suspended += n

        if not cfg.dry_run:
            backend.commit()

    except Exception as exc:
        logger.error("[session %s] Layer3 执行异常: %s", session_id, exc, exc_info=True)
        result.error = f"Layer3 error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# 内部辅助：冲突检测
# ─────────────────────────────────────────────────────────────────────────────

def _run_conflict_detection(
    session_id: str,
    new_neg_exps: List[Dict[str, Any]],
    backend: Any,
    result: SessionPipelineResult,
    cfg: SessionPipelineConfig,
) -> List[str]:
    """
    对新增的 PROCEDURAL_NEG 经验运行冲突检测。

    BUG-1 修复：三档阈值（0.20/0.50）
    BUG-2 修复：只检测 PROCEDURAL_POS layer
    BUG-3 修复：require_same_service + CVE 约束门（由 _constraint_gate 实现）

    Returns: newly_conflicted 的 exp_id 列表。
    """
    from src.layer4.conflict import ConflictDetector, CONFLICT_TARGET_LAYERS

    detector = ConflictDetector(
        backend=backend,
        dry_run=cfg.dry_run,
        overlap_threshold=cfg.llm_gate_threshold,
        llm_client=cfg.llm_client,
    )
    # backend 已 load，直接引用内存状态
    detector._backend = backend  # type: ignore[attr-defined]

    newly_conflicted: List[str] = []
    for neg_exp in new_neg_exps:
        exp_report = detector.process_neg_exp(neg_exp)
        if exp_report and exp_report.get("conflicts"):
            for conflict_item in exp_report["conflicts"]:
                target_id = conflict_item.get("target_exp_id")
                if target_id:
                    newly_conflicted.append(target_id)
                    # 填写 conflict_triggered_by
                    backend.update_fields(
                        target_id,
                        conflict_triggered_by=neg_exp.get("exp_id"),
                    )

    conflicts_count = len(newly_conflicted)
    result.conflicts_found = conflicts_count
    if conflicts_count and not cfg.dry_run:
        backend.commit()

    logger.info("[session %s] 冲突检测结果: %d 条被标记 conflicted", session_id, conflicts_count)
    return newly_conflicted
