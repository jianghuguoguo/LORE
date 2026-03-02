"""
src/layer4/maintenance.py
==========================
每日定期维护任务（APScheduler 驱动，兜底融合 + BCC 更新 + 回流 + Layer4 缺口处理）。

任务列表（§2.5）：
  1. 扫描 raw 经验，找到满足门槛但未融合的 cluster → 执行 Layer3
  2. 对已有 consolidated 重新计算 BCC（新增 session 提升置信度）
  3. 将新产生的 reflux_ready 写入 RAGFlow
  4. Layer4 dispatcher：处理 P1 缺口队列（爬虫触发）

用法1（直接调用）：
    from src.layer4.maintenance import daily_maintenance, MaintenanceConfig
    from src.ragflow.client import RAGFlowExpClient
    cfg = MaintenanceConfig(ragflow_client=RAGFlowExpClient())
    result = daily_maintenance(cfg=cfg)

用法2（APScheduler 后台调度）：
    from src.layer4.maintenance import start_scheduler, stop_scheduler
    start_scheduler()          # 每日凌晨 2:00 自动执行
    ...
    stop_scheduler()

用法3（命令行）：
    python -m src.layer4.maintenance [--dry-run] [--now]
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..ragflow.client import RAGFlowExpClient

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logger = logging.getLogger(__name__)

_DATA_L3 = ROOT / "data" / "layer3_output"
_KLM_FILE     = _DATA_L3 / "phase5_klm_registry.jsonl"
_CONSOLIDATED = _DATA_L3 / "phase34_consolidated.jsonl"

# ─────────────────────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MaintenanceConfig:
    """daily_maintenance 执行参数。"""

    ragflow_client:  Optional["RAGFlowExpClient"] = None
    llm_client:      Optional[Any] = None

    # 融合门槛
    min_fusion_count: int = 3

    # BCC 升级阈值
    validated_threshold:   float = 0.6
    consolidated_threshold: float = 0.8

    # 是否跳过写磁盘/写 RAGFlow
    dry_run: bool = False

    # 文件路径（测试可覆盖）
    klm_path:         Optional[Path] = None
    consolidated_path: Optional[Path] = None


@dataclass
class MaintenanceResult:
    """daily_maintenance 执行摘要。"""
    ran_at:               str  = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    pending_fused:        int  = 0
    consolidated_added:   int  = 0
    bcc_updated:          int  = 0
    maturity_upgraded:    int  = 0
    reflux_uploaded:      int  = 0
    reflux_failed:        int  = 0
    layer4_queue_drained: int  = 0
    errors:               List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────────────────

def daily_maintenance(cfg: Optional[MaintenanceConfig] = None) -> MaintenanceResult:
    """
    每日凌晨维护任务主入口。

    对应文档 §2.5 daily_maintenance() 伪代码的完整实现。
    """
    cfg = cfg or MaintenanceConfig()
    result = MaintenanceResult()

    from src.layer4.conflict import LocalKLMBackend
    from src.layer4.reflux import flush_reflux_ready_to_ragflow

    klm_path  = cfg.klm_path  or _KLM_FILE
    cons_path = cfg.consolidated_path or _CONSOLIDATED

    backend = LocalKLMBackend(klm_path=klm_path, consolidated_path=cons_path)
    backend.load()

    # ── Task 1: 兜底融合 ──────────────────────────────────────────────────────
    logger.info("[daily] Task 1 — 扫描 raw 经验，执行兜底融合")
    _task1_pending_fusion(result, backend, cfg)

    # ── Task 2: BCC 重算 ──────────────────────────────────────────────────────
    logger.info("[daily] Task 2 — 对 consolidated 经验重新计算 BCC")
    _task2_bcc_recalculate(result, backend, cfg)

    # ── Task 3: 回流到 RAGFlow ───────────────────────────────────────────────
    logger.info("[daily] Task 3 — 将 reflux_ready 写入 RAGFlow")
    if cfg.ragflow_client is not None:
        try:
            reflux_result = flush_reflux_ready_to_ragflow(
                klm_backend=backend,
                ragflow_client=cfg.ragflow_client,
                dry_run=cfg.dry_run,
                commit=not cfg.dry_run,
            )
            result.reflux_uploaded = reflux_result.uploaded
            result.reflux_failed   = reflux_result.failed
        except Exception as exc:
            err = f"Task3 reflux error: {exc}"
            logger.error("[daily] %s", err, exc_info=True)
            result.errors.append(err)
    else:
        logger.info("[daily] Task 3 — ragflow_client=None，跳过 RAGFlow 写入")

    # ── Task 4: Layer4 缺口队列 ───────────────────────────────────────────────
    logger.info("[daily] Task 4 — Layer4 缺口队列处理")
    _task4_layer4_dispatcher(result, cfg)

    logger.info(
        "[daily] 完成 | 融合=%d consolidated=%d bcc_updated=%d "
        "maturity升级=%d 上传=%d layer4=%d errors=%d",
        result.pending_fused, result.consolidated_added,
        result.bcc_updated, result.maturity_upgraded,
        result.reflux_uploaded, result.layer4_queue_drained, len(result.errors),
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: 兜底融合
# ─────────────────────────────────────────────────────────────────────────────

def _task1_pending_fusion(
    result: MaintenanceResult,
    backend: Any,
    cfg: MaintenanceConfig,
) -> None:
    """扫描所有 raw 经验，对满足融合条件但未处理的 cluster 执行 Layer3。"""
    pending_clusters = backend.find_clusters_above_threshold(
        maturity="raw",
        min_count=cfg.min_fusion_count,
    )
    result.pending_fused = len(pending_clusters)

    if not pending_clusters:
        logger.info("[daily/Task1] 无待融合 cluster")
        return

    logger.info("[daily/Task1] 发现 %d 个待融合 cluster", len(pending_clusters))

    try:
        from src.layer3 import (
            cluster_experiences,
            weight_equivalence_sets,
            run_rme,
            run_bcc,
        )
    except ImportError as e:
        err = f"Layer3 import error: {e}"
        logger.error("[daily/Task1] %s", err)
        result.errors.append(err)
        return

    # 收集可融合的 raw 经验
    all_raw = [
        e for e in backend._entries
        if e.get("lifecycle_status") == "active"
        and e.get("maturity") in ("raw", "validated")
    ]
    if not all_raw:
        return

    try:
        eq_sets = cluster_experiences(all_raw)
        w_eq_sets = weight_equivalence_sets(eq_sets)
        merge_results = run_rme(w_eq_sets)
        # run_bcc 需要 wes_map: {cluster_id → WeightedEquivalenceSet}
        wes_map = {wes.cluster.cluster_id: wes for wes in w_eq_sets}
        bcc_results, consolidated_exps = run_bcc(merge_results, wes_map)

        for ce in consolidated_exps:
            # ConsolidatedExp 是 dataclass，转 dict
            import dataclasses as _dc
            ce_dict = _dc.asdict(ce) if _dc.is_dataclass(ce) else dict(ce)

            if backend.add_consolidated(ce_dict):
                result.consolidated_added += 1
                prov = ce_dict.get("provenance") or {}
                src_ids = (
                    ce_dict.get("source_exp_ids")
                    or (prov.get("source_exp_ids") if isinstance(prov, dict) else getattr(prov, "source_exp_ids", []))
                    or []
                )
                if src_ids and ce_dict.get("exp_id"):
                    backend.suspend_source_exps(
                        source_ids=src_ids,
                        merged_into=ce_dict["exp_id"],
                    )

        if not cfg.dry_run:
            backend.commit()

    except Exception as exc:
        err = f"Layer3 fusion error: {exc}"
        logger.error("[daily/Task1] %s", err, exc_info=True)
        result.errors.append(err)


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: BCC 重算
# ─────────────────────────────────────────────────────────────────────────────

def _task2_bcc_recalculate(
    result: MaintenanceResult,
    backend: Any,
    cfg: MaintenanceConfig,
) -> None:
    """
    对已有 consolidated 经验重新计算 BCC 置信度。
    若 p_fused 提升且跨越 maturity 阈值，更新 maturity + should_reflux。
    """
    existing_consolidated = backend.query(maturity="consolidated")
    existing_validated    = backend.query(maturity="validated")
    targets = existing_consolidated + existing_validated

    for exp in targets:
        exp_id  = exp.get("exp_id", "")
        old_p   = exp.get("p_fused") or exp.get("confidence") or 0.0
        old_mat = exp.get("maturity", "raw")

        try:
            # 贝叶斯后验更新：Beta(alpha + successes, beta + failures)
            # successes ≈ old_p * n_sessions；对应「见过 n_sessions 次，每次成功率 old_p」
            n_sessions = exp.get("n_independent_sessions") or 1
            alpha_prior, beta_prior = 1.0, 1.0
            s = old_p * n_sessions
            f = (1 - old_p) * n_sessions
            new_p = (alpha_prior + s) / (alpha_prior + beta_prior + s + f)
        except Exception:
            new_p = old_p  # 若计算异常，保留旧值

        if new_p > old_p + 1e-4:
            backend.update_p_fused(exp_id, new_p)
            result.bcc_updated += 1

            # 判断 maturity 是否升级
            new_mat = _determine_maturity(new_p, cfg)
            if new_mat != old_mat:
                backend.update_maturity(exp_id, new_mat)
                result.maturity_upgraded += 1
                logger.info(
                    "[daily/Task2] %s maturity %s → %s  p_fused %.4f → %.4f",
                    exp_id, old_mat, new_mat, old_p, new_p,
                )

    if not cfg.dry_run and (result.bcc_updated > 0):
        backend.commit()


def _determine_maturity(p_fused: float, cfg: MaintenanceConfig) -> str:
    """根据 p_fused 确定 maturity 级别。"""
    if p_fused >= cfg.consolidated_threshold:
        return "consolidated"
    elif p_fused >= cfg.validated_threshold:
        return "validated"
    return "raw"


# ─────────────────────────────────────────────────────────────────────────────
# Task 4: Layer4 缺口队列
# ─────────────────────────────────────────────────────────────────────────────

def _task4_layer4_dispatcher(
    result: MaintenanceResult,
    cfg: MaintenanceConfig,
) -> None:
    """调用 Layer4 dispatcher 处理 P1 缺口队列。"""
    try:
        dispatcher_path = ROOT / "src" / "layer4" / "dispatcher.py"
        if not dispatcher_path.exists():
            logger.info("[daily/Task4] dispatcher.py 不存在，跳过")
            return

        from src.layer4.dispatcher import run_daily_job
        n = run_daily_job(dry_run=cfg.dry_run)
        result.layer4_queue_drained = n or 0
        logger.info("[daily/Task4] Layer4 处理完成：%d 条", result.layer4_queue_drained)

    except (ImportError, AttributeError) as e:
        logger.info("[daily/Task4] dispatcher.run_daily_job 不可用: %s", e)
    except Exception as exc:
        err = f"Layer4 dispatcher error: {exc}"
        logger.error("[daily/Task4] %s", err, exc_info=True)
        result.errors.append(err)


# ─────────────────────────────────────────────────────────────────────────────
# APScheduler 调度器
# ─────────────────────────────────────────────────────────────────────────────

_scheduler = None


def start_scheduler(
    hour: int = 2,
    minute: int = 0,
    cfg: Optional[MaintenanceConfig] = None,
) -> None:
    """
    启动 APScheduler，每日指定时间执行 daily_maintenance。

    Parameters
    ----------
    hour   : 触发小时（本地时间，默认凌晨 2 点）
    minute : 触发分钟（默认 0）
    cfg    : 维护配置（含 ragflow_client 等）
    """
    global _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        logger.error(
            "APScheduler 未安装，无法启动定时任务。请执行：pip install apscheduler"
        )
        return

    if _scheduler is not None and _scheduler.running:
        logger.warning("Scheduler 已在运行，跳过重复启动")
        return

    _scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    _scheduler.add_job(
        daily_maintenance,
        trigger=CronTrigger(hour=hour, minute=minute),
        kwargs={"cfg": cfg},
        id="daily_maintenance",
        name="KLM 每日维护 + RAGFlow 回流",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info(
        "Scheduler 已启动，daily_maintenance 将每日 %02d:%02d 执行", hour, minute
    )


def stop_scheduler() -> None:
    """停止后台调度器。"""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler 已停止")


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def _cli_main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="每日 KLM 维护 + RAGFlow 回流任务")
    parser.add_argument("--dry-run", action="store_true", help="只分析，不写磁盘和 RAGFlow")
    parser.add_argument("--now", action="store_true", help="立即执行（不等调度）")
    parser.add_argument("--no-ragflow", action="store_true", help="跳过 RAGFlow 写入（仅本地）")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    ragflow_client = None
    if not args.no_ragflow:
        try:
            from src.ragflow.client import RAGFlowExpClient
            ragflow_client = RAGFlowExpClient()
        except Exception as e:
            logger.warning("RAGFlowExpClient 初始化失败: %s  将跳过 RAGFlow 写入", e)

    cfg = MaintenanceConfig(
        ragflow_client=ragflow_client,
        dry_run=args.dry_run,
    )

    result = daily_maintenance(cfg=cfg)

    print()
    print("─" * 60)
    print("  每日维护结果" + ("  (DRY-RUN)" if args.dry_run else ""))
    print("─" * 60)
    print(f"  运行时间         : {result.ran_at}")
    print(f"  待融合 cluster   : {result.pending_fused}")
    print(f"  新 consolidated  : {result.consolidated_added}")
    print(f"  BCC 更新         : {result.bcc_updated}")
    print(f"  maturity 升级    : {result.maturity_upgraded}")
    print(f"  RAGFlow 上传     : {result.reflux_uploaded}")
    print(f"  RAGFlow 上传失败 : {result.reflux_failed}")
    print(f"  Layer4 队列处理  : {result.layer4_queue_drained}")
    if result.errors:
        print(f"  错误             : {len(result.errors)} 条")
        for err in result.errors:
            print(f"    - {err}")
    print("─" * 60)
    return 0 if not result.errors else 1


if __name__ == "__main__":
    sys.exit(_cli_main())
