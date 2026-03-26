"""
Layer 2 主流水线（Experience Extraction Pipeline）
===================================================
从 Layer 1 输出的 AnnotatedTurnSequence 中统一编排所有提取器，
生成并可选保存 ExperienceBundle。

流水线执行顺序：
  Step 1 : FACTUAL  提取    （规则驱动，无 LLM）
  Step 2 : PROCEDURAL 提取  （规则驱动，无 LLM）
  Step 3 : METACOGNITIVE 提取（LLM 驱动，可选）
  Step 4 : CONCEPTUAL 提取   （LLM 驱动，可选）
  Step 5 : 会话内去重 + 统计
  Step 6 : 保存到磁盘（可选）

公开 API：
  run_layer2(ann_seq, client=None) -> ExperienceBundle
  run_layer2_batch(input_dir, output_dir, client) -> Iterator[ExperienceBundle]
"""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Iterator, List, Optional

from ..utils.log_utils import get_logger
from ..models import AnnotatedTurnSequence
from .experience_models import ExperienceBundle, KnowledgeLayer
from .extractors.factual import extract_factual_experiences
from .extractors.factual_llm import extract_factual_experience_llm
from .extractors.procedural import extract_procedural_experiences
from .extractors.metacognitive import extract_metacognitive_experience
from .extractors.conceptual import extract_conceptual_experiences
from .serializer import save_experience_bundle

logger = get_logger(__name__)


def run_layer2(
    ann_seq: AnnotatedTurnSequence,
    client=None,
    save: bool = False,
    output_dir: Optional[Path] = None,
) -> ExperienceBundle:
    """对单个 AnnotatedTurnSequence 执行完整 Layer 2 经验提取流水线。

    Args:
        ann_seq    : Layer 1 完整标注输出
        client     : LLMClient 实例（None 时跳过 LLM 任务）
        save       : 是否将结果保存至磁盘
        output_dir : 保存目录（save=True 时必须提供）

    Returns:
        ExperienceBundle（包含本会话所有提取到的经验条目）
    """
    session_id = ann_seq.metadata.session_id
    target_raw = ann_seq.metadata.target_raw
    session_outcome_str = "unknown"
    if ann_seq.session_outcome:
        session_outcome_str = ann_seq.session_outcome.outcome_label

    bundle = ExperienceBundle(
        session_id=session_id,
        session_outcome=session_outcome_str,
        target_raw=target_raw,
    )

    counter = 1
    llm_calls = 0
    # 会话级服务名识别结果（Step 1.5 赋値，Step 2 后传播到 PROCEDURAL）
    _svc_name: str = ""
    _svc_cves: list = []
    _svc_version: str = ""

    # ── Step 1: FACTUAL （规则驱动）─────────────────────────────────────────────
    try:
        factual_exps = extract_factual_experiences(ann_seq, exp_counter_start=counter)
        for exp in factual_exps:
            bundle.add(exp)
        counter += len(factual_exps)
        logger.debug(
            "[layer2] session=%s FACTUAL extracted=%d",
            session_id[:8], len(factual_exps),
        )
    except Exception as e:
        msg = f"FACTUAL 提取失败: {e}"
        logger.error("[layer2] %s session=%s\n%s", msg, session_id[:8], traceback.format_exc())
        bundle.extraction_errors.append(msg)

    # ── Step 1.5: FACTUAL（LLM 来源，服务识别，可选）───────────────────────
    if client is not None:
        try:
            llm_fact_exp = extract_factual_experience_llm(ann_seq, client=client, exp_counter=counter)
            if llm_fact_exp:
                bundle.add(llm_fact_exp)
                counter += 1
                llm_calls += 1
                logger.debug(
                    "[layer2] session=%s FACTUAL extracted=1 source=llm service=%s",
                    session_id[:8], llm_fact_exp.content.get("target_service", "?"),
                )
                # F-1: 将 LLM 识别的服务名和 CVE 列表反向注入所有规则驱动 FACTUAL 经验
                llm_service = llm_fact_exp.content.get("target_service", "")
                llm_cves = llm_fact_exp.content.get("cve_context", {}).get("attempted", [])[:5]
                llm_version = llm_fact_exp.content.get("target_version", "")
                # P1: 跳过 "Unknown Service" 等无效服务名，避免污染规则经验
                if llm_service and "unknown" not in llm_service.lower():
                    # 保存到会话级变量，供 Step 2 后传播到 PROCEDURAL
                    _svc_name, _svc_cves, _svc_version = llm_service, llm_cves, llm_version
                    for rule_exp in bundle.by_layer(KnowledgeLayer.FACTUAL):
                        if rule_exp.content.get("extraction_method") != "llm_service_abstract":
                            if not rule_exp.content.get("target_service"):
                                rule_exp.content["target_service"] = llm_service
                            # P0-A: 始终回填 target_version（rule 记录从不自行提取版本号）
                            rule_exp.content["target_version"] = llm_version
                            # P0-A: 合并 CVE IDs（规则正则提取 + LLM 识别）去重保序
                            existing_cves = rule_exp.content.get("cve_ids") or []
                            merged_cves = list(dict.fromkeys(existing_cves + llm_cves))
                            rule_exp.content["cve_ids"] = merged_cves
                            # P0-A: 始终同步 applicable_constraints（含最新 version/CVE）
                            rule_exp.metadata.applicable_constraints = {
                                "target_service": llm_service,
                                "target_version": llm_version,
                                "cve_ids": merged_cves,
                            }
            else:
                logger.debug("[layer2] session=%s FACTUAL skipped source=llm", session_id[:8])
        except Exception as e:
            msg = f"FACTUAL(LLM来源) 提取失败: {e}"
            logger.warning("[layer2] %s session=%s", msg, session_id[:8])
            bundle.extraction_errors.append(msg)

    # ── Step 2: PROCEDURAL （规则驱动 + 延迟 NEG 决策规则 LLM）───────────────
    try:
        pos_exps, neg_exps = extract_procedural_experiences(
            ann_seq, exp_counter_start=counter, client=client,
            session_target_software=_svc_name,  # P0-B/P1: 传入 LLM 识别的会话级软件名
        )
        for exp in pos_exps:
            bundle.add(exp)
        counter += len(pos_exps)
        for exp in neg_exps:
            bundle.add(exp)
        counter += len(neg_exps)
        logger.debug(
            "[layer2] session=%s PROCEDURAL pos=%d neg=%d",
            session_id[:8], len(pos_exps), len(neg_exps),
        )
        # NEG decision_rule 批量 LLM 调用也在 extract_procedural_experiences 内完成
        if client is not None and neg_exps:
            llm_calls += 1
        # 将 LLM 识别的服务名传播到所有 PROCEDURAL 经验
        if _svc_name:
            _GENERIC_SVC = {"HTTP (alt)", "http", "generic", "", None}
            for proc_exp in bundle.by_layer(KnowledgeLayer.PROCEDURAL_POS):
                # P0-B: 同时回填 content 级 target_service（不只是 applicable_constraints）
                current_ts = proc_exp.content.get("target_service") or ""
                if current_ts in _GENERIC_SVC:
                    proc_exp.content["target_service"] = _svc_name
                # P2: 合并 CVE IDs（content + 会话级），并同步到 applicable_constraints
                existing_pos_cves = proc_exp.content.get("cve_ids") or []
                merged_pos_cves = list(dict.fromkeys(existing_pos_cves + _svc_cves))
                if merged_pos_cves:
                    proc_exp.content["cve_ids"] = merged_pos_cves

                constraints = dict(proc_exp.metadata.applicable_constraints or {})
                if not constraints.get("target_service"):
                    constraints["target_service"] = _svc_name
                if _svc_version and not constraints.get("target_version"):
                    constraints["target_version"] = _svc_version
                if merged_pos_cves:
                    constraints["cve_ids"] = merged_pos_cves
                proc_exp.metadata.applicable_constraints = constraints

            for proc_exp in bundle.by_layer(KnowledgeLayer.PROCEDURAL_NEG):
                # 🔴 Fix: 同时回填 content 级 target_service（之前只填了 applicable_constraints）
                if not proc_exp.content.get("target_service"):
                    proc_exp.content["target_service"] = _svc_name

                existing_neg_cves = proc_exp.content.get("cve_ids") or []
                merged_neg_cves = list(dict.fromkeys(existing_neg_cves + _svc_cves))
                if merged_neg_cves:
                    proc_exp.content["cve_ids"] = merged_neg_cves

                constraints = dict(proc_exp.metadata.applicable_constraints or {})
                if not constraints.get("target_service"):
                    constraints["target_service"] = _svc_name
                if _svc_version and not constraints.get("target_version"):
                    constraints["target_version"] = _svc_version
                if merged_neg_cves:
                    constraints["cve_ids"] = merged_neg_cves
                proc_exp.metadata.applicable_constraints = constraints
    except Exception as e:
        msg = f"PROCEDURAL 提取失败: {e}"
        logger.error("[layer2] %s session=%s\n%s", msg, session_id[:8], traceback.format_exc())
        bundle.extraction_errors.append(msg)

    # ── Step 3: METACOGNITIVE（LLM 驱动）────────────────────────────────────
    if client is not None:
        try:
            meta_exp = extract_metacognitive_experience(
                ann_seq, client=client, exp_counter=counter
            )
            if meta_exp:
                bundle.add(meta_exp)
                counter += 1
                llm_calls += 1
                logger.debug(
                    "[layer2] session=%s METACOGNITIVE extracted=1",
                    session_id[:8],
                )
            else:
                logger.debug(
                    "[layer2] session=%s METACOGNITIVE skipped (LLM 返回 None)",
                    session_id[:8],
                )
        except Exception as e:
            msg = f"METACOGNITIVE 提取失败: {e}"
            logger.warning("[layer2] %s session=%s", msg, session_id[:8])
            bundle.extraction_errors.append(msg)

    # ── Step 4: CONCEPTUAL（LLM 驱动）────────────────────────────────────────
    if client is not None:
        try:
            concept_exps = extract_conceptual_experiences(
                ann_seq, client=client, exp_counter=counter
            )
            for concept_exp in concept_exps:
                bundle.add(concept_exp)
                counter += 1
                llm_calls += 1
            logger.debug(
                "[layer2] session=%s CONCEPTUAL extracted=%d",
                session_id[:8], len(concept_exps),
            )
        except Exception as e:
            msg = f"CONCEPTUAL 提取失败: {e}"
            logger.warning("[layer2] %s session=%s", msg, session_id[:8])
            bundle.extraction_errors.append(msg)

    # ── Step 4.5: 统一同步 cve_ids 到 metadata.applicable_constraints ─────────
    # 目的：保证 Layer3 SEC 优先读取 metadata 时不会因字段缺失导致 cve_ids 为空。
    for exp in bundle.experiences:
        constraints = dict(exp.metadata.applicable_constraints or {})

        content_cves = []
        raw_cves = exp.content.get("cve_ids")
        if isinstance(raw_cves, list):
            content_cves.extend([str(c).upper() for c in raw_cves if str(c).strip()])

        if exp.knowledge_layer == KnowledgeLayer.FACTUAL:
            cve_ctx = exp.content.get("cve_context", {})
            attempted = cve_ctx.get("attempted", []) if isinstance(cve_ctx, dict) else []
            content_cves.extend([str(c).upper() for c in attempted if str(c).strip()])

        merged_cves = list(dict.fromkeys(
            [str(c).upper() for c in (constraints.get("cve_ids") or []) if str(c).strip()] +
            content_cves
        ))
        if merged_cves:
            constraints["cve_ids"] = merged_cves

        content_service = str(exp.content.get("target_service", "")).strip()
        if content_service and not constraints.get("target_service"):
            constraints["target_service"] = content_service

        content_version = str(exp.content.get("target_version", "")).strip()
        if content_version and not constraints.get("target_version"):
            constraints["target_version"] = content_version

        if constraints:
            exp.metadata.applicable_constraints = constraints

    bundle.llm_call_count = llm_calls

    # ── Step 5: 日志汇总 ──────────────────────────────────────────────────────
    logger.info(
        "[layer2] DONE %s",
        bundle.summary(),
    )

    # ── Step 6: 可选保存 ──────────────────────────────────────────────────────
    if save and output_dir is not None:
        try:
            save_experience_bundle(bundle, output_dir)
        except Exception as e:
            logger.error("[layer2] 保存失败 session=%s err=%s", session_id[:8], e)
            bundle.extraction_errors.append(f"保存失败: {e}")

    return bundle


def run_layer2_batch(
    input_dir: Path,
    output_dir: Optional[Path] = None,
    client=None,
    save: bool = True,
) -> Iterator[ExperienceBundle]:
    """批量执行 Layer 2 流水线，处理 input_dir 下所有 layer1_*.jsonl 文件。

    Args:
        input_dir  : Layer 1 输出目录（含 layer1_{session_id}.jsonl）
        output_dir : Layer 2 输出目录（None 时默认 input_dir/../layer2_output）
        client     : LLMClient 实例（None 时跳过 LLM 步骤）
        save       : 是否将结果保存至磁盘

    Yields:
        每个会话的 ExperienceBundle
    """
    from ..layer1.pipeline import load_annotated_turn_sequence

    if output_dir is None:
        output_dir = input_dir.parent / "layer2_output"

    input_files = sorted(input_dir.glob("layer1_*.jsonl"))
    if not input_files:
        logger.warning("[layer2_batch] 未找到 layer1_*.jsonl in %s", input_dir)
        return

    total = len(input_files)
    for i, layer1_path in enumerate(input_files, 1):
        session_id = _extract_session_id(layer1_path)
        logger.info(
            "[layer2_batch] [%d/%d] processing %s",
            i, total, layer1_path.name,
        )
        try:
            ann_seq = load_annotated_turn_sequence(layer1_path)
            bundle = run_layer2(
                ann_seq,
                client=client,
                save=save,
                output_dir=output_dir if save else None,
            )
            if save:
                logger.info(
                    "[layer2_batch] saved session=%s exps=%d",
                    session_id[:8], bundle.total_count,
                )
            yield bundle

        except Exception as e:
            logger.error(
                "[layer2_batch] FAILED %s: %s\n%s",
                layer1_path.name, e, traceback.format_exc(),
            )


def _extract_session_id(path: Path) -> str:
    """从 layer1_{session_id}.jsonl 中提取 session_id。"""
    stem = path.stem
    if stem.startswith("layer1_"):
        return stem[len("layer1_"):]
    return stem
