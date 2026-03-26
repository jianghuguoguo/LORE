"""
uploader.py
===========
默认将 Layer 3 Phase34 的融合经验上传至 RAGflow 经验库。

兼容模式：
- fused（默认）：读取 data/layer3_output/phase34_consolidated.jsonl
- raw：读取 data/layer2_output/<session>/experiences.jsonl

设计：
- 按照 RAG 入库字段规范对各层经验字段做精简（削减 ~67% 噪声字段）
- 每条经验独立上传，按知识层路由到对应 dataset
- 使用 API Key 鉴权（Bearer），token 会在进程内缓存
- RAG_EVALUATION 层不上传（无 Agent 检索价值）

目标库：
  经验库   EXPERIENCE_DATASET_ID = b5f3a66f065f11f1bca40242ac120006
  完整语料库 FULL_DATASET_ID      = b877bec1065c11f1a8960242ac120006
    说明：生产路由中 CONCEPTUAL 与 METACOGNITIVE 统一进入 meta_conceptual
             （dataset_metacognitive）；FULL_DATASET_ID 仅作为全量归档预留，不参与默认分层上传。

账号配置 —— 统一在 configs/config.yaml 的 ragflow 节中修改：
    base_url / api_key_env / api_key_literal / datasets
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..utils.config_loader import get_config

# ─────────────────────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────────────────────

RAGFLOW_CONFIG: Dict[str, str] = get_config().ragflow_config

logger = logging.getLogger("ragflow_uploader")

_API_PREFIX = "/api/v1"

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_FUSED_FILE = ROOT / "data" / "layer3_output" / "phase34_consolidated.jsonl"

_LAYER_TO_DATASET_KEY: Dict[str, str] = {
    "FACTUAL": "dataset_factual",
    "PROCEDURAL_POS": "dataset_procedural_pos",
    "PROCEDURAL_NEG": "dataset_procedural_neg",
    # meta_conceptual 组合库：元认知 + 概念知识统一入此库
    "METACOGNITIVE": "dataset_metacognitive",
    "CONCEPTUAL": "dataset_metacognitive",
}

# ─────────────────────────────────────────────────────────────────────────────
# 鉴权
# ─────────────────────────────────────────────────────────────────────────────

_cached_token: Optional[str] = None


def _normalize_base_url(cfg: Dict[str, str]) -> str:
    """标准化 RAGFlow 基础地址，兼容 host 与 host/api/v1 两种写法。"""
    raw_base_url = os.environ.get("RAGFLOW_BASE_URL", "").strip() or cfg.get("base_url", "")
    base = (raw_base_url or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("[ragflow] 链接配置错误：base_url 为空。")
    if base.endswith(_API_PREFIX):
        base = base[: -len(_API_PREFIX)].rstrip("/")
    return base


def _api_url(cfg: Dict[str, str], path: str) -> str:
    """统一拼接 API URL，避免重复 /api/v1 或双斜杠。"""
    base = _normalize_base_url(cfg)
    normalized_path = "/" + (path or "").lstrip("/")
    if normalized_path == _API_PREFIX or normalized_path.startswith(f"{_API_PREFIX}/"):
        return f"{base}{normalized_path}"
    return f"{base}{_API_PREFIX}{normalized_path}"


def _login(cfg: Dict[str, str] = RAGFLOW_CONFIG) -> str:
    """
    获取 API Key（进程内缓存）。

    优先级：
    1. 缓存 token
    2. 环境变量 RAGFLOW_API_KEY
    3. cfg["api_key"]
    """
    global _cached_token
    if _cached_token:
        return _cached_token

    # 优先从环境变量 RAGFLOW_API_KEY 取，其次从 cfg["api_key"]
    token = os.environ.get("RAGFLOW_API_KEY", "").strip() or cfg.get("api_key", "").strip()
    if not token:
        raise RuntimeError(
            "[ragflow] 鉴权失败：未配置 API Key。"
            "请在环境变量 RAGFLOW_API_KEY 或 configs/config.yaml 的 ragflow.api_key_literal 中配置。"
        )

    _cached_token = token
    logger.info("[ragflow] 使用 API Key 进行认证")
    return token


def _headers(token: str) -> Dict[str, str]:
    """
    生成请求头。
    使用 API Key 模式，必须包含 Bearer 前缀。
    """
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────────────────────────────────────
# 字段精简变换
# ─────────────────────────────────────────────────────────────────────────────

def _transform_factual_rule(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """FACTUAL (rule) → 入库格式（保留35%关键字段）"""
    content_raw = raw.get("content", {})
    meta = raw.get("metadata", {})
    constraints = meta.get("applicable_constraints", {})

    target_service = content_raw.get("target_service") or constraints.get("target_service")
    target_version = content_raw.get("target_version") or constraints.get("target_version")
    cve_ids = (content_raw.get("cve_ids")
               or constraints.get("cve_ids")
               or meta.get("tags", []))
    # 只保留 CVE 标签
    cve_ids = [t for t in cve_ids if str(t).startswith("CVE-")] if isinstance(cve_ids, list) else []

    discovered_facts = content_raw.get("discovered_facts", [])

    content_out: Dict[str, Any] = {}
    if target_service:
        content_out["target_service"] = target_service
    if target_version and target_version != "None":
        content_out["target_version"] = target_version
    if cve_ids:
        content_out["cve_ids"] = cve_ids
    if discovered_facts:
        content_out["discovered_facts"] = discovered_facts

    if not content_out:
        return None  # 空内容不入库

    filter_out: Dict[str, Any] = {
        "session_outcome": meta.get("session_outcome", "unknown"),
        "confidence": raw.get("confidence", 0.0),
        "maturity": raw.get("maturity", "raw"),
        "factual_source": "rule",
    }
    if target_service:
        filter_out["target_service"] = target_service
    if target_version and target_version != "None":
        filter_out["target_version"] = target_version
    if cve_ids:
        filter_out["cve_ids"] = cve_ids

    return {
        "exp_id": raw["exp_id"],
        "layer": "FACTUAL",
        "content": content_out,
        "filter": filter_out,
    }


def _sanitize_strings(obj: Any) -> Any:
    """
    递归清洗字符串值中可能触发 Nginx 路由拦截的 URL 路径模式。
    将字符串中出现的 '/' 替换为 '\\/' 防止 Nginx 误解析。
    只处理字符串值（不处理 dict 键名）。
    """
    if isinstance(obj, str):
        return obj.replace("/", "\\/")
    elif isinstance(obj, list):
        return [_sanitize_strings(v) for v in obj]
    elif isinstance(obj, dict):
        return {k: _sanitize_strings(v) for k, v in obj.items()}
    return obj


def _val_to_text(v: Any, indent: int = 0) -> str:
    """将任意值递归转换为缩进文本，同时转义 URL 路径防 Nginx WAF。"""
    prefix = "  " * indent
    if isinstance(v, dict):
        parts = []
        for dk, dv in v.items():
            rendered = _val_to_text(dv, indent + 1)
            if "\n" in rendered:
                parts.append(f"{prefix}  {dk}:{rendered}")
            else:
                parts.append(f"{prefix}  {dk}: {rendered.strip()}")
        return "\n" + "\n".join(parts)
    elif isinstance(v, list):
        if not v:
            return "[]"
        parts = []
        for item in v:
            rendered = _val_to_text(item, indent + 1)
            if "\n" in rendered:
                parts.append(f"{prefix}  -{rendered}")
            else:
                parts.append(f"{prefix}  - {rendered.strip()}")
        return "\n" + "\n".join(parts)
    else:
        # 转义路径字符防止 Nginx WAF 拦截
        return str(v).replace("/", "\\/")


def _experiences_to_text(docs: List[Dict[str, Any]]) -> str:
    """
    将经验条目列表序列化为 RAGflow naive 解析器可处理的纯文本格式。
    每条经验独立成一个文本块，便于分段索引和语义检索。
    """
    lines: List[str] = []
    for doc in docs:
        exp_id = doc.get("exp_id", "unknown")
        layer  = doc.get("layer", "UNKNOWN")
        lines.append(f"=== EXPERIENCE {exp_id} [{layer}] ===")
        lines.append("")

        content = doc.get("content", {})
        for k, v in content.items():
            rendered = _val_to_text(v)
            if "\n" in rendered:
                lines.append(f"{k}:{rendered}")
            else:
                lines.append(f"{k}: {rendered.strip()}")

        flt = doc.get("filter", {})
        if flt:
            lines.append("")
            meta_parts = [f"{k}={v}" for k, v in flt.items()]
            lines.append("[meta] " + " | ".join(meta_parts))

        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def _transform_factual_llm(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """FACTUAL (llm) → 入库格式（CVE地图，最高价值）"""
    content_raw = raw.get("content", {})
    meta = raw.get("metadata", {})
    cve_ctx = content_raw.get("cve_context", {})
    constraints = content_raw.get("applicable_constraints", {})

    target_service   = content_raw.get("target_service")
    target_version   = content_raw.get("target_version")
    exploitation_st  = content_raw.get("exploitation_status", "unknown")
    cve_attempted    = cve_ctx.get("attempted", [])
    cve_results      = cve_ctx.get("exploitation_results", {})
    cve_unexplored   = cve_ctx.get("unexplored", [])
    known_ineffective = constraints.get("known_ineffective_vectors", [])

    content_out: Dict[str, Any] = {}
    if target_service:
        content_out["target_service"] = target_service
    if target_version and target_version != "None":
        content_out["target_version"] = target_version
    content_out["exploitation_status"] = exploitation_st
    if cve_attempted:
        content_out["cve_attempted"] = cve_attempted
    if cve_results:
        content_out["cve_results"] = cve_results
    if cve_unexplored:
        content_out["cve_unexplored"] = cve_unexplored
    if known_ineffective:
        content_out["known_ineffective_vectors"] = known_ineffective

    filter_out: Dict[str, Any] = {
        "exploitation_status": exploitation_st,
        "confidence": raw.get("confidence", 0.0),
        "maturity": raw.get("maturity", "raw"),
        "factual_source": "llm",
    }
    if target_service:
        filter_out["target_service"] = target_service

    return {
        "exp_id": raw["exp_id"],
        "layer": "FACTUAL",
        "content": content_out,
        "filter": filter_out,
    }


def _infer_target_service(raw: Dict[str, Any]) -> Optional[str]:
    """从 metadata.applicable_constraints 或 tags 推断 target_service。"""
    meta = raw.get("metadata", {})
    constraints = meta.get("applicable_constraints", {})
    ts = constraints.get("target_service")
    if ts:
        return ts
    # 从 tags 中找 "oracle", "weblogic" 等关键词拼出服务名（粗粒度兜底）
    tags = meta.get("tags", [])
    svc_hints = [t for t in tags if t.lower() not in {
        "llm_factual", "failure", "success", "metacognitive", "conceptual",
        "rag_evaluation", "rag_utility", "vulnerability_pattern",
    } and not t.startswith("bar_") and not t.startswith("CVE-") and "_" not in t[:3]]
    if svc_hints:
        return svc_hints[0]
    return None


def _transform_procedural_neg(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PROCEDURAL_NEG → 入库格式（保留决策规则，删除66%冗余）"""
    content_raw = raw.get("content", {})
    meta = raw.get("metadata", {})
    constraints = meta.get("applicable_constraints", {})

    target_service     = (constraints.get("target_service")
                          or content_raw.get("target_service")
                          or _infer_target_service(raw))
    failure_dim        = content_raw.get("failure_dimension", "UNKNOWN")
    failure_sub        = content_raw.get("failure_sub_dimension", "")
    decision_rule_raw  = content_raw.get("decision_rule")
    evidence           = content_raw.get("evidence", "")

    # 精简 decision_rule：只保留 IF/THEN/NOT/conclusion，去掉 next_actions（含代码/URL）
    decision_rule: Any = None
    if decision_rule_raw:
        if isinstance(decision_rule_raw, dict):
            decision_rule = {
                k: v for k, v in decision_rule_raw.items()
                if k in ("IF", "THEN", "NOT", "conclusion", "condition", "action")
            } or decision_rule_raw  # 若剩余为空则保留原始（兼容不同格式）
        else:
            decision_rule = decision_rule_raw

    content_out: Dict[str, Any] = {
        "failure_dimension":     failure_dim,
        "failure_sub_dimension": failure_sub,
    }
    if target_service:
        content_out["target_service"] = target_service
    if decision_rule:
        content_out["decision_rule"] = decision_rule
    if evidence:
        content_out["evidence"] = evidence

    filter_out: Dict[str, Any] = {
        "failure_dimension":     failure_dim,
        "failure_sub_dimension": failure_sub,
        "confidence": raw.get("confidence", 0.0),
        "maturity":   raw.get("maturity", "raw"),
    }
    if target_service:
        filter_out["target_service"] = target_service

    return {
        "exp_id": raw["exp_id"],
        "layer": "PROCEDURAL_NEG",
        "content": content_out,
        "filter": filter_out,
    }


def _transform_procedural_pos(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PROCEDURAL_POS → 入库格式（按类别直传，不再跳过）。"""
    content_raw = raw.get("content", {})
    meta = raw.get("metadata", {})
    constraints = meta.get("applicable_constraints", {})

    target_service = (
        constraints.get("target_service")
        or content_raw.get("target_service")
        or _infer_target_service(raw)
    )
    attack_phase = content_raw.get("attack_phase", "")
    command_template = content_raw.get("command_template") or content_raw.get("original_command")
    tool_name = content_raw.get("tool_name", "")
    preconditions = content_raw.get("preconditions", [])
    success_indicators = content_raw.get("success_indicators", [])
    cve_ids = content_raw.get("cve_ids") or constraints.get("cve_ids", [])

    content_out: Dict[str, Any] = {}
    if command_template:
        content_out["command_template"] = command_template
    if tool_name:
        content_out["tool_name"] = tool_name
    if attack_phase:
        content_out["attack_phase"] = attack_phase
    if preconditions:
        content_out["preconditions"] = preconditions
    if success_indicators:
        content_out["success_indicators"] = success_indicators
    if cve_ids:
        content_out["cve_ids"] = cve_ids
    if target_service:
        content_out["target_service"] = target_service

    if not content_out:
        return None

    filter_out: Dict[str, Any] = {
        "session_outcome": meta.get("session_outcome", "unknown"),
        "confidence": raw.get("confidence", 0.0),
        "maturity": raw.get("maturity", "raw"),
    }
    if attack_phase:
        filter_out["attack_phase"] = attack_phase
    if target_service:
        filter_out["target_service"] = target_service
    if cve_ids:
        filter_out["cve_ids"] = cve_ids[:5]

    return {
        "exp_id": raw["exp_id"],
        "layer": "PROCEDURAL_POS",
        "content": content_out,
        "filter": filter_out,
    }


def _transform_metacognitive(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """METACOGNITIVE → 入库格式（保留核心规则，删除统计噪声）"""
    content_raw = raw.get("content", {})
    meta = raw.get("metadata", {})

    session_goal          = content_raw.get("session_goal", "")
    key_lessons           = content_raw.get("key_lessons", [])
    optimal_path          = content_raw.get("optimal_decision_path", [])
    missed_opportunities  = content_raw.get("missed_opportunities", [])
    failure_pattern       = content_raw.get("failure_pattern")
    session_outcome       = meta.get("session_outcome", content_raw.get("session_outcome", "unknown"))

    content_out: Dict[str, Any] = {}
    if session_goal:
        content_out["session_goal"] = session_goal
    if key_lessons:
        content_out["key_lessons"] = key_lessons
    if optimal_path:
        content_out["optimal_decision_path"] = optimal_path
    if missed_opportunities:
        content_out["missed_opportunities"] = missed_opportunities
    if failure_pattern:
        content_out["failure_pattern"] = failure_pattern

    # 成功 session 额外字段
    for extra_key in ("minimal_success_path", "replicability_conditions", "critical_decision_point"):
        val = content_raw.get(extra_key)
        if val:
            content_out[extra_key] = val

    if not content_out:
        return None

    target_service = _infer_target_service(raw)
    filter_out: Dict[str, Any] = {
        "session_outcome": session_outcome,
        "confidence":      raw.get("confidence", 0.0),
        "maturity":        raw.get("maturity", "raw"),
    }
    if target_service:
        filter_out["target_service"] = target_service

    return {
        "exp_id": raw["exp_id"],
        "layer": "METACOGNITIVE",
        "content": content_out,
        "filter": filter_out,
    }


def _transform_conceptual(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """CONCEPTUAL → 入库格式（直接可检索的攻击规律）"""
    content_raw = raw.get("content", {})
    applicable = content_raw.get("applicable_conditions", {})

    pattern_type      = content_raw.get("pattern_type", "")
    positive_conds    = applicable.get("positive", [])
    negative_conds    = applicable.get("negative", [])
    retrieval_triggers = applicable.get("retrieval_triggers", [])
    core_insight      = content_raw.get("core_insight", "")
    supporting_ev     = content_raw.get("supporting_evidence", [])

    content_out: Dict[str, Any] = {}
    if pattern_type:
        content_out["pattern_type"] = pattern_type
    if positive_conds:
        content_out["positive_conditions"] = positive_conds
    if negative_conds:
        content_out["negative_conditions"] = negative_conds
    if retrieval_triggers:
        content_out["retrieval_triggers"] = retrieval_triggers
    if core_insight:
        content_out["core_insight"] = core_insight
    if supporting_ev:
        content_out["supporting_evidence"] = supporting_ev

    if not content_out:
        return None

    filter_out: Dict[str, Any] = {
        "confidence": raw.get("confidence", 0.0),
        "maturity":   raw.get("maturity", "raw"),
    }
    if pattern_type:
        filter_out["pattern_type"] = pattern_type
    if retrieval_triggers:
        filter_out["retrieval_triggers"] = retrieval_triggers

    return {
        "exp_id": raw["exp_id"],
        "layer": "CONCEPTUAL",
        "content": content_out,
        "filter": filter_out,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 主变换路由
# ─────────────────────────────────────────────────────────────────────────────

def transform_experience(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """将原始经验字典变换为 RAG 入库格式。返回 None 表示跳过不入库。"""
    raw_layer = str(raw.get("knowledge_layer", ""))
    layer = raw_layer
    if raw_layer.startswith("FACTUAL_"):
        layer = "FACTUAL"

    extraction_source = str(raw.get("metadata", {}).get("extraction_source", "")).lower()
    if raw_layer.endswith("_RULE"):
        extraction_source = "rule"
    elif raw_layer.endswith("_LLM"):
        extraction_source = "llm"

    if layer == "FACTUAL":
        if extraction_source == "rule":
            return _transform_factual_rule(raw)
        elif extraction_source == "llm":
            return _transform_factual_llm(raw)
        else:
            # fallback：根据字段内容判断
            if "cve_context" in raw.get("content", {}):
                return _transform_factual_llm(raw)
            return _transform_factual_rule(raw)

    elif layer == "PROCEDURAL_NEG":
        return _transform_procedural_neg(raw)

    elif layer == "METACOGNITIVE":
        return _transform_metacognitive(raw)

    elif layer == "CONCEPTUAL":
        return _transform_conceptual(raw)

    elif layer == "PROCEDURAL_POS":
        return _transform_procedural_pos(raw)

    return None


# ─────────────────────────────────────────────────────────────────────────────
# 上传
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_dataset_id_for_layer(
    layer: str,
    cfg: Dict[str, str],
    dataset_id_override: Optional[str] = None,
) -> Optional[str]:
    """根据知识层选择目标 dataset，未配置时返回 None（不再兜底）。"""
    if dataset_id_override:
        return dataset_id_override

    layer_upper = (layer or "").upper()
    dataset_key = _LAYER_TO_DATASET_KEY.get(layer_upper)
    if not dataset_key:
        return None
    dataset_id = (cfg.get(dataset_key) or "").strip()
    return dataset_id or None

def upload_experiences_to_ragflow(
    experiences: List[Dict[str, Any]],
    session_id: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
    retry_502_max: int = 3,
    retry_base_sec: float = 1.0,
) -> Dict[str, Any]:
    """
    将经验列表上传到 RAGflow 经验库。

    Parameters
    ----------
    experiences : list[dict]
        原始经验列表（来自 experiences.jsonl 的每行 dict）
    session_id  : str
        当前会话 ID（用于文件命名，便于溯源）
    dataset_id  : str, optional
        目标 dataset ID（传入时覆盖所有层的路由）
    cfg         : dict
        配置字典，包含 base_url / api_key / dataset 路由等
    dry_run     : bool
        True 时仅做变换和打印，不实际上传
    retry_502_max : int
        HTTP 502 的最大重试次数（指数退避）
    retry_base_sec : float
        502 重试基准等待秒数，等待序列为 retry_base_sec * 2^attempt

    Returns
    -------
    dict 包含 uploaded / skipped / failed / doc_ids / failed_items 等统计字段
    """
    # 1. 变换字段
    transformed: List[Dict[str, Any]] = []
    skipped_count = 0
    for raw in experiences:
        doc = transform_experience(raw)
        if doc is None:
            skipped_count += 1
        else:
            transformed.append(doc)

    logger.info(
        f"[ragflow] session={session_id[:8]} | 原始={len(experiences)} "
        f"变换后={len(transformed)} 跳过={skipped_count}"
    )

    if not transformed:
        return {
            "uploaded": 0,
            "skipped": skipped_count,
            "failed": 0,
            "doc_ids": [],
            "failed_items": [],
        }

    if dry_run:
        logger.info(f"[ragflow][DRY_RUN] 跳过实际上传，变换后 {len(transformed)} 条")
        return {
            "uploaded": 0,
            "skipped": skipped_count,
            "failed": 0,
            "doc_ids": [],
            "failed_items": [],
            "dry_run_docs": transformed,
        }

    # 2. 获取 Bearer token
    try:
        token = _login(cfg)
    except RuntimeError as e:
        logger.error(str(e))
        return {
            "uploaded": 0,
            "skipped": skipped_count,
            "failed": len(transformed),
            "doc_ids": [],
            "failed_items": [],
            "error": str(e),
        }

    # 3. 逐条上传：每条经验独立成一个 .txt 文件
    #    文件名格式：exp_{session_short}_{exp_id}_{layer}.txt
    #    每个文档对应一个知识点，RAGflow 向量检索精度更高，分类信息也保留在文件名中
    result: Dict[str, Any] = {
        "uploaded": 0,
        "skipped": skipped_count,
        "failed": 0,
        "doc_ids": [],
        "failed_items": [],
    }
    request_timeout = int(str(cfg.get("request_timeout", "60") or "60"))

    for doc in transformed:
        exp_id = doc.get("exp_id", "unknown")
        layer  = doc.get("layer", "UNKNOWN")
        doc_dataset_id = _resolve_dataset_id_for_layer(layer, cfg, dataset_id)
        if not doc_dataset_id:
            layer_upper = str(layer).upper()
            if layer_upper in _LAYER_TO_DATASET_KEY:
                result["failed"] += 1
                logger.error(
                    f"[ragflow] upload SKIP(CONFIG) | {exp_id}[{layer}] | "
                    f"缺少映射: {_LAYER_TO_DATASET_KEY[layer_upper]}"
                )
            else:
                result["skipped"] += 1
                logger.warning(
                    f"[ragflow] upload SKIP(LAYER) | {exp_id}[{layer}] | 未配置目标经验库"
                )
            continue
        # 文件名中嵌入 session + exp_id + 分类，便于溯源和去重
        filename = f"exp_{session_id[:8]}_{exp_id}_{layer}.txt"
        payload_bytes = _experiences_to_text([doc]).encode("utf-8")
        files = {"file": (filename, payload_bytes, "text/plain")}
        
        # 构建 API Key 模式下的上传 URL：/api/v1/datasets/{kb_id}/documents
        dataset_upload_url = _api_url(cfg, f"/datasets/{doc_dataset_id}/documents")
        
        attempt = 0
        while True:
            try:
                resp = requests.post(
                    dataset_upload_url,
                    headers=_headers(token),
                    files=files,
                    timeout=request_timeout,
                )
                resp_json = resp.json() if resp.content else {}

                if resp.status_code == 200 and resp_json.get("code") == 0:
                    data = resp_json.get("data", {})
                    did = None
                    if isinstance(data, list) and data:
                        did = data[0].get("id")
                    elif isinstance(data, dict):
                        did = data.get("id")
                    if did:
                        result["doc_ids"].append(did)
                    result["uploaded"] += 1
                    break

                if resp.status_code == 502 and attempt < retry_502_max:
                    wait_sec = retry_base_sec * (2 ** attempt)
                    attempt += 1
                    logger.warning(
                        "[ragflow] upload RETRY(502) | %s[%s] | dataset=%s | attempt=%d/%d | wait=%.1fs",
                        exp_id,
                        layer,
                        doc_dataset_id,
                        attempt,
                        retry_502_max,
                        wait_sec,
                    )
                    time.sleep(wait_sec)
                    continue

                result["failed"] += 1
                detail = {
                    "exp_id": exp_id,
                    "layer": layer,
                    "dataset": doc_dataset_id,
                    "status_code": resp.status_code,
                    "error": str(resp_json or resp.text[:200]),
                    "attempts": attempt + 1,
                }
                result["failed_items"].append(detail)
                logger.error(
                    f"[ragflow] upload FAIL | {exp_id}[{layer}] | "
                    f"dataset={doc_dataset_id} | "
                    f"HTTP {resp.status_code} | {resp_json or resp.text[:200]}"
                )
                break

            except Exception as e:
                result["failed"] += 1
                detail = {
                    "exp_id": exp_id,
                    "layer": layer,
                    "dataset": doc_dataset_id,
                    "status_code": None,
                    "error": str(e),
                    "attempts": attempt + 1,
                }
                result["failed_items"].append(detail)
                logger.error(
                    f"[ragflow] upload ERROR | {exp_id}[{layer}] | dataset={doc_dataset_id} | {e}"
                )
                break

    logger.info(
        f"[ragflow] upload OK | session={session_id[:8]} | "
        f"docs={result['uploaded']} failed={result['failed']} "
        f"doc_ids(first3)={result['doc_ids'][:3]}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 便捷工具：从 JSONL 文件读取并上传
# ─────────────────────────────────────────────────────────────────────────────

def upload_session_jsonl(
    jsonl_path: str,
    session_id: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
    retry_502_max: int = 3,
    retry_base_sec: float = 1.0,
) -> Dict[str, Any]:
    """从 experiences.jsonl 文件读取所有经验并上传至 RAGflow。"""
    from pathlib import Path
    p = Path(jsonl_path)
    if not p.exists():
        logger.warning(f"[ragflow] 文件不存在: {jsonl_path}")
        return {"uploaded": 0, "skipped": 0, "failed": 0, "doc_ids": [], "error": "file_not_found"}

    experiences: List[Dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    experiences.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logger.warning(f"[ragflow] JSON 解析失败: {e}")
                    continue

    return upload_experiences_to_ragflow(
        experiences,
        session_id,
        dataset_id=dataset_id,
        cfg=cfg,
        dry_run=dry_run,
        retry_502_max=retry_502_max,
        retry_base_sec=retry_base_sec,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 批量上传：扫描 layer2_output 目录下所有 session
# ─────────────────────────────────────────────────────────────────────────────

def upload_all_sessions(
    layer2_output_dir: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
    retry_502_max: int = 3,
    retry_base_sec: float = 1.0,
) -> Dict[str, Any]:
    """
    扫描 data/layer2_output/ 下所有 session 子目录，
    读取各自的 experiences.jsonl 并上传到 RAGflow 经验库。

    适用于"把现有内容全量推送"的初始化场景。
    """
    from pathlib import Path
    base = Path(layer2_output_dir)

    total_uploaded = 0
    total_skipped  = 0
    total_failed   = 0
    all_doc_ids: List[str] = []
    all_failed_items: List[Dict[str, Any]] = []
    session_results: List[Dict[str, Any]] = []

    # 枚举 UUID 格式目录
    for session_dir in sorted(base.iterdir()):
        if not session_dir.is_dir():
            continue
        jsonl_file = session_dir / "experiences.jsonl"
        if not jsonl_file.exists():
            continue
        session_id = session_dir.name

        logger.info(f"[ragflow] 处理 session: {session_id[:8]}…")
        res = upload_session_jsonl(
            str(jsonl_file), session_id,
            dataset_id=dataset_id,
            cfg=cfg,
            dry_run=dry_run,
            retry_502_max=retry_502_max,
            retry_base_sec=retry_base_sec,
        )
        total_uploaded += res.get("uploaded", 0)
        total_skipped  += res.get("skipped", 0)
        total_failed   += res.get("failed", 0)
        all_doc_ids.extend(res.get("doc_ids", []))
        all_failed_items.extend(res.get("failed_items", []))
        session_results.append({"session_id": session_id, **res})

    summary = {
        "total_sessions": len(session_results),
        "total_uploaded": total_uploaded,
        "total_skipped":  total_skipped,
        "total_failed":   total_failed,
        "doc_ids":        all_doc_ids,
        "failed_items":   all_failed_items,
        "sessions":       session_results,
    }
    logger.info(
        f"[ragflow] 批量上传完成 | sessions={len(session_results)} "
        f"uploaded={total_uploaded} skipped={total_skipped} failed={total_failed}"
    )
    return summary


def upload_fused_jsonl(
    fused_jsonl_path: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
    retry_502_max: int = 3,
    retry_base_sec: float = 1.0,
    exp_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """上传 Layer3 Phase34 融合经验（不按 maturity 过滤）。"""
    p = Path(fused_jsonl_path)
    if not p.exists():
        logger.warning(f"[ragflow] 融合经验文件不存在: {fused_jsonl_path}")
        return {
            "uploaded": 0,
            "skipped": 0,
            "failed": 0,
            "doc_ids": [],
            "failed_items": [],
            "error": "file_not_found",
            "source": "fused",
            "input_file": str(p),
        }

    experiences: List[Dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                experiences.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"[ragflow] 融合经验 JSON 解析失败: {e}")

    exp_id_set = {x.strip() for x in (exp_ids or []) if str(x).strip()}
    missing_exp_ids: List[str] = []
    if exp_id_set:
        before = len(experiences)
        experiences = [e for e in experiences if str(e.get("exp_id", "")).strip() in exp_id_set]
        found = {str(e.get("exp_id", "")).strip() for e in experiences}
        missing_exp_ids = sorted(exp_id_set - found)
        logger.info(
            "[ragflow] 融合子集补传: requested=%d matched=%d missing=%d (input=%d)",
            len(exp_id_set),
            len(found),
            len(missing_exp_ids),
            before,
        )

    session_id = f"fused_{p.stem}" if not exp_id_set else f"fused_retry_{p.stem}"
    result = upload_experiences_to_ragflow(
        experiences,
        session_id=session_id,
        dataset_id=dataset_id,
        cfg=cfg,
        dry_run=dry_run,
        retry_502_max=retry_502_max,
        retry_base_sec=retry_base_sec,
    )
    result["source"] = "fused"
    result["input_file"] = str(p)
    result["total_input"] = len(experiences)
    if exp_id_set:
        result["requested_exp_ids"] = sorted(exp_id_set)
        result["missing_exp_ids"] = missing_exp_ids
    return result


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

def _extract_dataset_items(raw_data: Any) -> List[Dict[str, Any]]:
    if isinstance(raw_data, list):
        return [d for d in raw_data if isinstance(d, dict)]
    if isinstance(raw_data, dict):
        for key in ("datasets", "items", "docs"):
            value = raw_data.get(key)
            if isinstance(value, list):
                return [d for d in value if isinstance(d, dict)]
    return []


def validate_ragflow_connection(
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """仅验证 RAGFlow 连接与数据集可见性，不执行任何上传。"""
    base_url = _normalize_base_url(cfg)
    datasets_url = _api_url(cfg, "/datasets")
    retrieval_url = _api_url(cfg, "/retrieval")

    try:
        token = _login(cfg)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "base_url": base_url,
            "error": f"auth_failed: {exc}",
        }

    try:
        resp = requests.get(
            datasets_url,
            headers=_headers(token),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "base_url": base_url,
            "datasets_url": datasets_url,
            "error": f"request_failed: {exc}",
        }

    body = resp.json() if resp.content else {}
    if resp.status_code != 200 or body.get("code") != 0:
        return {
            "ok": False,
            "base_url": base_url,
            "datasets_url": datasets_url,
            "status_code": resp.status_code,
            "api_code": body.get("code"),
            "api_message": body.get("message"),
        }

    dataset_items = _extract_dataset_items(body.get("data"))
    visible_ids = {
        str(item.get("id", "")).strip()
        for item in dataset_items
        if str(item.get("id", "")).strip()
    }

    required_dataset_keys = sorted(set(_LAYER_TO_DATASET_KEY.values()))
    required_dataset_ids = [
        str(cfg.get(k, "")).strip()
        for k in required_dataset_keys
        if str(cfg.get(k, "")).strip()
    ]
    missing_dataset_ids = [did for did in required_dataset_ids if did not in visible_ids]

    return {
        "ok": len(missing_dataset_ids) == 0,
        "mode": "validate_only",
        "base_url": base_url,
        "datasets_url": datasets_url,
        "retrieval_url": retrieval_url,
        "dataset_count": len(visible_ids),
        "required_dataset_ids": required_dataset_ids,
        "missing_dataset_ids": missing_dataset_ids,
    }


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="将融合经验或 layer2 原始经验上传至 RAGflow 经验库")
    parser.add_argument(
        "--source",
        choices=["fused", "raw"],
        default="fused",
        help="上传源：fused=Layer3 融合结果，raw=Layer2 原始经验（按 session 目录）",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="仅验证 RAGflow 连接与知识库可见性，不执行上传",
    )
    parser.add_argument(
        "--validate-timeout",
        type=float,
        default=15.0,
        help="--validate-only 模式下的请求超时秒数",
    )
    parser.add_argument(
        "--retry-502-max",
        type=int,
        default=3,
        help="HTTP 502 最大重试次数（指数退避）",
    )
    parser.add_argument(
        "--retry-base-sec",
        type=float,
        default=1.0,
        help="HTTP 502 指数退避基准秒数（默认 1.0）",
    )
    parser.add_argument(
        "--fused-file",
        default=str(DEFAULT_FUSED_FILE),
        help="融合经验文件（默认 data/layer3_output/phase34_consolidated.jsonl）",
    )
    parser.add_argument(
        "--layer2-dir",
        default=str(ROOT / "data" / "layer2_output"),
        help="data/layer2_output 目录路径",
    )
    parser.add_argument("--dry-run", action="store_true", help="仅变换，不实际上传")
    parser.add_argument("--session", default=None, help="仅 raw 模式下上传指定 session ID（可省略）")
    parser.add_argument(
        "--exp-ids",
        default="",
        help="仅 fused 模式：按逗号指定 exp_id 子集补传（例如 exp_a,exp_b）",
    )
    args = parser.parse_args(argv)

    if args.validate_only:
        result = validate_ragflow_connection(
            cfg=RAGFLOW_CONFIG,
            timeout=max(1.0, float(args.validate_timeout)),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1

    retry_502_max = max(0, int(args.retry_502_max))
    retry_base_sec = max(0.1, float(args.retry_base_sec))
    exp_ids = [s.strip() for s in str(args.exp_ids).split(",") if s.strip()]

    def _is_hard_upload_failure(res: dict) -> bool:
        """上传阶段失败判定：非 dry-run 且全部上传失败。"""
        uploaded = int(res.get("uploaded", res.get("total_uploaded", 0)) or 0)
        failed = int(res.get("failed", res.get("total_failed", 0)) or 0)
        return failed > 0 and uploaded == 0

    if args.source == "fused":
        result = upload_fused_jsonl(
            args.fused_file,
            dry_run=args.dry_run,
            retry_502_max=retry_502_max,
            retry_base_sec=retry_base_sec,
            exp_ids=exp_ids,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2,
                         default=lambda o: str(o)))
        if not args.dry_run and _is_hard_upload_failure(result):
            logger.error(
                "[ragflow] 融合经验上传全失败：uploaded=%s failed=%s",
                result.get("uploaded", 0),
                result.get("failed", 0),
            )
            return 1
        return 0

    if args.session:
        jsonl_path = Path(args.layer2_dir) / args.session / "experiences.jsonl"
        result = upload_session_jsonl(
            str(jsonl_path),
            args.session,
            dry_run=args.dry_run,
            retry_502_max=retry_502_max,
            retry_base_sec=retry_base_sec,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not args.dry_run and _is_hard_upload_failure(result):
            logger.error(
                "[ragflow] 会话上传失败：uploaded=%s failed=%s",
                result.get("uploaded", 0),
                result.get("failed", 0),
            )
            return 1
        return 0

    result = upload_all_sessions(
        args.layer2_dir,
        dry_run=args.dry_run,
        retry_502_max=retry_502_max,
        retry_base_sec=retry_base_sec,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2,
                     default=lambda o: str(o)))
    if not args.dry_run and _is_hard_upload_failure(result):
        logger.error(
            "[ragflow] 批量上传全失败：uploaded=%s failed=%s",
            result.get("total_uploaded", 0),
            result.get("total_failed", 0),
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
