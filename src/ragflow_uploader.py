"""
ragflow_uploader.py
===================
将 Layer 2 提取的经验条目上传至 RAGflow 经验库。

设计：
- 按照 RAG 入库字段规范对各层经验字段做精简（削减 ~67% 噪声字段）
- 每个 session 的经验打包为一个 JSON 文件上传到 RAGflow 的经验库 dataset
- 支持 email/password 登录获取 Bearer token，token 会在进程内缓存
- RAG_EVALUATION 层不上传（无 Agent 检索价值）

目标库：
  经验库   EXPERIENCE_DATASET_ID = b5f3a66f065f11f1bca40242ac120006
  完整语料库 FULL_DATASET_ID      = b877bec1065c11f1a8960242ac120006
  （完整语料库暂未启用，预留接口）

账号配置 —— 统一在 RAGFLOW_CONFIG 字典中修改：
  BASE_URL  : http://8.140.33.83
  EMAIL     : 123456@mail.com
  PASSWORD  : 123456
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

# ─────────────────────────────────────────────────────────────────────────────
# 配置
# ─────────────────────────────────────────────────────────────────────────────

RAGFLOW_CONFIG: Dict[str, str] = {
    "base_url":            "http://8.140.33.83",
    "email":               "123456@mail.com",
    "password":            "123456",
    # ↓ 推荐：直接在 RAGflow Web UI (右上角头像→API Key) 生成后填入此处。
    #   填入后自动跳过 email/password 登录流程，更稳定。
    "api_key":             "",                                    # e.g. "ragflow-Xxxx..."
    "experience_dataset":  "b5f3a66f065f11f1bca40242ac120006",   # 经验库
    "full_dataset":        "b877bec1065c11f1a8960242ac120006",    # 完整语料库（预留）
}

logger = logging.getLogger("ragflow_uploader")

# ─────────────────────────────────────────────────────────────────────────────
# RAGflow 默认 RSA 公钥（硬编码，来源：infiniflow/ragflow admin/client/ragflow_cli.py）
# 服务器在 conf/public.pem 使用相同的默认密钥对，Docker 默认镜像均使用此密钥
# ─────────────────────────────────────────────────────────────────────────────
_RAGFLOW_DEFAULT_PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArq9XTUSeYr2+N1h3Afl/"
    "z8Dse/2yD0ZGrKwx+EEEcdsBLca9Ynmx3nIB5obmLlSfmskLpBo0UACBmB5rEjBp"
    "2Q2f3AG3Hjd4B+gNCG6BDaawuDlgANIhGnaTLrIqWrrcm4EMzJOnAOI1fgzJRsOO"
    "UEfaS318Eq9OVO3apEyCCt0lOQK6PuksduOjVxtltDav+guVAA068NrPYmRNabVKR"
    "NLJpL8w4D44sfth5RvZ3q9t+6RTArpEtc5sh5ChzvqPOzKGMXW83C95TxmXqpbK6o"
    "lN4RevSfVjEAgCydH6HN6OhtOQEcnrU97r9H0iZOWwbw3pVrZiUkuRD1R56Wzs2w"
    "IDAQAB"
    "\n-----END PUBLIC KEY-----"
)

# ─────────────────────────────────────────────────────────────────────────────
# 鉴权
# ─────────────────────────────────────────────────────────────────────────────

_cached_token: Optional[str] = None


def _rsa_encrypt_password(password: str, base_url: str) -> Optional[str]:
    """
    使用 RSA PKCS1_v1_5 加密密码。
    优先使用 RAGflow 硬编码的默认公钥，备选从服务器 JS 动态提取。
    返回 base64(encrypt(base64(password))) 字符串，或 None（失败时）。
    """
    try:
        try:
            from Cryptodome.PublicKey import RSA
            from Cryptodome.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
        except ImportError:
            from Crypto.PublicKey import RSA              # type: ignore
            from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5  # type: ignore
        import base64 as _b64

        # ── 主路径：使用硬编码默认公钥 ─────────────────────────────────────
        pub_key_pem: Optional[str] = _RAGFLOW_DEFAULT_PUBKEY

        # ── 备选路径：从前端 JS 动态提取（用于自定义密钥的部署） ─────────
        # （先尝试默认密钥，若服务器返回 500/crypt error 再考虑走此路径）
        # 此处保留逻辑但默认不执行，若需启用请注释掉上方 pub_key_pem 赋值
        # import re
        # main_resp = requests.get(base_url + "/", timeout=10)
        # js_files = re.findall(r'src="(/[^"]+\.js)"', main_resp.text)
        # ... （略）

        rsa_key = RSA.import_key(pub_key_pem)
        cipher = Cipher_pkcs1_v1_5.new(rsa_key)
        pwd_b64 = _b64.b64encode(password.encode("utf-8"))
        encrypted = cipher.encrypt(pwd_b64)
        return _b64.b64encode(encrypted).decode("utf-8")
    except Exception as e:
        logger.warning(f"[ragflow] RSA 密码加密失败: {e}")
        return None


def _login(cfg: Dict[str, str] = RAGFLOW_CONFIG) -> str:
    """
    获取 Bearer token（进程内缓存）。

    优先级：
    1. 缓存 token
    2. cfg["api_key"] 直接使用（推荐，从 RAGflow Web UI API Key 页面获取）
    3. email/password 登录（需要 RSA 加密密码，自动尝试从前端 JS 提取公钥）
    """
    global _cached_token
    if _cached_token:
        return _cached_token

    # ── 方式 1：直接 API key ─────────────────────────────────────────────────
    # 优先从环境变量 RAGFLOW_API_KEY 取，其次从 cfg["api_key"]
    api_key = os.environ.get("RAGFLOW_API_KEY", "").strip() or cfg.get("api_key", "").strip()
    if api_key:
        _cached_token = api_key
        logger.info("[ragflow] 使用配置的 api_key 进行认证")
        return api_key

    # ── 方式 2：email/password 登录 ─────────────────────────────────────────
    logger.info("[ragflow] 尝试 email/password 登录...")
    url = f"{cfg['base_url']}/v1/user/login"

    # 先尝试 RSA 加密密码
    enc_password = _rsa_encrypt_password(cfg["password"], cfg["base_url"])
    if enc_password is None:
        logger.warning(
            "\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[ragflow] ⚠️  无法自动登录（需要 RSA 加密密码）\n"
            "  请手动获取 API Key：\n"
            f"  1. 浏览器打开 {cfg['base_url']}\n"
            f"  2. 账号 {cfg['email']} 登录\n"
            "  3. 右上角头像 → API Key → 创建新 Key\n"
            "  4. 复制后填入 RAGFLOW_CONFIG['api_key'] 字段\n"
            "     或设置环境变量 RAGFLOW_API_KEY=ragflow-xxx\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        raise RuntimeError(
            "[ragflow] 登录失败：无法获取 RSA 公钥加密密码。"
            "请在 RAGFLOW_CONFIG['api_key'] 中配置从 Web UI 获取的 API Key。"
        )

    payload = {"email": cfg["email"], "password": enc_password}
    try:
        resp = requests.post(url, json=payload, timeout=15)
        data = resp.json() if resp.content else {}
        if data.get("code") == 0:
            # RAGflow 将 token 放在响应头 Authorization 里（ragflow_cli.py 同逻辑）
            auth_header = resp.headers.get("Authorization", "")
            # 头部格式可能是 "Bearer <token>" 或直接是 token 字符串
            token = auth_header.split()[-1] if auth_header else ""
            # 老版本可能在响应体 data 里
            if not token:
                token = (
                    data.get("data", {}).get("access_token", "")
                    or data.get("data", {}).get("token", "")
                )
            if not token:
                raise RuntimeError(
                    f"登录成功但未返回 token。\n"
                    f"  响应头 Authorization: {auth_header!r}\n"
                    f"  响应体 data: {data.get('data', {})}"
                )
            _cached_token = token
            logger.info("[ragflow] 登录成功，token 已缓存")
            return token
        else:
            raise RuntimeError(
                f"登录失败 (code={data.get('code')}): {data.get('message', data)}"
            )
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"[ragflow] 登录异常: {e}") from e


def _headers(token: str) -> Dict[str, str]:
    """
    生成请求头。
    - 老版本 RAGflow (/v1/ 路径) 使用 session token（不加 Bearer 前缀）
    - 新版本 RAGflow (/api/v1/ 路径) 需要 Bearer + ragflow-xxx API key
    """
    return {"Authorization": token}


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
    }
    if target_service:
        filter_out["target_service"] = target_service
    if target_version and target_version != "None":
        filter_out["target_version"] = target_version
    if cve_ids:
        filter_out["cve_ids"] = cve_ids

    return {
        "exp_id": raw["exp_id"],
        "layer": "FACTUAL_RULE",
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
    }
    if target_service:
        filter_out["target_service"] = target_service

    return {
        "exp_id": raw["exp_id"],
        "layer": "FACTUAL_LLM",
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
    layer = raw.get("knowledge_layer", "")
    extraction_source = (raw.get("metadata", {}).get("extraction_source", "")
                         or raw.get("metadata", {}).get("extraction_source", ""))

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
        # PROCEDURAL_POS 暂无上传规范
        return None

    return None


# ─────────────────────────────────────────────────────────────────────────────
# 上传
# ─────────────────────────────────────────────────────────────────────────────

def upload_experiences_to_ragflow(
    experiences: List[Dict[str, Any]],
    session_id: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
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
        目标 dataset ID，默认使用 cfg["experience_dataset"]
    cfg         : dict
        配置字典，包含 base_url / email / password 等
    dry_run     : bool
        True 时仅做变换和打印，不实际上传

    Returns
    -------
    dict 包含 uploaded / skipped / failed / doc_ids 等统计字段
    """
    if dataset_id is None:
        dataset_id = cfg["experience_dataset"]

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
        return {"uploaded": 0, "skipped": skipped_count, "failed": 0, "doc_ids": []}

    if dry_run:
        logger.info(f"[ragflow][DRY_RUN] 跳过实际上传，变换后 {len(transformed)} 条")
        return {"uploaded": 0, "skipped": skipped_count, "failed": 0,
                "doc_ids": [], "dry_run_docs": transformed}

    # 2. 获取 Bearer token
    try:
        token = _login(cfg)
    except RuntimeError as e:
        logger.error(str(e))
        return {"uploaded": 0, "skipped": skipped_count, "failed": len(transformed), "doc_ids": [],
                "error": str(e)}

    # 3. 逐条上传：每条经验独立成一个 .txt 文件
    #    文件名格式：exp_{session_short}_{exp_id}_{layer}.txt
    #    每个文档对应一个知识点，RAGflow 向量检索精度更高，分类信息也保留在文件名中
    upload_url = f"{cfg['base_url']}/v1/document/upload"
    form_data = {"kb_id": dataset_id, "parser_id": "naive"}

    result: Dict[str, Any] = {
        "uploaded": 0,
        "skipped": skipped_count,
        "failed": 0,
        "doc_ids": [],
    }

    for doc in transformed:
        exp_id = doc.get("exp_id", "unknown")
        layer  = doc.get("layer", "UNKNOWN")
        # 文件名中嵌入 session + exp_id + 分类，便于溯源和去重
        filename = f"exp_{session_id[:8]}_{exp_id}_{layer}.txt"
        payload_bytes = _experiences_to_text([doc]).encode("utf-8")
        files = {"file": (filename, payload_bytes, "text/plain")}
        try:
            resp = requests.post(
                upload_url,
                headers=_headers(token),
                files=files,
                data=form_data,
                timeout=60,
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
            else:
                result["failed"] += 1
                logger.error(
                    f"[ragflow] upload FAIL | {exp_id}[{layer}] | "
                    f"HTTP {resp.status_code} | {resp_json or resp.text[:200]}"
                )
        except Exception as e:
            result["failed"] += 1
            logger.error(f"[ragflow] upload ERROR | {exp_id}[{layer}] | {e}")

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
        experiences, session_id, dataset_id=dataset_id, cfg=cfg, dry_run=dry_run
    )


# ─────────────────────────────────────────────────────────────────────────────
# 批量上传：扫描 layer2_output 目录下所有 session
# ─────────────────────────────────────────────────────────────────────────────

def upload_all_sessions(
    layer2_output_dir: str,
    dataset_id: Optional[str] = None,
    cfg: Dict[str, str] = RAGFLOW_CONFIG,
    dry_run: bool = False,
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
            dataset_id=dataset_id, cfg=cfg, dry_run=dry_run
        )
        total_uploaded += res.get("uploaded", 0)
        total_skipped  += res.get("skipped", 0)
        total_failed   += res.get("failed", 0)
        all_doc_ids.extend(res.get("doc_ids", []))
        session_results.append({"session_id": session_id, **res})

    summary = {
        "total_sessions": len(session_results),
        "total_uploaded": total_uploaded,
        "total_skipped":  total_skipped,
        "total_failed":   total_failed,
        "doc_ids":        all_doc_ids,
        "sessions":       session_results,
    }
    logger.info(
        f"[ragflow] 批量上传完成 | sessions={len(session_results)} "
        f"uploaded={total_uploaded} skipped={total_skipped} failed={total_failed}"
    )
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="将 layer2 经验上传至 RAGflow 经验库")
    parser.add_argument(
        "--layer2-dir",
        default=str(Path(__file__).parent.parent / "data" / "layer2_output"),
        help="data/layer2_output 目录路径",
    )
    parser.add_argument("--dry-run", action="store_true", help="仅变换，不实际上传")
    parser.add_argument("--session", default=None, help="只上传指定 session ID（可省略）")
    args = parser.parse_args()

    if args.session:
        jsonl_path = Path(args.layer2_dir) / args.session / "experiences.jsonl"
        result = upload_session_jsonl(
            str(jsonl_path), args.session, dry_run=args.dry_run
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        result = upload_all_sessions(
            args.layer2_dir, dry_run=args.dry_run
        )
        print(json.dumps(result, ensure_ascii=False, indent=2,
                         default=lambda o: str(o)))
