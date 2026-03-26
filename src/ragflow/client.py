"""
src/ragflow/client.py
=====================
RAGFlowExpClient — 专用于「经验回流」的 RAGFlow HTTP 封装。

职责：
  - upload_exp(exp_id, title, content_text, meta) → ragflow_doc_id
  - delete_document(doc_id)                       → bool
  - search_exp(query, top_k)                      → List[hit]
  - list_documents(dataset_id)                    → List[doc_meta]

设计原则（来自2.3节）：
  RAGFlow 是「只读缓存」，经验先在本地 KLM 完成冲突检测，
  通过后才调用本模块写入 RAGFlow。
  RAGFlow 中永远不应存在 conflicted 或 suspended 状态的经验。
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from ..utils.config_loader import get_config

logger = logging.getLogger(__name__)

_API_PREFIX = "/api/v1"

# ─────────────────────────────────────────────────────────────────────────────
# 默认配置（统一读取 configs/config.yaml）
# ─────────────────────────────────────────────────────────────────────────────
RAGFLOW_CONFIG: Dict[str, str] = get_config().ragflow_config


def _normalize_base_url(raw_base_url: str) -> str:
    """标准化 RAGFlow 基础地址，兼容是否包含 /api/v1。"""
    base = (raw_base_url or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("[RAGFlowExpClient] base_url 为空，请检查 RAGFlow 配置。")

    if base.endswith(_API_PREFIX):
        base = base[: -len(_API_PREFIX)].rstrip("/")

    return base


def _build_api_url(base_url: str, path: str) -> str:
    """拼接 API 地址，避免重复 /api/v1 或双斜杠。"""
    normalized_base = _normalize_base_url(base_url)
    normalized_path = "/" + (path or "").lstrip("/")

    if normalized_path == _API_PREFIX or normalized_path.startswith(f"{_API_PREFIX}/"):
        return f"{normalized_base}{normalized_path}"

    return f"{normalized_base}{_API_PREFIX}{normalized_path}"


# ─────────────────────────────────────────────────────────────────────────────
# 客户端主类
# ─────────────────────────────────────────────────────────────────────────────

class RAGFlowExpClient:
    """
    RAGFlow 经验回流客户端。

    Parameters
    ----------
    cfg          : dict，连接配置（默认使用模块级 RAGFLOW_CONFIG）
    dataset_id   : 目标 dataset，默认使用 cfg["experience_dataset"]
    timeout      : 单次请求超时（秒）
    retry_times  : 上传失败重试次数
    """

    def __init__(
        self,
        cfg: Optional[Dict[str, str]] = None,
        dataset_id: Optional[str] = None,
        timeout: Optional[int] = None,
        retry_times: Optional[int] = None,
    ) -> None:
        self.cfg = dict(RAGFLOW_CONFIG)
        if cfg:
            self.cfg.update(cfg)

        env_base_url = os.environ.get("RAGFLOW_BASE_URL", "").strip()
        if env_base_url:
            self.cfg["base_url"] = env_base_url

        self._base_url = _normalize_base_url(self.cfg.get("base_url", ""))
        self.dataset_id = dataset_id or self.cfg.get("experience_dataset", "")
        cfg_timeout = int(str(self.cfg.get("request_timeout", "60") or "60"))
        cfg_retry_times = int(str(self.cfg.get("retry_times", "2") or "2"))
        self.timeout = int(timeout) if timeout is not None else cfg_timeout
        self.retry_times = int(retry_times) if retry_times is not None else cfg_retry_times
        self._token: Optional[str] = None
        self._proxies: Dict[str, str] = {}   # 始终绕过系统代理

    # ── 鉴权 ─────────────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        """获取 API Key（优先使用环境变量）。"""
        if self._token:
            return self._token

        # 优先使用环境变量或配置中的 api_key
        api_key = (os.environ.get("RAGFLOW_API_KEY", "").strip()
                   or self.cfg.get("api_key", "").strip())
        if not api_key:
            raise RuntimeError(
                "[RAGFlowExpClient] 无法鉴权：未配置 API Key。"
                "请设置 RAGFLOW_API_KEY 环境变量或在 configs/config.yaml 的 ragflow.api_key_literal 中填入。"
            )

        self._token = api_key
        logger.info("[RAGFlowExpClient] 使用 API Key 鉴权")
        return self._token

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        # RAGFlow API Key 规范：必须带 Bearer 前缀
        return {"Authorization": f"Bearer {token}"}

    @property
    def base_url(self) -> str:
        """返回标准化后的 RAGFlow 主机地址（不含 /api/v1）。"""
        return self._base_url

    def _api_url(self, path: str) -> str:
        """构建 RAGFlow API 地址。"""
        return _build_api_url(self._base_url, path)

    def api_url(self, path: str) -> str:
        """对外暴露 URL 构建，便于测试脚本复用同一链接规则。"""
        return self._api_url(path)

    # ── 核心操作 ─────────────────────────────────────────────────────────────

    def upload_exp(
        self,
        exp_id: str,
        title: str,
        content_text: str,
        custom_meta: Optional[Dict[str, Any]] = None,
        dataset_id: Optional[str] = None,
    ) -> Optional[str]:
        """
        上传单条经验文本到 RAGFlow 经验知识库。

        Parameters
        ----------
        exp_id       : 经验 ID（写入文件名，用于溯源）
        title        : 文档标题（将成为 doc.name）
        content_text : 纯文本内容（已由 format_exp_for_rag 格式化）
        custom_meta  : 额外元数据（当前 RAGFlow 暂不支持自定义 chunk meta，预留）
        dataset_id   : 可选覆盖上传目标 dataset（默认 self.dataset_id）

        Returns
        -------
        str  : ragflow_doc_id（形如 "abc123..."），失败返回 None
        """
        url = self._api_url("/document/upload")
        filename = f"xpec_{exp_id}.txt"
        payload = content_text.encode("utf-8")
        target_dataset = dataset_id or self.dataset_id
        form_data = {"kb_id": target_dataset, "parser_id": "naive"}

        for attempt in range(self.retry_times + 1):
            try:
                resp = requests.post(
                    url,
                    headers=self._headers(),
                    files={"file": (filename, payload, "text/plain")},
                    data=form_data,
                    timeout=self.timeout,
                    proxies=self._proxies,
                )
                body = resp.json() if resp.content else {}
                if resp.status_code == 200 and body.get("code") == 0:
                    data = body.get("data") or {}
                    doc_id = (
                        data[0].get("id") if isinstance(data, list) and data
                        else data.get("id") if isinstance(data, dict) else None
                    )
                    logger.info(
                        "[upload_exp] OK exp_id=%s dataset=%s doc_id=%s",
                        exp_id,
                        target_dataset,
                        doc_id,
                    )
                    return doc_id
                logger.warning(
                    "[upload_exp] FAIL attempt=%d/%d exp_id=%s dataset=%s HTTP=%d body=%s",
                    attempt + 1, self.retry_times + 1, exp_id,
                    target_dataset, resp.status_code, str(body)[:200],
                )
            except Exception as exc:
                logger.warning(
                    "[upload_exp] ERROR attempt=%d/%d exp_id=%s dataset=%s err=%s",
                    attempt + 1, self.retry_times + 1, exp_id, target_dataset, exc,
                )
            if attempt < self.retry_times:
                time.sleep(2 ** attempt)  # 指数退避

        return None

    def delete_document(self, doc_id: str) -> bool:
        """
        从 RAGFlow 知识库中删除文档。

        当经验被标记为 conflicted 时，若之前已写入 RAGFlow，调用此方法删除。
        Returns True on success.
        """
        url = self._api_url("/document")
        payload = {"doc_ids": [doc_id]}
        try:
            resp = requests.delete(
                url,
                headers={**self._headers(), "Content-Type": "application/json"},
                json=payload,
                timeout=30,
                proxies=self._proxies,
            )
            body = resp.json() if resp.content else {}
            if resp.status_code == 200 and body.get("code") == 0:
                logger.info("[delete_document] OK  doc_id=%s", doc_id)
                return True
            logger.warning(
                "[delete_document] FAIL doc_id=%s HTTP=%d body=%s",
                doc_id, resp.status_code, str(body)[:200],
            )
        except Exception as exc:
            logger.error("[delete_document] ERROR doc_id=%s err=%s", doc_id, exc)
        return False

    def list_datasets(self) -> List[Dict[str, Any]]:
        """列出可访问的数据集列表。"""
        url = self._api_url("/datasets")
        try:
            resp = requests.get(
                url,
                headers=self._headers(),
                timeout=30,
                proxies=self._proxies,
            )
            body = resp.json() if resp.content else {}
            if body.get("code") != 0:
                return []

            data = body.get("data")
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("datasets", "items", "docs"):
                    value = data.get(key)
                    if isinstance(value, list):
                        return value
            return []
        except Exception as exc:
            logger.error("[list_datasets] ERROR %s", exc)
            return []

    def list_documents(self, dataset_id: Optional[str] = None, page_size: int = 100) -> List[Dict]:
        """列出知识库中的文档（用于对账）。"""
        did = dataset_id or self.dataset_id
        url = self._api_url("/document/list")
        try:
            resp = requests.get(
                url,
                headers=self._headers(),
                params={"kb_id": did, "page_size": page_size},
                timeout=30,
                proxies=self._proxies,
            )
            body = resp.json() if resp.content else {}
            if body.get("code") == 0:
                docs = body.get("data", {}).get("docs") or []
                return docs
        except Exception as exc:
            logger.error("[list_documents] ERROR %s", exc)
        return []

    def search_exp(
        self,
        query: str,
        dataset_id: Optional[str] = None,
        top_k: int = 5,
    ) -> List[Dict]:
        """
        语义搜索经验知识库（用于 Agent 查询；冲突检测不走此路径）。
        """
        did = dataset_id or self.dataset_id
        url = self._api_url("/retrieval")
        payload = {
            "question": query,
            "dataset_ids": [did],
            "datasets": [did],
            "top_k": top_k,
        }
        try:
            resp = requests.post(
                url,
                headers={**self._headers(), "Content-Type": "application/json"},
                json=payload,
                timeout=30,
                proxies=self._proxies,
            )
            body = resp.json() if resp.content else {}
            if body.get("code") == 0:
                return body.get("data", {}).get("chunks") or []
        except Exception as exc:
            logger.error("[search_exp] ERROR %s", exc)
        return []
