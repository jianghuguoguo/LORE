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

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 默认配置（与 ragflow_uploader.py 保持一致）
# ─────────────────────────────────────────────────────────────────────────────
RAGFLOW_CONFIG: Dict[str, str] = {
    "base_url":           "http://8.140.33.83",
    "email":              "123456@mail.com",
    "password":           "123456",
    "api_key":            "",                                    # 推荐：填入 Web UI 生成的 API Key
    "experience_dataset": "b5f3a66f065f11f1bca40242ac120006",   # 经验知识库
}

# RAGFlow 默认 RSA 公钥（与 ragflow_uploader.py 同源）
_DEFAULT_PUBKEY = (
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


def _rsa_encrypt(password: str) -> Optional[str]:
    """RSA PKCS1_v1_5 加密密码，返回 base64 字符串；失败返回 None。"""
    try:
        try:
            from Cryptodome.PublicKey import RSA
            from Cryptodome.Cipher import PKCS1_v1_5 as Cipher_pkcs1
        except ImportError:
            from Crypto.PublicKey import RSA              # type: ignore
            from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1  # type: ignore
        import base64
        rsa_key = RSA.import_key(_DEFAULT_PUBKEY)
        cipher = Cipher_pkcs1.new(rsa_key)
        encrypted = cipher.encrypt(base64.b64encode(password.encode()))
        return base64.b64encode(encrypted).decode()
    except Exception as exc:
        logger.debug("RSA 加密失败: %s", exc)
        return None


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
        timeout: int = 60,
        retry_times: int = 2,
    ) -> None:
        self.cfg = cfg or RAGFLOW_CONFIG
        self.dataset_id = dataset_id or self.cfg.get("experience_dataset", "")
        self.timeout = timeout
        self.retry_times = retry_times
        self._token: Optional[str] = None
        self._auth_is_api_key: bool = False  # True=api_key(Bearer前缀), False=JWT(无前缀)
        self._proxies: Dict[str, str] = {}   # 始终绕过系统代理

    # ── 鉴权 ─────────────────────────────────────────────────────────────────

    def _get_token(self) -> str:
        """获取 Bearer token（进程内缓存；优先使用 api_key）。"""
        if self._token:
            return self._token

        # 优先：环境变量 或 cfg api_key
        api_key = (os.environ.get("RAGFLOW_API_KEY", "").strip()
                   or self.cfg.get("api_key", "").strip())
        if api_key:
            self._token = api_key
            self._auth_is_api_key = True
            logger.info("[RAGFlowExpClient] 使用 api_key 鉴权")
            return self._token

        # 备选：email/password 登录
        enc_pwd = _rsa_encrypt(self.cfg.get("password", ""))
        if enc_pwd is None:
            raise RuntimeError(
                "[RAGFlowExpClient] 无法鉴权：RSA 加密失败，"
                "请在 RAGFLOW_CONFIG['api_key'] 或 RAGFLOW_API_KEY 环境变量中配置 API Key。"
            )
        url = f"{self.cfg['base_url']}/v1/user/login"
        resp = requests.post(
            url,
            json={"email": self.cfg["email"], "password": enc_pwd},
            timeout=15,
            proxies=self._proxies,
        )
        data = resp.json() if resp.content else {}
        if data.get("code") == 0:
            # RAGFlow 旧版：Bearer token 在响应 header Authorization 中
            auth = resp.headers.get("Authorization", "")
            token = auth if auth else (
                data.get("data", {}).get("access_token")
                or data.get("data", {}).get("token", "")
            )
            if not token:
                raise RuntimeError(f"登录返回无 token: {data}")
            self._token = token
            self._auth_is_api_key = False  # JWT，无需 Bearer 前缀
            logger.info("[RAGFlowExpClient] email/password 登录成功")
            return self._token
        raise RuntimeError(f"登录失败 code={data.get('code')} msg={data.get('message')}")

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        if self._auth_is_api_key:
            return {"Authorization": f"Bearer {token}"}
        return {"Authorization": token}  # JWT 直接使用，无需 Bearer 前缀

    # ── 核心操作 ─────────────────────────────────────────────────────────────

    def upload_exp(
        self,
        exp_id: str,
        title: str,
        content_text: str,
        custom_meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        上传单条经验文本到 RAGFlow 经验知识库。

        Parameters
        ----------
        exp_id       : 经验 ID（写入文件名，用于溯源）
        title        : 文档标题（将成为 doc.name）
        content_text : 纯文本内容（已由 format_exp_for_rag 格式化）
        custom_meta  : 额外元数据（当前 RAGFlow 暂不支持自定义 chunk meta，预留）

        Returns
        -------
        str  : ragflow_doc_id（形如 "abc123..."），失败返回 None
        """
        url = f"{self.cfg['base_url']}/v1/document/upload"
        filename = f"xpec_{exp_id}.txt"
        payload = content_text.encode("utf-8")
        form_data = {"kb_id": self.dataset_id, "parser_id": "naive"}

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
                    logger.info("[upload_exp] OK  exp_id=%s  doc_id=%s", exp_id, doc_id)
                    return doc_id
                logger.warning(
                    "[upload_exp] FAIL attempt=%d/%d exp_id=%s HTTP=%d body=%s",
                    attempt + 1, self.retry_times + 1, exp_id,
                    resp.status_code, str(body)[:200],
                )
            except Exception as exc:
                logger.warning(
                    "[upload_exp] ERROR attempt=%d/%d exp_id=%s err=%s",
                    attempt + 1, self.retry_times + 1, exp_id, exc,
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
        url = f"{self.cfg['base_url']}/v1/document"
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

    def list_documents(self, dataset_id: Optional[str] = None, page_size: int = 100) -> List[Dict]:
        """列出知识库中的文档（用于对账）。"""
        did = dataset_id or self.dataset_id
        url = f"{self.cfg['base_url']}/v1/document/list"
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
        url = f"{self.cfg['base_url']}/v1/retrieval"
        payload = {
            "question": query,
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
