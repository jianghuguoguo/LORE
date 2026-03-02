"""
LLM 客户端抽象层
================
职责：封装所有 LLM API 调用，与具体 Provider 解耦。

支持的 Provider（均通过 openai SDK 的 OpenAI-compatible 接口调用）：
    - DeepSeek  : base_url="https://api.deepseek.com"  model="deepseek-chat"
    - OpenAI    : base_url=None（默认）               model="gpt-4o-mini"
    - Kimi      : base_url="https://api.moonshot.cn/v1" model="moonshot-v1-8k"
    - 通义千问  : base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
                  model="qwen-plus"
    - 其他兼容 OpenAI API 的服务：设置对应的 base_url 和 model 即可

切换方式：修改 configs/config.yaml 的 [llm] 节即可，代码无需改动。

设计原则：
    - openai SDK 统一入口，base_url 注入实现 Provider 切换
    - API Key 支持两种来源：环境变量（优先）> 配置文件明文（仅限测试）
    - 失败重试：指数退避，最多 max_retries 次
    - 输出：强制要求 JSON 格式，内置解析与校验
    - 线程安全：无共享状态，每次调用独立
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .utils.log_utils import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 配置数据类
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LLMConfig:
    """LLM 调用配置（从 config.yaml [llm] 节加载）。

    Fields:
        provider      : Provider 名称（仅说明用途，不影响调用逻辑）
        model         : 模型名称（如 "deepseek-chat", "gpt-4o-mini"）
        base_url      : API 端点 URL；None 表示使用 OpenAI 默认端点
        api_key_env   : 读取 API Key 的环境变量名（优先级高于 api_key_literal）
        api_key_literal: 直接写在配置文件中的 API Key（仅限开发/测试环境）
        temperature   : 生成温度（推荐 0.0 保证确定性输出）
        max_tokens    : 最大输出 token 数
        max_retries   : 失败后最多重试次数
        retry_delay   : 首次重试等待秒数（指数退避基数）
        timeout       : 单次 API 请求超时秒数
    """
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: Optional[str] = "https://api.deepseek.com"
    api_key_env: str = "DEEPSEEK_API_KEY"
    api_key_literal: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 2048
    max_retries: int = 3
    retry_delay: float = 2.0
    timeout: int = 60


@dataclass
class LLMCallResult:
    """单次 LLM 调用的结构化结果。

    Fields:
        content       : 响应文本（原始字符串）
        parsed        : 解析后的 JSON 对象（若 JSON 解析失败则为 None）
        model         : 实际使用的模型名
        prompt_tokens : 输入 token 数
        completion_tokens: 输出 token 数
        total_tokens  : 总 token 数
        latency_s     : 调用耗时（秒）
        success       : 是否成功（False 表示重试耗尽或解析失败）
        error         : 错误信息（success=False 时）
    """
    content: str = ""
    parsed: Optional[Dict[str, Any]] = None
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_s: float = 0.0
    success: bool = True
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# LLM 客户端
# ─────────────────────────────────────────────────────────────────────────────

class LLMClient:
    """Provider 无关的 LLM 调用客户端。

    Example:
        from src.llm_client import LLMClient, LLMConfig
        cfg = LLMConfig(provider="deepseek", model="deepseek-chat",
                        base_url="https://api.deepseek.com",
                        api_key_env="DEEPSEEK_API_KEY")
        client = LLMClient(cfg)
        result = client.chat_json([{"role": "user", "content": "Who are you?"}])
    """

    def __init__(self, config: LLMConfig) -> None:
        self._cfg = config
        self._client = self._build_client()

    # ── 内部：构建 openai 客户端 ──────────────────────────────────────────────

    def _build_client(self):
        """延迟导入 openai，避免影响未安装 openai 的单元测试环境。"""
        try:
            import openai  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "openai 包未安装。请运行：pip install openai>=1.0.0"
            ) from e

        api_key = self._resolve_api_key()
        if not api_key:
            raise ValueError(
                f"未能解析 API Key。检查环境变量 '{self._cfg.api_key_env}' 或"
                f" configs/config.yaml 的 llm.api_key_literal 字段。"
            )

        import openai as _openai

        kwargs: Dict[str, Any] = {"api_key": api_key, "timeout": self._cfg.timeout}
        if self._cfg.base_url:
            kwargs["base_url"] = self._cfg.base_url

        return _openai.OpenAI(**kwargs)

    def _resolve_api_key(self) -> Optional[str]:
        """按优先级解析 API Key：环境变量 > 配置明文。"""
        # 1. 环境变量（最高优先级，生产环境推荐）
        env_key = os.environ.get(self._cfg.api_key_env, "").strip()
        if env_key:
            return env_key
        # 2. 配置文件明文（仅限开发/测试）
        if self._cfg.api_key_literal:
            return self._cfg.api_key_literal.strip()
        return None

    # ── 公开接口 ──────────────────────────────────────────────────────────────

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        *,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMCallResult:
        """发送对话请求并要求返回 JSON 格式。

        Args:
            messages  : 消息列表（[{"role": "user", "content": "..."}]）
            system    : system prompt（若非 None 将插入 messages[0] 前）
            temperature: 覆盖配置的 temperature（None 则使用配置值）
            max_tokens : 覆盖配置的 max_tokens

        Returns:
            LLMCallResult，success=False 时 parsed 为 None，error 含错误描述
        """
        if system:
            messages = [{"role": "system", "content": system}] + list(messages)

        temp = temperature if temperature is not None else self._cfg.temperature
        max_tok = max_tokens if max_tokens is not None else self._cfg.max_tokens

        last_error: str = ""
        t0 = time.monotonic()

        for attempt in range(1, self._cfg.max_retries + 1):
            if attempt > 1:
                delay = self._cfg.retry_delay * (2 ** (attempt - 2))
                logger.debug("[llm] retry %d/%d after %.1fs", attempt, self._cfg.max_retries, delay)
                time.sleep(delay)

            try:
                resp = self._client.chat.completions.create(
                    model=self._cfg.model,
                    messages=messages,        # type: ignore[arg-type]
                    temperature=temp,
                    max_tokens=max_tok,
                    response_format={"type": "json_object"},
                )
                latency = time.monotonic() - t0
                raw = resp.choices[0].message.content or ""
                usage = resp.usage

                parsed = _parse_json(raw)
                if parsed is None:
                    logger.warning("[llm] JSON parse failed, attempt=%d raw=%r", attempt, raw[:200])
                    last_error = f"JSON decode error: {raw[:200]}"
                    continue  # 重试

                return LLMCallResult(
                    content=raw,
                    parsed=parsed,
                    model=resp.model,
                    prompt_tokens=usage.prompt_tokens if usage else 0,
                    completion_tokens=usage.completion_tokens if usage else 0,
                    total_tokens=usage.total_tokens if usage else 0,
                    latency_s=round(latency, 3),
                    success=True,
                )

            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                logger.warning("[llm] API error attempt=%d: %s", attempt, exc)

        latency = time.monotonic() - t0
        return LLMCallResult(
            success=False,
            error=last_error,
            latency_s=round(latency, 3),
            model=self._cfg.model,
        )

    @property
    def model(self) -> str:
        return self._cfg.model

    @property
    def provider(self) -> str:
        return self._cfg.provider

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ) -> str:
        """Layer 2 提取器使用的便捷接口：返回 raw 字符串而非 LLMCallResult。

        与 chat_json 的区别：
        - 不强制 response_format=json_object（支持数组、自由文本、代码块包裹的 JSON）
        - 提取器自己负责 JSON 解析

        Args:
            system_prompt : 系统提示词
            user_prompt   : 用户提示词
            temperature   : LLM 采样温度
            max_tokens    : 最大输出 token 数

        Returns:
            LLM 返回的原始文本

        Raises:
            RuntimeError: LLM 调用失败（全部重试序列均失败）
        """
        import time as _time

        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        temp = temperature if temperature is not None else self._cfg.temperature
        max_tok = max_tokens if max_tokens is not None else self._cfg.max_tokens
        last_error = ""

        for attempt in range(1, self._cfg.max_retries + 1):
            if attempt > 1:
                delay = self._cfg.retry_delay * (2 ** (attempt - 2))
                _time.sleep(delay)
            try:
                resp = self._client.chat.completions.create(
                    model=self._cfg.model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temp,
                    max_tokens=max_tok,
                )
                usage = resp.usage
                logger.info(
                    "[llm] chat() OK model=%s in=%d out=%d total=%d",
                    self._cfg.model,
                    usage.prompt_tokens if usage else 0,
                    usage.completion_tokens if usage else 0,
                    usage.total_tokens if usage else 0,
                )
                return resp.choices[0].message.content or ""
            except Exception as exc:
                last_error = str(exc)
                logger.warning("[llm] chat() error attempt=%d: %s", attempt, exc)

        raise RuntimeError(f"LLM 调用失败: {last_error}")


# ─────────────────────────────────────────────────────────────────────────────
# 工厂函数：从 config.yaml 构建 LLMClient
# ─────────────────────────────────────────────────────────────────────────────

def build_llm_client_from_config() -> LLMClient:
    """从 configs/config.yaml [llm] 节构建 LLMClient。

    config.yaml 示例::

        llm:
          provider: "deepseek"
          model: "deepseek-chat"
          base_url: "https://api.deepseek.com"
          api_key_env: "DEEPSEEK_API_KEY"
          api_key_literal: null          # 仅测试环境填写明文
          temperature: 0.0
          max_tokens: 2048
          max_retries: 3
          retry_delay: 2.0
          timeout: 60
    """
    from .utils.config_loader import get_config
    cfg_dict = get_config()._cfg.get("llm", {})

    llm_cfg = LLMConfig(
        provider=cfg_dict.get("provider", "deepseek"),
        model=cfg_dict.get("model", "deepseek-chat"),
        base_url=cfg_dict.get("base_url", "https://api.deepseek.com") or None,
        api_key_env=cfg_dict.get("api_key_env", "DEEPSEEK_API_KEY"),
        api_key_literal=cfg_dict.get("api_key_literal") or None,
        temperature=float(cfg_dict.get("temperature", 0.0)),
        max_tokens=int(cfg_dict.get("max_tokens", 2048)),
        max_retries=int(cfg_dict.get("max_retries", 3)),
        retry_delay=float(cfg_dict.get("retry_delay", 2.0)),
        timeout=int(cfg_dict.get("timeout", 60)),
    )
    return LLMClient(llm_cfg)


# ─────────────────────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json(text: Optional[str]) -> Optional[Dict[str, Any]]:
    """尝试解析 JSON，支持带有 markdown 代码块的输出。"""
    if not text:
        return None
    text = text.strip()
    # 去掉可能的 ```json ... ``` 包裹
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
