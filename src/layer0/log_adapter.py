"""
log_adapter.py – LogAdapter 抽象基类 + AdapterRegistry
========================================================
定义适配器契约（§2 LogAdapter 接口定义）与注册表机制。

使用示例：
    from src.layer0 import AdapterRegistry

    # 自动嗅探日志格式（推荐）
    adapter = AdapterRegistry.auto_detect(log_file)

    # 手动指定格式（config 中明确 adapter_name 时使用）
    adapter = AdapterRegistry.get_by_name("langchain")

    meta, turns = adapter.parse(log_file)
    for turn in turns:
        ...  # CanonicalAgentTurn

设计约束：
  - 适配器只做结构转换，不做任何语义判断（成功/失败判断是 Layer1 职责）
  - parse() 返回惰性迭代器，不要一次性加载全量数据到内存
  - can_handle() 不允许读取完整文件，只读前 N 行做格式嗅探
  - registry 是全局单例；适配器通过 @AdapterRegistry.register 装饰器注册
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, ClassVar, Iterator, List, Optional, Tuple, Type

from .canonical_types import CanonicalAgentTurn, SessionMeta

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# LogAdapter 抽象基类
# ─────────────────────────────────────────────────────────────────────────────

class LogAdapter(ABC):
    """渗透测试日志适配器抽象基类。

    职责（严格限定）：
      - 将特定外部日志格式的文件解析为 (SessionMeta, Iterator[CanonicalAgentTurn])
      - 不做语义理解，不做成功/失败判断，不做攻击阶段推断

    子类实现要求：
      1. 实现 can_handle(file_path) ─ 格式嗅探，只读前 N 行，O(1) 内存
      2. 实现 parse(file_path)      ─ 解析文件，返回惰性迭代器
      3. 实现 adapter_name 属性     ─ 唯一小写名称（用于日志与配置）
    """

    # ── 抽象接口 ─────────────────────────────────────────────────────────────

    @classmethod
    @abstractmethod
    def can_handle(cls, file_path: Path) -> bool:
        """格式嗅探：判断给定文件是否符合本适配器支持的格式。

        约束：
          - 只读文件头部（建议 ≤10 行），不读整个文件
          - 任何异常（IO、JSON 解析等）均 catch 并 return False
          - 通用兜底适配器（GenericJsonlAdapter）始终返回 True
        """

    @abstractmethod
    def parse(
        self,
        file_path: Path,
    ) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        """解析日志文件，返回 (会话元数据, 规范Turn惰性迭代器)。

        约束：
          - 迭代器须按 turn_index 升序 yield CanonicalAgentTurn
          - 同一 Turn 内的多个并行 tool_call 用 slot_in_turn 区分
          - 不要一次性将所有 Turn 加载到内存（大文件场景）
          - 任何单行解析失败均 log.warning 后跳过，不抛出异常
        """

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """适配器的唯一小写名称（如 "cai", "langchain", "generic"）。"""

    # ── 可选覆盖钩子 ────────────────────────────────────────────────────────

    def validate_file(self, file_path: Path) -> None:
        """验证文件可读性，在 parse() 前调用。子类可覆盖以添加格式专项校验。

        Raises:
            FileNotFoundError: 文件不存在
            ValueError:        文件为空或格式无效
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        if file_path.stat().st_size == 0:
            raise ValueError(f"Log file is empty: {file_path}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.adapter_name!r})>"


# ─────────────────────────────────────────────────────────────────────────────
# AdapterRegistry – 适配器注册表（全局单例）
# ─────────────────────────────────────────────────────────────────────────────

class AdapterRegistry:
    """适配器注册表，支持自动嗅探和手动指定。

    注册方式（两种，等价）：
        # 方式一：装饰器（推荐）
        @AdapterRegistry.register
        class MyAdapter(LogAdapter):
            ...

        # 方式二：手动注册
        AdapterRegistry.register(MyAdapter)

    查找顺序：
        按注册时间先后顺序嗅探，越先注册的优先级越高。
        通用 GenericJsonlAdapter 应最后注册（始终 can_handle=True）。
    """

    _adapters: ClassVar[List[Type[LogAdapter]]] = []

    @classmethod
    def register(
        cls,
        adapter_cls: Type[LogAdapter],
    ) -> Type[LogAdapter]:
        """注册一个适配器类（同时支持装饰器和直接调用）。

        若同名适配器已存在，发出警告并覆盖（便于热重载场景）。
        Returns:
            adapter_cls（保持可作为装饰器使用）
        """
        # 检查重复注册
        existing = next(
            (a for a in cls._adapters if a().adapter_name == adapter_cls().adapter_name),
            None,
        )
        if existing is not None:
            logger.warning(
                "Adapter '%s' already registered (%s). Overwriting with %s.",
                adapter_cls().adapter_name, existing, adapter_cls,
            )
            cls._adapters.remove(existing)
        cls._adapters.append(adapter_cls)
        logger.debug("Registered adapter: %s (name=%s)", adapter_cls, adapter_cls().adapter_name)
        return adapter_cls

    @classmethod
    def auto_detect(cls, file_path: Path) -> LogAdapter:
        """按注册顺序嗅探，返回第一个 can_handle=True 的适配器实例。

        若所有专用适配器均返回 False，兜底使用 GenericJsonlAdapter。
        若注册表为空，也返回 GenericJsonlAdapter。

        Args:
            file_path: 需要解析的日志文件路径

        Returns:
            适配器实例（已实例化）

        Raises:
            FileNotFoundError: 文件不存在时
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        for adapter_cls in cls._adapters:
            try:
                if adapter_cls.can_handle(file_path):
                    instance = adapter_cls()
                    logger.debug(
                        "auto_detect: %s matched by %s", file_path.name, instance.adapter_name
                    )
                    return instance
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Adapter %s.can_handle() raised: %s. Skipping.", adapter_cls, exc
                )

        # 兜底：即使注册表为空也可工作
        from .adapters.generic import GenericJsonlAdapter  # noqa: PLC0415

        logger.debug("auto_detect: no specific adapter matched; falling back to GenericJsonlAdapter")
        return GenericJsonlAdapter()

    @classmethod
    def get_by_name(cls, name: str) -> LogAdapter:
        """通过适配器名称直接获取实例（config 中指定 adapter: cai 时使用）。

        Args:
            name: 适配器名称（小写，如 "cai", "langchain", "generic"）

        Returns:
            适配器实例

        Raises:
            ValueError: 未找到对应名称的适配器
        """
        for adapter_cls in cls._adapters:
            instance = adapter_cls()
            if instance.adapter_name == name:
                return instance

        # 兜底：尝试从 adapters 子包懒加载（避免循环导入问题）
        _LAZY_MAP = {
            "cai": "src.layer0.adapters.cai.CaiAdapter",
            "langchain": "src.layer0.adapters.langchain.LangChainAdapter",
            "openai_assistant": "src.layer0.adapters.openai_assistant.OpenAIAssistantAdapter",
            "generic": "src.layer0.adapters.generic.GenericJsonlAdapter",
        }
        if name in _LAZY_MAP:
            import importlib  # noqa: PLC0415

            module_path, cls_name = _LAZY_MAP[name].rsplit(".", 1)
            module = importlib.import_module(module_path)
            return getattr(module, cls_name)()

        known = [a().adapter_name for a in cls._adapters]
        raise ValueError(
            f"Unknown adapter name: '{name}'. "
            f"Registered adapters: {known}. "
            f"Available via lazy-load: {list(_LAZY_MAP.keys())}"
        )

    @classmethod
    def list_adapters(cls) -> List[str]:
        """返回所有已注册适配器的名称列表。"""
        return [a().adapter_name for a in cls._adapters]

    @classmethod
    def clear(cls) -> None:
        """清空注册表（主要用于测试隔离）。"""
        cls._adapters.clear()
        logger.debug("AdapterRegistry cleared.")
