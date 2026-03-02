"""
log_adapter/adapters/__init__.py – 内置适配器注册入口
======================================================
按优先级顺序导入所有内置适配器，使其通过 @AdapterRegistry.register
装饰器完成自动注册。

注册顺序决定 auto_detect() 嗅探优先级：
  1. CaiAdapter             – 精准嗅探：event=session_start
  2. LangChainAdapter       – 精准嗅探：type in {agent_action, on_tool_start, …}
  3. OpenAIAssistantAdapter – 精准嗅探：object.startswith("thread.run.step")
  4. GenericJsonlAdapter    – 兜底：can_handle() 始终返回 True

⚠️  GenericJsonlAdapter 必须最后导入，确保兜底语义正确。
"""

from .cai import CaiAdapter
from .langchain import LangChainAdapter
from .openai_assistant import OpenAIAssistantAdapter
from .generic import GenericJsonlAdapter  # 兜底，must be last

__all__ = [
    "CaiAdapter",
    "LangChainAdapter",
    "OpenAIAssistantAdapter",
    "GenericJsonlAdapter",
]
