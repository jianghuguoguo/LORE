"""
RefPenTest 全局配置加载器
===========================
统一从 configs/config.yaml 加载配置，提供强类型化的配置访问接口。
支持环境变量覆盖（前缀 REFPENTEST_）以适应 CI/CD 环境。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ─────────────────────────────────────────────────────────────────────────────
# 默认配置（作为 config.yaml 的 fallback，保证零配置可运行）
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULTS: Dict[str, Any] = {
    "tool_categories": {
        "rag_tool_names": ["make_kb_search"],
        "code_execute_tool_names": ["execute_code"],
        "generic_command_tool_names": ["generic_linux_command"],
    },
    "rag_context": {
        "window_turns": 3,
    },
    "logging": {
        "log_dir": "../logs",
        "output_dir": "../data/processed",
        "log_glob": "cai_*.jsonl",
    },
    "parser": {
        "api_request_marker": "UNKNOWN",
        "completion_object_value": "chat.completion",
        "tool_result_content_type": "text_wrapper",
        "target_extraction": {
            "event_types": ["user_message"],
            "max_scan_lines": 10,
            "target_keywords": [
                "渗透测试目标", "target", "Target", "http://", "https://", "IP:", "ip:"
            ],
        },
    },
    "output": {
        "format": "jsonl",
        "include_raw_records": False,
        "flatten_events": False,
        "filename_template": "layer0_{session_id}.jsonl",
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """递归合并两个字典，override 优先"""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


class Config:
    """强类型配置访问器，封装 YAML 配置文件的读取与访问。"""

    def __init__(self, config_path: Optional[Path] = None):
        raw = dict(_DEFAULTS)

        # 加载 YAML 文件
        if config_path is None:
            # 默认搜索路径：项目根目录下的 configs/config.yaml
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "configs" / "config.yaml"

        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                file_cfg = yaml.safe_load(f) or {}
            raw = _deep_merge(raw, file_cfg)

        self._cfg = raw

    # ── tool_categories ──────────────────────────────────────────────────────

    @property
    def rag_tool_names(self) -> List[str]:
        return self._cfg["tool_categories"]["rag_tool_names"]

    @property
    def code_execute_tool_names(self) -> List[str]:
        return self._cfg["tool_categories"]["code_execute_tool_names"]

    @property
    def generic_command_tool_names(self) -> List[str]:
        return self._cfg["tool_categories"]["generic_command_tool_names"]

    # ── rag_context ───────────────────────────────────────────────────────────

    @property
    def rag_context_window_turns(self) -> int:
        return int(self._cfg["rag_context"]["window_turns"])

    # ── logging ───────────────────────────────────────────────────────────────

    @property
    def log_dir(self) -> Path:
        return Path(self._cfg["logging"]["log_dir"])

    @property
    def output_dir(self) -> Path:
        return Path(self._cfg["logging"]["output_dir"])

    @property
    def log_glob(self) -> str:
        return self._cfg["logging"]["log_glob"]

    # ── parser ────────────────────────────────────────────────────────────────

    @property
    def completion_object_value(self) -> str:
        return self._cfg["parser"]["completion_object_value"]

    @property
    def tool_result_content_type(self) -> str:
        return self._cfg["parser"]["tool_result_content_type"]

    @property
    def target_extraction_event_types(self) -> List[str]:
        return self._cfg["parser"]["target_extraction"]["event_types"]

    @property
    def target_extraction_max_scan_lines(self) -> int:
        return int(self._cfg["parser"]["target_extraction"]["max_scan_lines"])

    @property
    def target_extraction_keywords(self) -> List[str]:
        return self._cfg["parser"]["target_extraction"]["target_keywords"]

    # ── output ────────────────────────────────────────────────────────────────

    @property
    def include_raw_records(self) -> bool:
        return bool(self._cfg["output"]["include_raw_records"])

    @property
    def flatten_events(self) -> bool:
        return bool(self._cfg["output"]["flatten_events"])

    @property
    def output_filename_template(self) -> str:
        return self._cfg["output"]["filename_template"]

    # ── 辅助方法 ──────────────────────────────────────────────────────────────

    def classify_tool(self, tool_name: str) -> str:
        """根据 tool_name 返回 ActionCategory 的字符串值（无需导入 models）"""
        if tool_name in self.rag_tool_names:
            return "RAG_QUERY"
        if tool_name in self.code_execute_tool_names:
            return "CODE_WRITE"
        if tool_name in self.generic_command_tool_names:
            return "GENERIC_COMMAND_CALL"
        return "STRUCTURED_TOOL_CALL"


# 全局单例（延迟初始化）
_config_instance: Optional[Config] = None


def get_config(config_path: Optional[Path] = None) -> Config:
    """获取全局配置单例（线程安全性：单进程场景不需要 Lock）"""
    global _config_instance
    if _config_instance is None or config_path is not None:
        _config_instance = Config(config_path)
    return _config_instance
