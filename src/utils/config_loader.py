"""
LORE 全局配置加载器
===========================
统一配置分层加载策略：
- 设计配置：configs/design.yaml（项目规则、语义映射、默认行为）
- 用户配置：configs/config.yaml（LLM/RAGflow API 与知识库 ID 等必填项）

最终配置 = 代码内兜底默认值 + design.yaml + config.yaml + 环境变量覆盖。
支持关键运行时环境变量覆盖，以适应 CI/CD 与容器部署场景。
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


_DEFAULT_DESIGN_CONFIG_REL = Path("configs/design.yaml")
_DEFAULT_USER_CONFIG_REL = Path("configs/config.yaml")


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
    "llm": {
        "provider": "generic",
        "model": "deepseek-chat",
        "base_url": "https://api.deepseek.com",
        "api_key_env": "LLM_API_KEY",
        "api_key_literal": "",
        "temperature": 0.0,
        "max_tokens": 2048,
        "max_retries": 3,
        "retry_delay": 2.0,
        "timeout": 60,
    },
    "ragflow": {
        "base_url": "http://127.0.0.1:9380",
        "base_url_env": "RAGFLOW_BASE_URL",
        "api_key_env": "RAGFLOW_API_KEY",
        "api_key_literal": "",
        "request_timeout": 60,
        "retry_times": 2,
        "datasets": {
            "experience": "",
            "factual": "",
            "procedural_pos": "",
            "procedural_neg": "",
            "metacognitive": "",
            "full": "",
            "secondary": "",
        },
    },
    "layer3": {
        "sec_aliases_file": "configs/sec_aliases.json",
    },
    "layer4": {
        "enabled": True,
        "crawler": {
            "sources": ["csdn", "github", "xianzhi", "qianxin"],
            "max_pages": 3,
            "min_quality_score": 0.3,
            "max_docs_per_gap": 5,
        },
        "p0_immediate": True,
        "schedule": {
            "daily_hour": 2,
            "weekly_day": "mon",
            "weekly_hour": 3,
        },
        "queue": {
            "dir": "",
        },
        "reflux": {
            "secondary_dataset_id": "",
            "secondary_dataset_id_env": "RAGFLOW_SECONDARY_DATASET_ID",
        },
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


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _abs_path(project_root: Path, raw_path: str) -> Path:
    p = Path(raw_path)
    if p.is_absolute():
        return p
    return (project_root / p).resolve()


def _apply_env_overrides(raw: Dict[str, Any]) -> Dict[str, Any]:
    """将关键环境变量覆盖到配置对象。"""
    out = deepcopy(raw)

    ragflow = out.setdefault("ragflow", {})
    if not isinstance(ragflow, dict):
        ragflow = {}
        out["ragflow"] = ragflow
    datasets = ragflow.setdefault("datasets", {})
    if not isinstance(datasets, dict):
        datasets = {}
        ragflow["datasets"] = datasets

    base_url_env = _to_str(ragflow.get("base_url_env") or "RAGFLOW_BASE_URL")
    api_key_env = _to_str(ragflow.get("api_key_env") or "RAGFLOW_API_KEY")

    env_base_url = _to_str(os.environ.get(base_url_env, ""))
    if env_base_url:
        ragflow["base_url"] = env_base_url

    env_api_key = _to_str(os.environ.get(api_key_env, ""))
    if env_api_key:
        ragflow["api_key_literal"] = env_api_key

    layer4 = out.setdefault("layer4", {})
    if not isinstance(layer4, dict):
        layer4 = {}
        out["layer4"] = layer4

    queue_cfg = layer4.setdefault("queue", {})
    if not isinstance(queue_cfg, dict):
        queue_cfg = {}
        layer4["queue"] = queue_cfg

    queue_dir_env = _to_str(os.environ.get("LAYER4_QUEUE_DIR", ""))
    if queue_dir_env:
        queue_cfg["dir"] = queue_dir_env

    reflux_cfg = layer4.setdefault("reflux", {})
    if not isinstance(reflux_cfg, dict):
        reflux_cfg = {}
        layer4["reflux"] = reflux_cfg

    secondary_env_key = _to_str(
        reflux_cfg.get("secondary_dataset_id_env") or "RAGFLOW_SECONDARY_DATASET_ID"
    )
    secondary_dataset = _to_str(os.environ.get(secondary_env_key, ""))
    if secondary_dataset:
        reflux_cfg["secondary_dataset_id"] = secondary_dataset

    return out


def _load_yaml_mapping(path: Path) -> Dict[str, Any]:
    """读取 YAML 文件并确保顶层为字典；缺失文件返回空字典。"""
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"配置文件顶层必须是对象映射: {path}")
    return data


class Config:
    """强类型配置访问器，封装 YAML 配置文件的读取与访问。"""

    def __init__(self, config_path: Optional[Path] = None):
        raw = deepcopy(_DEFAULTS)
        self._project_root = Path(__file__).resolve().parent.parent.parent
        self._design_config_path = (self._project_root / _DEFAULT_DESIGN_CONFIG_REL).resolve()

        # 用户配置文件（可由调用方指定）
        if config_path is None:
            config_path = self._project_root / _DEFAULT_USER_CONFIG_REL

        self._config_path = Path(config_path).resolve()

        # 1) 先加载 design.yaml（项目设计层默认）
        raw = _deep_merge(raw, _load_yaml_mapping(self._design_config_path))

        # 2) 再加载 config.yaml（用户部署层覆盖）
        raw = _deep_merge(raw, _load_yaml_mapping(self._config_path))

        self._cfg = _apply_env_overrides(raw)

    @property
    def project_root(self) -> Path:
        return self._project_root

    @property
    def design_config_path(self) -> Path:
        return self._design_config_path

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def raw_dict(self) -> Dict[str, Any]:
        return deepcopy(self._cfg)

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

    # ── llm ───────────────────────────────────────────────────────────────────

    @property
    def llm_config(self) -> Dict[str, Any]:
        llm = self._cfg.get("llm", {})
        if not isinstance(llm, dict):
            return {}
        return deepcopy(llm)

    # ── ragflow ───────────────────────────────────────────────────────────────

    @property
    def ragflow_config(self) -> Dict[str, str]:
        ragflow = self._cfg.get("ragflow", {})
        datasets = ragflow.get("datasets", {}) if isinstance(ragflow, dict) else {}
        if not isinstance(datasets, dict):
            datasets = {}

        return {
            "base_url": _to_str(ragflow.get("base_url") if isinstance(ragflow, dict) else ""),
            "api_key": _to_str(ragflow.get("api_key_literal") if isinstance(ragflow, dict) else ""),
            "request_timeout": _to_str(ragflow.get("request_timeout") if isinstance(ragflow, dict) else 60),
            "retry_times": _to_str(ragflow.get("retry_times") if isinstance(ragflow, dict) else 2),
            "experience_dataset": _to_str(datasets.get("experience")),
            "dataset_factual": _to_str(datasets.get("factual")),
            "dataset_procedural_pos": _to_str(datasets.get("procedural_pos")),
            "dataset_procedural_neg": _to_str(datasets.get("procedural_neg")),
            "dataset_metacognitive": _to_str(datasets.get("metacognitive")),
            "full_dataset": _to_str(datasets.get("full")),
            "secondary_dataset": _to_str(datasets.get("secondary")),
        }

    # ── layer3 ────────────────────────────────────────────────────────────────

    @property
    def sec_aliases_path(self) -> Path:
        layer3 = self._cfg.get("layer3", {})
        raw_path = "configs/sec_aliases.json"
        if isinstance(layer3, dict):
            raw_path = _to_str(layer3.get("sec_aliases_file") or raw_path)
        return _abs_path(self.project_root, raw_path)

    # ── layer4 ────────────────────────────────────────────────────────────────

    @property
    def layer4_config(self) -> Dict[str, Any]:
        layer4 = self._cfg.get("layer4", {})
        if not isinstance(layer4, dict):
            return {}
        return deepcopy(layer4)

    @property
    def layer4_queue_dir(self) -> Path:
        layer4 = self._cfg.get("layer4", {})
        queue = layer4.get("queue", {}) if isinstance(layer4, dict) else {}
        raw_dir = _to_str(queue.get("dir")) if isinstance(queue, dict) else ""
        if raw_dir:
            return _abs_path(self.project_root, raw_dir)
        return self.project_root / "src" / "layer4" / "queues"

    @property
    def layer4_secondary_dataset_id(self) -> str:
        layer4 = self._cfg.get("layer4", {})
        reflux = layer4.get("reflux", {}) if isinstance(layer4, dict) else {}
        if not isinstance(reflux, dict):
            return ""
        return _to_str(reflux.get("secondary_dataset_id"))

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

