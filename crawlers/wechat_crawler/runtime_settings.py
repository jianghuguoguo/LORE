from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

_BASE = Path(__file__).resolve().parent
RUNTIME_CONFIG_PATH = _BASE / 'runtime_config.json'

DEFAULT_RUNTIME_SETTINGS: dict[str, Any] = {
    'default_mode': 'sogou',
    'sogou': {
        'proxy_mode': 'direct',
        'proxy_url': 'http://127.0.0.1:7890',
        'proxy_host': '127.0.0.1',
        'proxy_port': 7890,
        'search_delay_min': 1.8,
        'search_delay_max': 3.4,
        'antispider_wait_min': 45,
        'antispider_wait_max': 75,
    },
    'native': {
        'proxy_host': '127.0.0.1',
        'proxy_port': 8080,
        'scheduler_force': True,
    },
}


def merge_runtime_settings(base: Mapping[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    merged = deepcopy(dict(base))
    if not isinstance(override, Mapping):
        return merged

    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = merge_runtime_settings(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def load_runtime_settings(path: Path = RUNTIME_CONFIG_PATH) -> dict[str, Any]:
    if not path.exists():
        return deepcopy(DEFAULT_RUNTIME_SETTINGS)
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return deepcopy(DEFAULT_RUNTIME_SETTINGS)
    return merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS, data)


def save_runtime_settings(data: Mapping[str, Any], path: Path = RUNTIME_CONFIG_PATH) -> dict[str, Any]:
    merged = merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS, data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return merged


def get_sogou_settings(settings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    cfg = merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS, settings)
    sogou = cfg.get('sogou') or {}
    return merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS['sogou'], sogou)


def get_native_settings(settings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    cfg = merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS, settings)
    native = cfg.get('native') or {}
    return merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS['native'], native)


def _env_text(env: Mapping[str, str], name: str, fallback: str) -> str:
    value = env.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _env_float(env: Mapping[str, str], name: str, fallback: float) -> float:
    value = env.get(name)
    if value is None or str(value).strip() == '':
        return float(fallback)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)


def _env_int(env: Mapping[str, str], name: str, fallback: int) -> int:
    value = env.get(name)
    if value is None or str(value).strip() == '':
        return int(fallback)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def get_effective_sogou_settings(
    settings: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    runtime = get_sogou_settings(settings if settings is not None else load_runtime_settings())
    current_env = env or os.environ

    proxy_host = _env_text(current_env, 'LORE_PROXY_HOST', str(runtime.get('proxy_host', '127.0.0.1')))
    proxy_port = _env_int(current_env, 'LORE_PROXY_PORT', int(runtime.get('proxy_port', 7890)))
    proxy_url_default = str(runtime.get('proxy_url') or f'http://{proxy_host}:{proxy_port}')

    search_delay_min = _env_float(current_env, 'LORE_SOGOU_SEARCH_DELAY_MIN', float(runtime.get('search_delay_min', 1.8)))
    search_delay_max = _env_float(current_env, 'LORE_SOGOU_SEARCH_DELAY_MAX', float(runtime.get('search_delay_max', 3.4)))
    antispider_wait_min = _env_int(current_env, 'LORE_SOGOU_ANTISPIDER_WAIT_MIN', int(runtime.get('antispider_wait_min', 45)))
    antispider_wait_max = _env_int(current_env, 'LORE_SOGOU_ANTISPIDER_WAIT_MAX', int(runtime.get('antispider_wait_max', 75)))

    if search_delay_max < search_delay_min:
        search_delay_max = search_delay_min
    if antispider_wait_max < antispider_wait_min:
        antispider_wait_max = antispider_wait_min

    return {
        'proxy_mode': _env_text(current_env, 'LORE_SOGOU_PROXY_MODE', str(runtime.get('proxy_mode', 'direct'))).lower(),
        'proxy_url': _env_text(current_env, 'LORE_SOGOU_PROXY_URL', proxy_url_default),
        'proxy_host': proxy_host,
        'proxy_port': proxy_port,
        'search_delay_min': search_delay_min,
        'search_delay_max': search_delay_max,
        'antispider_wait_min': antispider_wait_min,
        'antispider_wait_max': antispider_wait_max,
    }


def build_sogou_env(
    base_env: Mapping[str, str] | None = None,
    settings: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    env = dict(base_env or os.environ)
    effective = get_effective_sogou_settings(settings=settings, env=env)
    env.setdefault('LORE_PROXY_HOST', str(effective['proxy_host']))
    env.setdefault('LORE_PROXY_PORT', str(effective['proxy_port']))
    env.setdefault('LORE_SOGOU_PROXY_MODE', str(effective['proxy_mode']))
    env.setdefault('LORE_SOGOU_PROXY_URL', str(effective['proxy_url']))
    env.setdefault('LORE_SOGOU_SEARCH_DELAY_MIN', str(effective['search_delay_min']))
    env.setdefault('LORE_SOGOU_SEARCH_DELAY_MAX', str(effective['search_delay_max']))
    env.setdefault('LORE_SOGOU_ANTISPIDER_WAIT_MIN', str(effective['antispider_wait_min']))
    env.setdefault('LORE_SOGOU_ANTISPIDER_WAIT_MAX', str(effective['antispider_wait_max']))
    return env