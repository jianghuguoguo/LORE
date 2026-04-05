"""
LORE 知识提炼系统 — Dashboard 后端
为经验库浏览、会话分析和流水线管理提供 RESTful API
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from crawlers.wechat_crawler.runtime_settings import (
    DEFAULT_RUNTIME_SETTINGS,
    RUNTIME_CONFIG_PATH,
    build_sogou_env,
    get_native_settings,
    load_runtime_settings,
    merge_runtime_settings,
    save_runtime_settings,
)
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# ── 路径配置 ─────────────────────────────────────────────────────────────────
ROOT_DIR    = Path(__file__).parent.parent          # LORE/
WORKSPACE   = ROOT_DIR.parent                       # 语料/ (含 .venv)
DATA_DIR    = ROOT_DIR / "data" / "layer2_output"
LAYER3_DIR  = ROOT_DIR / "data" / "layer3_output"
LOGS_DIR    = ROOT_DIR / "logs"
LORE_ROOT   = ROOT_DIR                              # 主入口就在 ROOT_DIR 内
PIPELINE_PY = ROOT_DIR / "run" / "run_layer2_analysis.py"


def _resolve_script_path(*candidates: Path) -> Path:
    """返回首个存在的路径，兼容目录迁移后的新旧位置。"""
    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate
        except OSError:
            continue
    return candidates[0]


CRAWLER_PY  = _resolve_script_path(
    ROOT_DIR / "crawlers" / "main_crawler.py",
    ROOT_DIR / "main_crawler.py",
)
SYNC_PY     = _resolve_script_path(
    ROOT_DIR / "crawlers" / "sync_data_light.py",
    ROOT_DIR / "scripts" / "sync_data_light.py",
)
RAW_DATA_DIR = _resolve_script_path(
    WORKSPACE / "raw_data",
    ROOT_DIR / "raw_data",
)


def _resolve_python_exe() -> Path:
    """解析可用的 Python 解释器路径，避免硬编码路径导致 WinError 2。"""
    candidates = []

    if sys.executable:
        candidates.append(Path(sys.executable))

    candidates.extend([
        ROOT_DIR / ".venv" / "Scripts" / "python.exe",
        WORKSPACE / ".venv" / "Scripts" / "python.exe",
    ])

    for p in candidates:
        try:
            if p and p.exists():
                return p
        except OSError:
            continue

    # 最后回退到当前解释器字符串，保留可执行机会（如 conda/pipenv）。
    return Path(sys.executable or "python")


PYTHON_EXE  = _resolve_python_exe()
# ── Layer 1-3 脚本路径 ────────────────────────────────────────────────────────
LAYER1_PY       = ROOT_DIR / "run" / "run_layer1_llm_batch.py"
LAYER3_P12_PY   = ROOT_DIR / "run" / "run_layer3_phase12.py"
LAYER3_P34_PY   = ROOT_DIR / "run" / "run_layer3_phase34.py"
LAYER3_P5_PY    = ROOT_DIR / "run" / "run_layer3_phase5.py"

# ── Lore 全链路流水线配置 ─────────────────────────────────────────────────────
LORE_PY         = ROOT_DIR / "lore.py"
LORE_STATE_FILE = ROOT_DIR / "data" / ".pipeline_state.json"
LORE_LOG_FILE   = ROOT_DIR / "data" / ".pipeline_live.log"
LORE_STAGE_DEFINITIONS = [
    ("layer0",    "Layer 0  日志标准化",               ROOT_DIR / "run" / "run_layer0.py"),
    ("layer1",    "Layer 1  LLM 会话标注",             ROOT_DIR / "run" / "run_layer1_llm_batch.py"),
    ("layer2",    "Layer 2  经验蒸馏",                 ROOT_DIR / "run" / "run_layer2_analysis.py"),
    ("layer3_p12","Layer 3  Phase 1+2  SEC/EWC",       ROOT_DIR / "run" / "run_layer3_phase12.py"),
    ("layer3_p34","Layer 3  Phase 3+4  RME/BCC",       ROOT_DIR / "run" / "run_layer3_phase34.py"),
    ("layer3_p5", "Layer 3  Phase 5    KLM",            ROOT_DIR / "run" / "run_layer3_phase5.py"),
    ("layer4",    "Layer 4  缺口感知 + 冲突检测",      ROOT_DIR / "run" / "run_layer4_gap_dispatch.py"),
    ("upload",    "Upload   上传 Layer3 融合经验到 RAGflow", None),
]

# ── 微信专属路径 ──────────────────────────────────────────────────────────────
WECHAT_SOGOU_PY     = ROOT_DIR / "crawlers" / "wechat_crawler" / "sogou_crawler.py"
WECHAT_SCHEDULER_PY = ROOT_DIR / "crawlers" / "wechat_crawler" / "scheduler.py"
WECHAT_INTERCEPTOR  = ROOT_DIR / "crawlers" / "wechat_crawler" / "interceptor.py"
WECHAT_MITM_LOG     = LOGS_DIR / "wechat_mitmdump.log"
SEED_YAML           = ROOT_DIR / "crawlers" / "wechat_crawler" / "seed_accounts.yaml"
WECHAT_RAW_DIR      = RAW_DATA_DIR / "wechat"
WECHAT_RUNTIME_CFG  = RUNTIME_CONFIG_PATH

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# ── 流水线状态 ────────────────────────────────────────────────────────────────
pipeline_state: Dict = {
    "running":     False,
    "last_run":    None,
    "last_output": "",
    "last_error":  "",
}
_pipeline_thread: Optional[threading.Thread] = None

# ── 爬虫任务状态 ──────────────────────────────────────────────────────────────
crawler_state: Dict = {
    "running":     False,
    "last_run":    None,
    "last_output": "",
    "last_error":  "",
    "last_query":  "",
    "last_sources": [],
}
_crawler_thread: Optional[threading.Thread] = None

# ── 微信爬虫状态 ──────────────────────────────────────────────────────────────
wechat_crawler_state: Dict = {
    "running":     False,
    "last_run":    None,
    "last_output": "",
    "last_error":  "",
    "last_accounts": [],
    "last_mode":   "sogou",
    "last_days":   None,
}
_wechat_crawler_thread: Optional[threading.Thread] = None
_wechat_mitm_process = None
_wechat_mitm_log_handle = None
_wechat_proxy_backup: Optional[Dict] = None

# ── 缺口爬虫状态 ─────────────────────────────────────────────────────────────
gap_crawler_state: Dict = {
    "running":     False,
    "last_run":    None,
    "last_output": "",
    "last_error":  "",
    "last_query":  "",
}
_gap_crawler_thread: Optional[threading.Thread] = None

# ── 全链路流水线状态 ─────────────────────────────────────────────────────────
full_pipeline_state: Dict = {
    "running":     False,
    "last_run":    None,
    "last_output": "",
    "last_error":  "",
    "current_step": "",
}
_full_pipeline_thread: Optional[threading.Thread] = None

# ── Lore 分阶段流水线状态（由 /api/pipeline/lore/* 管理）───────────────────
lore_pipeline_state: Dict = {
    "running":      False,
    "last_run":     None,
    "current_step": "",
    "last_error":   "",
}
_lore_pipeline_thread: Optional[threading.Thread] = None

# ── 已知数据源 ─────────────────────────────────────────────────────────────────
# ALL_SOURCES 保留 wechat 仅供 rawdata 分组；网站爬虫源单独列出
ALL_SOURCES = ["csdn", "github", "qianxin", "xianzhi", "wechat"]
WEB_SOURCES  = ["csdn", "github", "qianxin", "xianzhi"]   # 网站爬虫（不含微信）
SOURCE_LABELS = {
    "csdn":     "CSDN",
    "github":   "GitHub",
    "qianxin":  "奇安信攻防社区",
    "xianzhi":  "先知社区",
    "wechat":   "微信公众号",
}
# ── 外部知识库同步目录 ─────────────────────────────────────
ALL_REPOS: List[Dict] = [
    {"id": "attack",          "label": "MITRE ATT&CK",         "desc": "ATT&CK 威胁矩阵 (Enterprise/ICS/Mobile STIX)", "local_dir": "attack-database"},
    {"id": "cisa-kev",        "label": "CISA KEV",             "desc": "已知利用漏洞目录",         "local_dir": "cisa-kev-database"},
    {"id": "cwe",             "label": "MITRE CWE",            "desc": "CWE 常见弱点列表",         "local_dir": "cwe-database"},
    {"id": "capec",           "label": "MITRE CAPEC",          "desc": "CAPEC 攻击模式库",           "local_dir": "capec-database"},
    {"id": "d3fend",          "label": "MITRE D3FEND",         "desc": "D3FEND 防御知识图谱",         "local_dir": "d3fend-database"},
    {"id": "github-advisory", "label": "GitHub Advisory",      "desc": "GitHub 安全公告数据库",       "local_dir": "github-advisory-database"},
    {"id": "zdi",             "label": "ZDI Advisories",       "desc": "Zero Day Initiative 公告",     "local_dir": "zdi-advisory-database"},
    {"id": "cve",             "label": "CVE List (cvelistV5)", "desc": "CVE 官方列表（体积较大）",   "local_dir": "cve-database"},
    {"id": "nvd",             "label": "NVD JSON Feeds",       "desc": "NVD 种漏洞数据 (fkie-cad)",  "local_dir": "nvd-database"},
    {"id": "exploit-db",      "label": "Exploit-DB",           "desc": "Exploit-DB 漏洞利用代码库",    "local_dir": "exploit-db-database"},
    {"id": "linux-vulns",     "label": "Linux Kernel Vulns",  "desc": "Linux 内核安全漏洞列表",   "local_dir": "linux-vulns-database"},
]

# 确保所有知识库同步目录在 Dashboard 启动时预先存在（目录存在 ≠ 已同步，只影响 _repo_dir_stats 的 exists 字段）
for _repo_def in ALL_REPOS:
    (RAW_DATA_DIR / _repo_def["local_dir"]).mkdir(exist_ok=True, parents=True)

# ── 同步任务状态 ─────────────────────────────────────────────
sync_state: Dict = {
    "running":      False,
    "last_run":     None,
    "last_output":  "",
    "last_error":   "",
    "last_repos":   [],
}
_sync_thread: Optional[threading.Thread] = None


def _resolve_mitmdump_exe() -> Optional[Path]:
    candidates = [
        PYTHON_EXE.with_name("mitmdump.exe"),
        ROOT_DIR / ".venv" / "Scripts" / "mitmdump.exe",
        WORKSPACE / ".venv" / "Scripts" / "mitmdump.exe",
    ]
    which_hit = shutil.which("mitmdump")
    if which_hit:
        candidates.append(Path(which_hit))
    for candidate in candidates:
        try:
            if candidate and candidate.exists():
                return candidate
        except OSError:
            continue
    return None


def _is_process_running(image_name: str) -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except Exception:
        return False
    text = f"{result.stdout}\n{result.stderr}".lower()
    return image_name.lower() in text


def _is_wechat_running() -> bool:
    return _is_process_running("Weixin.exe") or _is_process_running("WeChat.exe")


def _cleanup_mitmdump_process() -> None:
    global _wechat_mitm_process, _wechat_mitm_log_handle
    if _wechat_mitm_process is not None and _wechat_mitm_process.poll() is not None:
        _wechat_mitm_process = None
        if _wechat_mitm_log_handle is not None:
            try:
                _wechat_mitm_log_handle.close()
            except Exception:
                pass
            _wechat_mitm_log_handle = None


def _is_mitmdump_running() -> bool:
    _cleanup_mitmdump_process()
    if _wechat_mitm_process is not None:
        return _wechat_mitm_process.poll() is None
    return _is_process_running("mitmdump.exe")


def _tail_text_file(path: Path, limit: int = 4000) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except Exception:
        return ""


def _get_windows_proxy_state() -> Dict:
    result = {
        "supported": os.name == "nt",
        "enabled": False,
        "server": "",
        "error": "",
    }
    if os.name != "nt":
        return result
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            result["enabled"] = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
            result["server"] = str(winreg.QueryValueEx(key, "ProxyServer")[0] or "")
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _refresh_windows_proxy() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def _set_windows_proxy(host: str, port: int) -> Dict:
    if os.name != "nt":
        raise RuntimeError("当前系统不支持 Windows 系统代理控制")

    import winreg

    snapshot = _get_windows_proxy_state()
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{int(port)}")
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    _refresh_windows_proxy()
    return snapshot


def _restore_windows_proxy(snapshot: Optional[Dict]) -> None:
    if os.name != "nt":
        raise RuntimeError("当前系统不支持 Windows 系统代理控制")

    import winreg

    previous = snapshot or {"enabled": False, "server": ""}
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(previous.get("server") or ""))
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if previous.get("enabled") else 0)
    _refresh_windows_proxy()


def _proxy_matches_target(server: str, host: str, port: int) -> bool:
    expected = f"{host}:{int(port)}".lower()
    for part in str(server or "").lower().split(";"):
        token = part.split("=", 1)[-1].strip()
        if token == expected:
            return True
    return False


def _get_wechat_runtime_config() -> Dict:
    return merge_runtime_settings(DEFAULT_RUNTIME_SETTINGS, load_runtime_settings(WECHAT_RUNTIME_CFG))


def _normalize_runtime_config(body: Dict) -> Dict:
    merged = merge_runtime_settings(_get_wechat_runtime_config(), body)
    merged["default_mode"] = str(merged.get("default_mode") or "sogou").strip().lower()
    if merged["default_mode"] not in {"sogou", "native"}:
        merged["default_mode"] = "sogou"

    sogou = merged.setdefault("sogou", {})
    sogou["proxy_mode"] = str(sogou.get("proxy_mode") or "direct").strip().lower()
    if sogou["proxy_mode"] not in {"direct", "auto", "proxy"}:
        sogou["proxy_mode"] = "direct"
    sogou["proxy_url"] = str(sogou.get("proxy_url") or "http://127.0.0.1:7890").strip()
    sogou["proxy_host"] = str(sogou.get("proxy_host") or "127.0.0.1").strip() or "127.0.0.1"
    sogou["proxy_port"] = int(sogou.get("proxy_port") or 7890)
    sogou["search_delay_min"] = max(0.2, float(sogou.get("search_delay_min") or 1.8))
    sogou["search_delay_max"] = max(sogou["search_delay_min"], float(sogou.get("search_delay_max") or 3.4))
    sogou["antispider_wait_min"] = max(5, int(sogou.get("antispider_wait_min") or 45))
    sogou["antispider_wait_max"] = max(sogou["antispider_wait_min"], int(sogou.get("antispider_wait_max") or 75))

    native = merged.setdefault("native", {})
    native["proxy_host"] = str(native.get("proxy_host") or "127.0.0.1").strip() or "127.0.0.1"
    native["proxy_port"] = int(native.get("proxy_port") or 8080)
    native["scheduler_force"] = bool(native.get("scheduler_force", True))
    return merged


def _collect_native_preflight(cfg: Dict) -> List[str]:
    native = get_native_settings(cfg)
    proxy = _get_windows_proxy_state()
    issues: List[str] = []
    if not _is_mitmdump_running():
        issues.append("mitmdump 未启动")
    if not proxy.get("enabled") or not _proxy_matches_target(proxy.get("server", ""), native["proxy_host"], native["proxy_port"]):
        issues.append(f"系统代理未指向 {native['proxy_host']}:{native['proxy_port']}")
    if not _is_wechat_running():
        issues.append("未检测到已登录的 PC 微信进程")
    return issues


def _start_mitmdump_process() -> tuple[bool, str]:
    """启动 mitmdump；如果已在运行则直接返回成功。"""
    global _wechat_mitm_process, _wechat_mitm_log_handle

    _cleanup_mitmdump_process()
    if _is_mitmdump_running():
        return True, "mitmdump 已在运行"

    mitmdump_exe = _resolve_mitmdump_exe()
    if not mitmdump_exe:
        return False, "未找到 mitmdump.exe"

    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    if _wechat_mitm_log_handle is not None:
        try:
            _wechat_mitm_log_handle.close()
        except Exception:
            pass
        _wechat_mitm_log_handle = None

    try:
        _wechat_mitm_log_handle = open(WECHAT_MITM_LOG, "a", encoding="utf-8")
        _wechat_mitm_process = subprocess.Popen(
            [str(mitmdump_exe), "-s", str(WECHAT_INTERCEPTOR)],
            cwd=str(ROOT_DIR),
            stdout=_wechat_mitm_log_handle,
            stderr=_wechat_mitm_log_handle,
            text=True,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        return True, "mitmdump 已启动"
    except Exception as exc:
        if _wechat_mitm_log_handle is not None:
            try:
                _wechat_mitm_log_handle.close()
            except Exception:
                pass
            _wechat_mitm_log_handle = None
        _wechat_mitm_process = None
        return False, f"启动 mitmdump 失败: {exc}"


def _ensure_native_runtime_ready(cfg: Dict) -> List[str]:
    """自动准备原生微信轨运行条件，并返回仍未满足的项。"""
    global _wechat_proxy_backup

    native = get_native_settings(cfg)
    issues: List[str] = []

    mitm_ok, mitm_msg = _start_mitmdump_process()
    if not mitm_ok:
        issues.append(mitm_msg)

    proxy = _get_windows_proxy_state()
    proxy_ready = bool(
        proxy.get("enabled")
        and _proxy_matches_target(proxy.get("server", ""), native["proxy_host"], native["proxy_port"])
    )
    if not proxy_ready:
        try:
            if _wechat_proxy_backup is None:
                _wechat_proxy_backup = _set_windows_proxy(native["proxy_host"], native["proxy_port"])
            else:
                _set_windows_proxy(native["proxy_host"], native["proxy_port"])
        except Exception as exc:
            issues.append(f"系统代理自动设置失败: {exc}")

    for item in _collect_native_preflight(cfg):
        if item not in issues:
            issues.append(item)

    return issues

# ══════════════════════════════ 数据读取工具 ══════════════════════════════════

def _load_jsonl(path: Path) -> List[Dict]:
    """安全逐行读取 JSONL 文件，跳过损坏行。"""
    if not path.exists():
        return []
    result = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    result.append(json.loads(line))
                except Exception:
                    pass
    return result


def load_all_experiences() -> List[Dict]:
    return _load_jsonl(DATA_DIR / "experience_raw.jsonl")


def _sanitize_experience_for_ui(exp: Dict) -> Dict:
    """移除 UI 不再展示的历史字段，避免元认知层出现 RAG 效用评价。"""
    if not isinstance(exp, dict):
        return exp

    normalized = dict(exp)
    layer = normalized.get("knowledge_layer")
    content = normalized.get("content")

    if layer == "METACOGNITIVE" and isinstance(content, dict):
        cleaned = dict(content)
        cleaned.pop("rag_effectiveness", None)
        cleaned.pop("rag_adoption_stats", None)
        cleaned.pop("rag_utility", None)
        normalized["content"] = cleaned

    return normalized


def load_sessions() -> List[Dict]:
    """扫描 per-session 子目录，返回会话摘要列表。"""
    sessions = []
    if not DATA_DIR.exists():
        return sessions
    for p in sorted(DATA_DIR.iterdir()):
        if not p.is_dir():
            continue
        exps = _load_jsonl(p / "experiences.jsonl")
        if not exps:
            continue
        meta = exps[0].get("metadata", {})
        ac   = meta.get("applicable_constraints", {}) or {}
        sessions.append({
            "session_id":       p.name,
            "session_id_short": p.name[:8],
            "outcome":          meta.get("session_outcome", "unknown"),
            "bar_score":        meta.get("session_bar_score", 0.0),
            "target_service":   ac.get("target_service") or meta.get("target_raw", "")[:40],
            "cve_ids":          ac.get("cve_ids", []),
            "created_at":       meta.get("created_at", ""),
            "exp_count":        len(exps),
            "layer_counts":     dict(Counter(e.get("knowledge_layer", "") for e in exps)),
        })
    sessions.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return sessions


# ══════════════════════════════ API 路由 ══════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """总览统计：分层计数 / 会话结果 / 置信度分布 / 服务分布 / 攻击阶段分布。"""
    exps     = load_all_experiences()
    sessions = load_sessions()

    layer_counts   = dict(Counter(e.get("knowledge_layer", "UNKNOWN") for e in exps))
    outcome_counts = dict(Counter(s.get("outcome", "unknown") for s in sessions))

    conf_dist: Dict[str, int] = defaultdict(int)
    for e in exps:
        bucket = str(round(float(e.get("confidence", 0)), 1))
        conf_dist[bucket] += 1

    svc_cnt: Counter = Counter()
    for e in exps:
        svc = (
            (e.get("metadata", {}).get("applicable_constraints") or {}).get("target_service")
            or e.get("content", {}).get("target_service", "")
        )
        if svc:
            svc_cnt[svc] += 1

    phase_cnt: Counter = Counter()
    for e in exps:
        phase = e.get("content", {}).get("attack_phase", "")
        if phase:
            phase_cnt[phase] += 1

    src_cnt: Counter = Counter()
    for e in exps:
        src = e.get("metadata", {}).get("extraction_source", "unknown")
        src_cnt[src] += 1

    return jsonify({
        "success":           True,
        "total_experiences": len(exps),
        "total_sessions":    len(sessions),
        "layer_counts":      layer_counts,
        "outcome_counts":    outcome_counts,
        "confidence_dist":   dict(sorted(conf_dist.items())),
        "service_dist":      dict(svc_cnt.most_common(8)),
        "phase_dist":        dict(phase_cnt.most_common(8)),
        "source_dist":       dict(src_cnt),
    })


@app.route("/api/experiences")
def api_experiences():
    """
    分页获取经验列表。

    Query params:
      layer    — knowledge_layer 过滤（逗号分隔支持多选）
      session  — session_id 前缀过滤
      search   — 全文模糊搜索（tags + content JSON）
      page     — 页码（默认 1）
      size     — 每页条数（默认 24）
    """
    layer   = request.args.get("layer", "")
    session = request.args.get("session", "")
    search  = request.args.get("search", "").strip().lower()
    page    = request.args.get("page", 1, type=int)
    size    = request.args.get("size", 24, type=int)

    exps = load_all_experiences()

    if layer:
        layers = {l.strip() for l in layer.split(",") if l.strip()}
        exps = [e for e in exps if e.get("knowledge_layer") in layers]

    if session:
        exps = [e for e in exps
                if e.get("metadata", {}).get("source_session_id", "").startswith(session)]

    if search:
        def _hit(e: Dict) -> bool:
            tags = " ".join(e.get("metadata", {}).get("tags", []))
            body = json.dumps(e.get("content", {}), ensure_ascii=False)
            return search in tags.lower() or search in body.lower()
        exps = [e for e in exps if _hit(e)]

    total     = len(exps)
    page_data = exps[(page - 1) * size: page * size]
    page_data = [_sanitize_experience_for_ui(e) for e in page_data]

    return jsonify({
        "success":     True,
        "total":       total,
        "page":        page,
        "size":        size,
        "experiences": page_data,
    })


@app.route("/api/experiences/<exp_id>")
def api_experience_detail(exp_id: str):
    for e in load_all_experiences():
        if e.get("exp_id") == exp_id:
            return jsonify({"success": True, "experience": _sanitize_experience_for_ui(e)})
    return jsonify({"success": False, "message": "Not found"}), 404


@app.route("/api/sessions")
def api_sessions():
    return jsonify({"success": True, "sessions": load_sessions()})


@app.route("/api/pipeline/status")
def api_pipeline_status():
    return jsonify({"success": True, **pipeline_state})


@app.route("/api/pipeline/run", methods=["POST"])
def api_pipeline_run():
    """清空旧数据并重新运行 Layer 2 分析流水线。"""
    global _pipeline_thread

    if pipeline_state["running"]:
        return jsonify({"success": False, "message": "流水线正在运行中，请稍候"})

    if not PIPELINE_PY.exists():
        return jsonify({"success": False, "message": f"未找到入口脚本: {PIPELINE_PY}"})

    def _run():
        pipeline_state["running"]     = True
        pipeline_state["last_output"] = ""
        pipeline_state["last_error"]  = ""
        try:
            if DATA_DIR.exists():
                for item in DATA_DIR.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item)
                    elif item.suffix == ".jsonl":
                        item.unlink(missing_ok=True)

            result = subprocess.run(
                [str(PYTHON_EXE), str(PIPELINE_PY)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(LORE_ROOT),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=600,
            )
            pipeline_state["last_output"] = (result.stdout or "")[-5000:]
            pipeline_state["last_error"]  = (result.stderr or "")[-2000:]
            pipeline_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            pipeline_state["last_error"] = "Pipeline 超时 (>600s)"
        except Exception as exc:
            pipeline_state["last_error"] = str(exc)
        finally:
            pipeline_state["running"] = False

    _pipeline_thread = threading.Thread(target=_run, daemon=True)
    _pipeline_thread.start()
    return jsonify({"success": True, "message": "流水线已启动，正在处理..."})


# ══════════════════════════════ 爬虫管理 API ══════════════════════════════════

def _count_raw_data_files() -> Dict[str, int]:
    """统计 raw_data 目录下各数据源的文件数。"""
    counts: Dict[str, int] = {s: 0 for s in ALL_SOURCES}
    if not RAW_DATA_DIR.exists():
        return counts
    for subdir in RAW_DATA_DIR.iterdir():
        if subdir.is_dir() and subdir.name in counts:
            counts[subdir.name] = len(list(subdir.glob("*.json"))) + len(list(subdir.glob("*.jsonl")))
    # 兼容平铺文件命名（source_timestamp.json）
    for f in RAW_DATA_DIR.glob("*.json"):
        for src in ALL_SOURCES:
            if src in f.name:
                counts[src] += 1
                break
    return counts


@app.route("/api/crawler/sources")
def api_crawler_sources():
    """返回各网站爬虫数据源状态与 raw_data 文件统计（不含微信，微信由 /api/wechat/* 管理）。"""
    counts = _count_raw_data_files()

    sources = []
    for src in WEB_SOURCES:   # 只暴露网站来源，不含 wechat
        entry: Dict = {
            "id":           src,
            "label":        SOURCE_LABELS.get(src, src),
            "file_count":   counts.get(src, 0),
            "needs_config": False,
            "configured":   True,
        }
        sources.append(entry)
    return jsonify({
        "success":      True,
        "sources":      sources,
        "rawdata_root": str(RAW_DATA_DIR),
    })


@app.route("/api/crawler/run", methods=["POST"])
def api_crawler_run():
    """异步启动爬虫任务。
    Body JSON: { query: str, sources: [str], max_pages: int }
    """
    global _crawler_thread

    if crawler_state["running"]:
        return jsonify({"success": False, "message": "爬虫正在运行中，请稍候"})

    body = request.get_json(silent=True) or {}
    query    = str(body.get("query", "")).strip()
    sources  = body.get("sources", WEB_SOURCES)
    try:
        max_pages = max(1, min(50, int(body.get("max_pages", 5))))
    except (TypeError, ValueError):
        max_pages = 5

    if not sources:
        return jsonify({"success": False, "message": "请至少选择一个数据源"})

    valid_sources = [s for s in sources if s in WEB_SOURCES]
    if not valid_sources:
        return jsonify({"success": False, "message": "数据源不合法"})

    def _run():
        crawler_state["running"]      = True
        crawler_state["last_output"]  = ""
        crawler_state["last_error"]   = ""
        crawler_state["last_query"]   = query
        crawler_state["last_sources"] = valid_sources
        try:
            cmd = [
                str(PYTHON_EXE), str(CRAWLER_PY),
                "--sources", ",".join(valid_sources),
                "--max-pages", str(max_pages),
                "-q", query,
                "-o", str(RAW_DATA_DIR),   # 📁 输出到 raw_data/，与 rawdata 管理一致
                "-y",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(ROOT_DIR),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=1800,
            )
            crawler_state["last_output"] = (result.stdout or "")[-8000:]
            crawler_state["last_error"]  = (result.stderr or "")[-3000:]
            if result.returncode != 0 and not crawler_state["last_error"]:
                crawler_state["last_error"] = f"爬虫进程异常退出，退出码={result.returncode}"
            crawler_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            crawler_state["last_error"] = "爬虫超时 (>1800s)"
        except Exception as exc:
            crawler_state["last_error"] = str(exc)
        finally:
            crawler_state["running"] = False

    _crawler_thread = threading.Thread(target=_run, daemon=True)
    _crawler_thread.start()
    return jsonify({
        "success":  True,
        "message":  f"爬虫已启动 — 数据源: {', '.join(valid_sources)}，关键词: {query or '(全量)'}",
    })


@app.route("/api/crawler/status")
def api_crawler_status():
    return jsonify({"success": True, **crawler_state})


@app.route("/api/crawler/rawdata")
def api_crawler_rawdata():
    """列出 raw_data 目录下所有文件（按数据源分组）。
    同时返回外部知识库同步目录的摘要统计（不枚举单文件，防止列表过大）。
    """
    # ── 爬虫数据源（逐文件列举） ────────────────────────────────────────────
    # 跳过已属于同步知识库的子目录，避免重复计入
    sync_dirs = {repo["local_dir"] for repo in ALL_REPOS}

    groups: Dict[str, List] = {s: [] for s in ALL_SOURCES}
    other: List = []

    if RAW_DATA_DIR.exists():
        for fp in sorted(RAW_DATA_DIR.rglob("*.json")):
            # 排除同步知识库子目录内的文件
            rel = fp.relative_to(RAW_DATA_DIR)
            if rel.parts and rel.parts[0] in sync_dirs:
                continue
            src = next((s for s in ALL_SOURCES if s in fp.parts or s in fp.name), None)
            entry = {
                "path":  str(rel).replace("\\", "/"),
                "size":  fp.stat().st_size,
                "mtime": datetime.fromtimestamp(fp.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            }
            if src:
                groups[src].append(entry)
            else:
                other.append(entry)

    # ── 外部知识库同步目录（只返回摘要，不枚举单文件） ───────────────────────
    sync_summaries = []
    for repo in ALL_REPOS:
        stats = _repo_dir_stats(repo["local_dir"])
        if stats["exists"] and stats["file_count"] > 0:
            sync_summaries.append({
                "id":        repo["id"],
                "label":     repo["label"],
                "desc":      repo["desc"],
                "local_dir": repo["local_dir"],
                **stats,
            })

    crawl_file_count = sum(len(v) for v in groups.values()) + len(other)
    sync_file_count  = sum(s["file_count"] for s in sync_summaries)
    total_files = crawl_file_count + sync_file_count

    return jsonify({
        "success":        True,
        "groups":         groups,
        "other":          other,
        "sync_summaries": sync_summaries,
        "total_files":    total_files,
    })


@app.route("/api/crawler/rawdata/delete", methods=["POST"])
def api_crawler_rawdata_delete():
    """删除原始数据文件。
    Body JSON: { source: str }  -- 删除指定数据源所有文件
               { all: true }    -- 清空全部 raw_data
               { path: str }    -- 删除单个文件
    """
    body = request.get_json(silent=True) or {}
    deleted = 0

    if body.get("all"):
        if RAW_DATA_DIR.exists():
            for fp in RAW_DATA_DIR.rglob("*.json"):
                fp.unlink(missing_ok=True)
                deleted += 1
        return jsonify({"success": True, "deleted": deleted, "message": f"已清空全部原始数据（{deleted} 个文件）"})

    src = body.get("source", "")
    if src and src in ALL_SOURCES:
        # 子目录
        sub = RAW_DATA_DIR / src
        if sub.exists():
            for fp in sub.rglob("*.json"):
                fp.unlink(missing_ok=True)
                deleted += 1
        # 平铺文件
        if RAW_DATA_DIR.exists():
            for fp in RAW_DATA_DIR.glob(f"*{src}*.json"):
                fp.unlink(missing_ok=True)
                deleted += 1
        return jsonify({"success": True, "deleted": deleted, "message": f"已清理 {src} 的原始数据（{deleted} 个文件）"})

    path = body.get("path", "")
    if path:
        target = RAW_DATA_DIR / path
        if target.exists() and target.is_file():
            target.unlink()
            return jsonify({"success": True, "deleted": 1})
        return jsonify({"success": False, "message": "文件不存在"})

    return jsonify({"success": False, "message": "请提供删除参数"})


# ══════════════════════════════ 外部知识库同步 API ════════════════════════════

def _repo_dir_stats(local_dir: str, max_depth: int = 3, max_files: int = 50000) -> Dict:
    """统计某个本地知识库目录的文件情况（限制深度与数量，防止大目录阻塞）。"""
    path = RAW_DATA_DIR / local_dir
    if not path.exists():
        return {"exists": False, "file_count": 0, "size_kb": 0, "mtime": None}
    try:
        file_count = 0
        total_size = 0
        latest_mt: Optional[float] = None
        truncated = False

        def _walk(cur: Path, depth: int) -> None:
            nonlocal file_count, total_size, latest_mt, truncated
            if truncated or depth > max_depth:
                return
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        if truncated:
                            break
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if entry.is_file(follow_symlinks=False):
                            file_count += 1
                            total_size += st.st_size
                            if latest_mt is None or st.st_mtime > latest_mt:
                                latest_mt = st.st_mtime
                            if file_count >= max_files:
                                truncated = True
                        elif entry.is_dir(follow_symlinks=False):
                            _walk(Path(entry.path), depth + 1)
            except PermissionError:
                pass

        _walk(path, 0)
        mtime_str = datetime.fromtimestamp(latest_mt).strftime("%Y-%m-%d %H:%M") if latest_mt else None
        return {
            "exists":     True,
            "file_count": file_count,
            "size_kb":    round(total_size / 1024, 1),
            "mtime":      mtime_str,
            "truncated":  truncated,
        }
    except Exception:
        return {"exists": True, "file_count": 0, "size_kb": 0, "mtime": None, "truncated": False}


@app.route("/api/sync/repos")
def api_sync_repos():
    """返回所有外部知识库的定义和本地同步状态。"""
    result = []
    for repo in ALL_REPOS:
        stats = _repo_dir_stats(repo["local_dir"])
        result.append({**repo, **stats})
    return jsonify({"success": True, "repos": result})


@app.route("/api/sync/run", methods=["POST"])
def api_sync_run():
    """异步启动知识库同步。
    Body JSON: { repos: [str] }  -- 要同步的仓库 ID 列表，空表示全部
    """
    global _sync_thread

    if sync_state["running"]:
        return jsonify({"success": False, "message": "同步任务正在运行中，请稍候"})

    if not SYNC_PY.exists():
        return jsonify({"success": False, "message": f"未找到同步脚本: {SYNC_PY}"})

    body      = request.get_json(silent=True) or {}
    wanted    = body.get("repos", [])
    valid_ids = [r["id"] for r in ALL_REPOS]
    repos     = [r for r in wanted if r in valid_ids] if wanted else []

    def _run():
        sync_state["running"]     = True
        sync_state["last_output"] = ""
        sync_state["last_error"]  = ""
        sync_state["last_repos"]  = repos or valid_ids
        try:
            cmd = [str(PYTHON_EXE), str(SYNC_PY)]
            if repos:
                cmd += ["--repos", ",".join(repos)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(WORKSPACE),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=1800,
            )
            sync_state["last_output"] = (result.stdout or "")[-10000:]
            sync_state["last_error"]  = (result.stderr or "")[-3000:]
            sync_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            sync_state["last_error"] = "同步超时 (>1800s)"
        except Exception as exc:
            sync_state["last_error"] = str(exc)
        finally:
            sync_state["running"] = False

    _sync_thread = threading.Thread(target=_run, daemon=True)
    _sync_thread.start()
    label = ", ".join(repos) if repos else "全部"
    return jsonify({"success": True, "message": f"同步已启动 — {label}"})


@app.route("/api/sync/status")
def api_sync_status():
    return jsonify({"success": True, **sync_state})


@app.route("/api/sync/delete", methods=["POST"])
def api_sync_delete():
    """删除本地知识库目录（释放磁盘空间）。
    Body JSON: { repo_id: str }
    """
    body    = request.get_json(silent=True) or {}
    repo_id = body.get("repo_id", "")
    repo    = next((r for r in ALL_REPOS if r["id"] == repo_id), None)
    if not repo:
        return jsonify({"success": False, "message": "未知仓库 ID"})

    path = RAW_DATA_DIR / repo["local_dir"]
    if path.exists():
        shutil.rmtree(path)
        return jsonify({"success": True, "message": f"已删除 {repo['label']} 本地数据"})
    return jsonify({"success": True, "message": "目录不存在，无需删除"})


# ══════════════════════════════ RSS Feed API ════════════════════════════

@app.route("/api/rss/status")
def api_rss_status():
    """返回 RSS feed 配置及各 feed 上次同步时间、已抓取文件数等状态。"""
    try:
        from crawlers.config import RSS_FEEDS, RSS_POLL_INTERVAL_HOURS, RSS_MAX_ITEMS_PER_FEED
    except ImportError:
        return jsonify({"success": False, "message": "RSS 模块未加载"})

    state_file = ROOT_DIR / "data" / "rss_state.json"
    try:
        import json as _json
        state = _json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {}
    except Exception:
        state = {}

    FEED_LABELS = {
        "xianzhi": "先知安全社区",
        "butian":  "奇安信攻防社区",
    }

    feeds = []
    total_articles = 0
    for name, url in RSS_FEEDS.items():
        feed_state = state.get(name, {})
        article_dir = RAW_DATA_DIR / name
        file_count = len(list(article_dir.glob("*.json"))) if article_dir.exists() else 0
        seen_count = len(feed_state.get("seen_ids", []))
        total_articles += seen_count
        feeds.append({
            "name":        name,
            "label":       FEED_LABELS.get(name, name),
            "url":         url,
            "last_fetch":  feed_state.get("last_fetch"),
            "seen_count":  seen_count,
            "file_count":  file_count,
        })

    return jsonify({
        "success":        True,
        "feeds":          feeds,
        "interval_hours": RSS_POLL_INTERVAL_HOURS,
        "max_items":      RSS_MAX_ITEMS_PER_FEED,
        "total_articles": total_articles,
    })


_rss_sync_state: Dict = {"running": False, "last_run": None, "last_error": None}

@app.route("/api/rss/sync", methods=["POST"])
def api_rss_sync():
    """在后台线程立即触发一次全量 RSS 拉取。"""
    if _rss_sync_state["running"]:
        return jsonify({"success": False, "message": "RSS 同步正在进行中，请稍候"})

    def _run():
        _rss_sync_state["running"] = True
        _rss_sync_state["last_error"] = None
        try:
            import sys as _sys
            _sys.path.insert(0, str(ROOT_DIR))
            from crawlers.rss_crawler import RSSAggregator
            RSSAggregator().fetch_all(save=True)
            _rss_sync_state["last_run"] = datetime.now().isoformat(timespec="seconds")
        except Exception as e:
            _rss_sync_state["last_error"] = str(e)
        finally:
            _rss_sync_state["running"] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"success": True, "message": "RSS 同步已启动"})


@app.route("/api/rss/sync/status")
def api_rss_sync_status():
    """轮询 RSS 同步运行状态。"""
    return jsonify({"success": True, **_rss_sync_state})


@app.route("/api/crawler/wechat_config")
def api_wechat_config():
    """检测微信爬虫 Cookie 是否已配置。"""
    try:
        cfg_path = ROOT_DIR / "crawlers" / "wechat_crawler" / "config.py"
        configured = False
        if cfg_path.exists():
            text = cfg_path.read_text(encoding="utf-8")
            import re
            m = re.search(r"'COOKIE'\s*:\s*'([^']*)'", text)
            if m and m.group(1).strip():
                configured = True
        return jsonify({"success": True, "configured": configured})
    except Exception as e:
        return jsonify({"success": True, "configured": False, "error": str(e)})


# ══════════════════════════════ 微信公众号专项 API ════════════════════════════

WECHAT_CATEGORY_LABELS = {
    "vuln_research":   "漏洞研究",
    "redteam_tools":   "红队工具",
    "code_audit":      "代码审计",
    "threat_intel":    "威胁情报",
    "media":           "安全媒体",
    "ctf":             "CTF",
    "auto_discovered": "自动发现",
}

_WECHAT_STRONG_TECH_RE = re.compile(
    r"(cve-\d{4}-\d{4,7}|漏洞|exp\b|\bpoc\b|exploit|payload|rce|ssrf|xss|sql注入|越权|提权|"
    r"远程代码执行|任意代码执行|命令执行|反序列化|目录遍历|内网渗透|渗透测试|红队|应急响应|"
    r"漏洞复现|漏洞分析|补丁分析|攻击链)",
    re.IGNORECASE,
)

_WECHAT_TECH_HINTS = [
    "木马", "后门", "勒索", "恶意代码", "威胁情报", "apt", "c2", "免杀", "横向移动",
    "代码审计", "安全研究", "逆向", "ctf", "shellcode", "waf", "getshell", "蓝队", "攻防",
    "漏洞通告", "风险通告", "预警", "复盘", "利用链", "攻击面", "nmap", "burp", "sqlmap",
]

_WECHAT_NOISE_TITLE_HINTS = [
    "战略合作", "签署合作", "签约仪式", "达成合作", "发布会", "峰会", "论坛", "大会", "研讨会",
    "招聘", "校招", "内推", "获奖", "周年", "品牌升级", "生态合作", "联合声明", "活动报名",
    "直播预告", "课程报名", "产品发布",
]


def _load_seed_yaml() -> Dict:
    """读取 seed_accounts.yaml，返回原始 dict。"""
    if not _HAS_YAML:
        return {"categories": {}}
    if not SEED_YAML.exists():
        return {"categories": {}}
    try:
        with open(SEED_YAML, encoding="utf-8") as f:
            return _yaml.safe_load(f) or {"categories": {}}
    except Exception:
        return {"categories": {}}


def _save_seed_yaml(data: Dict) -> None:
    """将 seed data 写回 YAML 文件。"""
    if not _HAS_YAML:
        raise RuntimeError("PyYAML 未安装，无法写入 seed_accounts.yaml")
    SEED_YAML.parent.mkdir(parents=True, exist_ok=True)
    with open(SEED_YAML, "w", encoding="utf-8") as f:
        _yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _normalize_wechat_account_name(name: str) -> str:
    """规范化公众号名称，减少空格和标点差异导致的匹配失败。"""
    s = str(name or "").strip().lower()
    if not s:
        return ""
    s = re.sub(r"[\s\u3000]+", "", s)
    s = re.sub(r"[·•,，.。:：;；'\"“”‘’`~!！?？\-_/\\|()（）\[\]{}<>《》【】]", "", s)
    return s


def _wechat_accounts_match(actual_norm: str, target_norm: str) -> bool:
    """公众号名称匹配：精确匹配或包含匹配（处理简称/空格差异）。"""
    a = str(actual_norm or "")
    t = str(target_norm or "")
    if not a or not t:
        return False
    if a == t:
        return True
    return min(len(a), len(t)) >= 3 and (a in t or t in a)


def _is_wechat_article_relevant(article: Dict) -> bool:
    """筛掉公众号中的活动宣传/合作稿，只保留技术性安全内容。"""
    title = str(article.get("title") or "").strip()
    content = str(article.get("content") or "")
    text = f"{title}\n{content}".lower()
    title_text = title.lower()

    if not title and not content:
        return False

    strong_match = bool(_WECHAT_STRONG_TECH_RE.search(text))
    title_strong_match = bool(_WECHAT_STRONG_TECH_RE.search(title_text))
    hint_hits = sum(1 for kw in _WECHAT_TECH_HINTS if kw in text)
    noise_title_hits = sum(1 for kw in _WECHAT_NOISE_TITLE_HINTS if kw in title.lower())

    # 标题出现合作/活动等宣传信号时，只有标题本身具备明显技术信号才放行。
    if noise_title_hits > 0 and not title_strong_match:
        return False

    if title_strong_match:
        return True

    if strong_match and hint_hits >= 3:
        return True

    return hint_hits >= 5


def _count_wechat_articles_by_account(seed_names: Optional[List[str]] = None) -> Dict[str, int]:
    """统计 raw_data/wechat/ 下每个账号的已采集文章数（仅统计技术相关内容）。"""
    counts: Dict[str, int] = {}
    seed_norms = [_normalize_wechat_account_name(n) for n in (seed_names or []) if _normalize_wechat_account_name(n)]

    if not WECHAT_RAW_DIR.exists():
        return counts
    for fp in WECHAT_RAW_DIR.glob("*.json"):
        try:
            obj = json.loads(fp.read_text(encoding="utf-8"))
            if not _is_wechat_article_relevant(obj):
                continue

            acc_norm = _normalize_wechat_account_name(obj.get("account") or "")
            if not acc_norm:
                continue

            key = acc_norm
            if seed_norms:
                matched = [sn for sn in seed_norms if _wechat_accounts_match(acc_norm, sn)]
                if matched:
                    matched.sort(key=lambda x: (x == acc_norm, len(x)), reverse=True)
                    key = matched[0]

            counts[key] = counts.get(key, 0) + 1
        except Exception:
            pass
    return counts


@app.route("/api/wechat/seeds")
def api_wechat_seeds():
    """返回种子账号列表（按分类），并附带各账号已采集文章数。"""
    raw = _load_seed_yaml()
    categories_raw = raw.get("categories") or {}
    seed_names: List[str] = []
    for accounts in categories_raw.values():
        if not isinstance(accounts, list):
            continue
        for item in accounts:
            if isinstance(item, dict) and item.get("name"):
                seed_names.append(str(item.get("name")))

    art_counts = _count_wechat_articles_by_account(seed_names)

    result = {}
    for cat, accounts in categories_raw.items():
        if not isinstance(accounts, list):
            continue
        result[cat] = {
            "label":    WECHAT_CATEGORY_LABELS.get(cat, cat),
            "accounts": [
                {
                    "name":          a.get("name", ""),
                    "tags":          a.get("tags", []),
                    "priority":      a.get("priority", "normal"),
                    "notes":         a.get("notes", ""),
                    "article_count": art_counts.get(_normalize_wechat_account_name(a.get("name", "")), 0),
                }
                for a in accounts if isinstance(a, dict) and a.get("name")
            ],
        }
    return jsonify({"success": True, "categories": result})


@app.route("/api/wechat/seeds/update", methods=["POST"])
def api_wechat_seeds_update():
    """添加或删除种子账号。
    Body JSON add:    { action: "add",    category: str, name: str, tags: [str], priority: str, notes: str }
    Body JSON remove: { action: "remove", category: str, name: str }
    """
    if not _HAS_YAML:
        return jsonify({"success": False, "message": "服务器未安装 PyYAML，无法修改种子账号"})

    body   = request.get_json(silent=True) or {}
    action = body.get("action", "")
    cat    = body.get("category", "").strip()
    name   = body.get("name", "").strip()

    if not cat or not name:
        return jsonify({"success": False, "message": "category 和 name 不能为空"})

    data = _load_seed_yaml()
    if "categories" not in data or not isinstance(data["categories"], dict):
        data["categories"] = {}
    cats = data["categories"]

    if action == "add":
        if cat not in cats:
            cats[cat] = []
        existing = [a.get("name") for a in (cats[cat] or []) if isinstance(a, dict)]
        if name in existing:
            return jsonify({"success": False, "message": f"账号 '{name}' 已存在于 {cat} 分类"})
        entry: Dict = {
            "name":     name,
            "tags":     body.get("tags", []),
            "priority": body.get("priority", "normal"),
        }
        notes = body.get("notes", "").strip()
        if notes:
            entry["notes"] = notes
        cats[cat].append(entry)
        _save_seed_yaml(data)
        return jsonify({"success": True, "message": f"已添加账号 '{name}' 到 {cat}"})

    elif action == "remove":
        if cat not in cats:
            return jsonify({"success": False, "message": f"分类 {cat} 不存在"})
        before = len(cats[cat] or [])
        cats[cat] = [a for a in (cats[cat] or []) if a.get("name") != name]
        if len(cats[cat]) == before:
            return jsonify({"success": False, "message": f"账号 '{name}' 不存在于 {cat}"})
        _save_seed_yaml(data)
        return jsonify({"success": True, "message": f"已从 {cat} 移除账号 '{name}'"})

    return jsonify({"success": False, "message": f"不支持的操作: {action}"})


@app.route("/api/wechat/runtime_config")
def api_wechat_runtime_config():
    cfg = _get_wechat_runtime_config()
    return jsonify({"success": True, "config": cfg, "path": str(WECHAT_RUNTIME_CFG)})


@app.route("/api/wechat/runtime_config", methods=["POST"])
def api_wechat_runtime_config_update():
    body = request.get_json(silent=True) or {}
    try:
        cfg = _normalize_runtime_config(body)
        saved = save_runtime_settings(cfg, WECHAT_RUNTIME_CFG)
        return jsonify({"success": True, "config": saved, "message": "微信运行配置已保存"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/wechat/native/status")
def api_wechat_native_status():
    cfg = _get_wechat_runtime_config()
    native = get_native_settings(cfg)
    proxy = _get_windows_proxy_state()
    expected_proxy = f"{native['proxy_host']}:{native['proxy_port']}"
    return jsonify({
        "success": True,
        "windows": os.name == "nt",
        "proxy": proxy,
        "expected_proxy": expected_proxy,
        "proxy_ready": bool(proxy.get("enabled") and _proxy_matches_target(proxy.get("server", ""), native["proxy_host"], native["proxy_port"])),
        "mitm_running": _is_mitmdump_running(),
        "wechat_running": _is_wechat_running(),
        "mitm_log": str(WECHAT_MITM_LOG),
        "mitm_log_tail": _tail_text_file(WECHAT_MITM_LOG, limit=2500),
        "preflight": _collect_native_preflight(cfg),
    })


@app.route("/api/wechat/native/mitm/start", methods=["POST"])
def api_wechat_native_mitm_start():
    ok, msg = _start_mitmdump_process()
    payload = {"success": ok, "message": msg}
    if ok and _wechat_mitm_process is not None and _wechat_mitm_process.poll() is None:
        payload["pid"] = _wechat_mitm_process.pid
    return jsonify(payload)


@app.route("/api/wechat/native/mitm/stop", methods=["POST"])
def api_wechat_native_mitm_stop():
    global _wechat_mitm_process, _wechat_mitm_log_handle

    if _wechat_mitm_process is not None and _wechat_mitm_process.poll() is None:
        try:
            _wechat_mitm_process.terminate()
            _wechat_mitm_process.wait(timeout=5)
        except Exception:
            try:
                _wechat_mitm_process.kill()
            except Exception:
                pass
    _wechat_mitm_process = None
    if _wechat_mitm_log_handle is not None:
        try:
            _wechat_mitm_log_handle.close()
        except Exception:
            pass
        _wechat_mitm_log_handle = None
    return jsonify({"success": True, "message": "mitmdump 已停止"})


@app.route("/api/wechat/native/proxy/enable", methods=["POST"])
def api_wechat_native_proxy_enable():
    global _wechat_proxy_backup

    cfg = _get_wechat_runtime_config()
    native = get_native_settings(cfg)
    try:
        if _wechat_proxy_backup is None:
            _wechat_proxy_backup = _set_windows_proxy(native["proxy_host"], native["proxy_port"])
        else:
            _set_windows_proxy(native["proxy_host"], native["proxy_port"])
        return jsonify({"success": True, "message": f"系统代理已切到 {native['proxy_host']}:{native['proxy_port']}"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/wechat/native/proxy/restore", methods=["POST"])
def api_wechat_native_proxy_restore():
    global _wechat_proxy_backup

    try:
        _restore_windows_proxy(_wechat_proxy_backup)
        _wechat_proxy_backup = None
        return jsonify({"success": True, "message": "系统代理已恢复"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


@app.route("/api/wechat/crawl", methods=["POST"])
def api_wechat_crawl():
    """异步启动微信公众号爬虫。
    Body JSON: { accounts: [str], count: int, days: int, mode: str }
    """
    global _wechat_crawler_thread

    if wechat_crawler_state["running"]:
        return jsonify({"success": False, "message": "微信爬虫正在运行中，请稍候"})

    body     = request.get_json(silent=True) or {}
    accounts = [str(a).strip() for a in body.get("accounts", []) if str(a).strip()]
    count    = max(1, int(body.get("count", 10)))
    days_raw = body.get("days")
    try:
        days = max(1, min(90, int(days_raw))) if days_raw not in (None, "") else None
    except (TypeError, ValueError):
        days = None
    cfg      = _get_wechat_runtime_config()
    mode     = str(body.get("mode") or cfg.get("default_mode") or "sogou").strip().lower()

    if mode not in {"sogou", "native"}:
        return jsonify({"success": False, "message": f"不支持的模式: {mode}"})

    if not accounts:
        return jsonify({"success": False, "message": "请至少选择一个公众号账号"})

    if mode == "sogou" and not WECHAT_SOGOU_PY.exists():
        return jsonify({"success": False, "message": f"未找到爬虫脚本: {WECHAT_SOGOU_PY}"})

    if mode == "native":
        if not WECHAT_SCHEDULER_PY.exists():
            return jsonify({"success": False, "message": f"未找到调度脚本: {WECHAT_SCHEDULER_PY}"})
        preflight = _ensure_native_runtime_ready(cfg)
        if preflight:
            return jsonify({
                "success": False,
                "message": "原生微信轨未就绪（已尝试自动准备）：" + "；".join(preflight),
            })

    def _run():
        wechat_crawler_state["running"]       = True
        wechat_crawler_state["last_output"]   = ""
        wechat_crawler_state["last_error"]    = ""
        wechat_crawler_state["last_accounts"] = accounts
        wechat_crawler_state["last_mode"]     = mode
        wechat_crawler_state["last_days"]     = days
        try:
            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            if mode == "native":
                native = get_native_settings(cfg)
                cmd = [
                    str(PYTHON_EXE), str(WECHAT_SCHEDULER_PY),
                    "crawl",
                    "--accounts", *accounts,
                    "--count", str(count),
                ]
                if days:
                    cmd.extend(["--days", str(days)])
                if native.get("scheduler_force", True):
                    cmd.append("--force")
            else:
                cmd = [
                    str(PYTHON_EXE), str(WECHAT_SOGOU_PY),
                    "--accounts", *accounts,
                    "--count", str(count),
                ]
                if days:
                    cmd.extend(["--days", str(days)])
                env = build_sogou_env(env, cfg)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(ROOT_DIR),
                env=env,
                timeout=2400 if mode == "native" else 900,
            )
            wechat_crawler_state["last_output"] = (result.stdout or "")[-8000:]
            wechat_crawler_state["last_error"]  = (result.stderr or "")[-3000:]
            wechat_crawler_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            wechat_crawler_state["last_error"] = "爬虫超时 (>900s)"
        except Exception as exc:
            wechat_crawler_state["last_error"] = str(exc)
        finally:
            wechat_crawler_state["running"] = False

    _wechat_crawler_thread = threading.Thread(target=_run, daemon=True)
    _wechat_crawler_thread.start()
    day_suffix = f"，最近 {days} 天" if days else ""
    return jsonify({
        "success": True,
        "message": f"微信爬虫已启动（{mode}）— 账号: {', '.join(accounts)}，每号采集 {count} 篇{day_suffix}",
    })


@app.route("/api/wechat/crawl/status")
def api_wechat_crawl_status():
    return jsonify({"success": True, **wechat_crawler_state})


@app.route("/api/wechat/articles")
def api_wechat_articles():
    """列出 raw_data/wechat/ 下所有文章，按账号分组。
    额外参数: ?account=xxx 只返回指定账号的文章
    """
    account_filter = request.args.get("account", "").strip()
    norm_filter = _normalize_wechat_account_name(account_filter)
    groups: Dict[str, List] = {}

    if WECHAT_RAW_DIR.exists():
        for fp in sorted(WECHAT_RAW_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                obj = json.loads(fp.read_text(encoding="utf-8"))
                if not _is_wechat_article_relevant(obj):
                    continue

                acc = (obj.get("account") or "").strip() or "未知账号"
                acc_norm = _normalize_wechat_account_name(acc)
                if account_filter and not _wechat_accounts_match(acc_norm, norm_filter):
                    continue
                content = obj.get("content", "")
                preview = content[:200].replace("\n", " ").strip() if content else ""
                entry = {
                    "title":       obj.get("title", fp.stem),
                    "account":     acc,
                    "publish_time": obj.get("publish_time", ""),
                    "url":         obj.get("url", ""),
                    "char_count":  len(content),
                    "preview":     preview,
                    "file":        fp.name,
                }
                group_key = account_filter if account_filter else acc
                groups.setdefault(group_key, []).append(entry)
            except Exception:
                pass

    return jsonify({"success": True, "groups": groups, "total": sum(len(v) for v in groups.values())})


# ══════════════════════════════ Layer3 融合经验 API ═══════════════════════════

@app.route("/api/consolidated")
def api_consolidated():
    """
    返回 Layer3 融合后的 16 条权威经验（phase34_consolidated.jsonl）及统计摘要。
    同时附带 phase12_result.jsonl 中的等价集原始信息（来源 exp_ids 数量 / sessions）。
    """
    consolidated = _load_jsonl(LAYER3_DIR / "phase34_consolidated.jsonl")
    phase12      = _load_jsonl(LAYER3_DIR / "phase12_result.jsonl")
    raw_exps     = _load_jsonl(DATA_DIR   / "experience_raw.jsonl")

    # 构建 cluster_id → {n, sessions} 映射
    cluster_map: Dict[str, Dict] = {}
    for c in phase12:
        cid  = c.get("cluster_id", "")
        eids = c.get("exp_ids", [])
        wes  = c.get("weighted_experiences", [])
        sess = list({we.get("source_session_id", "")[:8]
                     for we in wes if we.get("source_session_id", "")})
        cluster_map[cid] = {"n": len(eids), "sessions": sess}

    # 为每条融合经验注入扁平化展示字段
    items = []
    for d in consolidated:
        prov    = d.get("provenance", {})
        n_src   = len(prov.get("source_exp_ids", []))
        sess    = prov.get("source_sessions", [])
        raw_layer = d.get("knowledge_layer", "")
        layer   = "FACTUAL" if str(raw_layer).startswith("FACTUAL_") else raw_layer
        content = d.get("content", {})

        # RAG_EVALUATION 层已弃用，不在融合经验页展示
        if layer == "RAG_EVALUATION":
            continue

        # 提取关键展示字段（层特定）
        display: Dict = {}
        if layer == "PROCEDURAL_NEG":
            dr = content.get("decision_rule", {})
            display = {
                "sub_dim": content.get("failure_sub_dimension", ""),
                "IF":      dr.get("IF", ""),
                "THEN":    dr.get("THEN", []),
                "NOT":     dr.get("NOT", []),
            }
        elif layer == "FACTUAL":
            facts = content.get("discovered_facts", [])
            cem = content.get("cve_exploitation_map", {})
            factual_source = ""
            if cem or str(raw_layer).endswith("_LLM"):
                factual_source = "llm"
            elif facts or str(raw_layer).endswith("_RULE"):
                factual_source = "rule"
            display = {
                "facts": [
                    {"key": f.get("key",""), "value": f.get("value",""), "count": f.get("count", 1)}
                    for f in facts if isinstance(f, dict)
                ],
                "cve_map": [
                    {"cve": cve, "status": v.get("consensus_status",""), "conf": v.get("confidence",0)}
                    for cve, v in cem.items() if isinstance(v, dict)
                ],
                "cve_unexplored": content.get("cve_unexplored", []),
                "factual_source": factual_source,
            }
        elif layer == "PROCEDURAL_POS":
            display = {
                "preconditions":       content.get("preconditions", []),
                "success_indicators":  content.get("success_indicators", []),
                "sub_dim":             content.get("success_sub_dimension", ""),
            }
        elif layer == "METACOGNITIVE":
            lessons = content.get("key_lessons", [])
            display = {
                "lessons": [
                    {"fp": l.get("rule_fingerprint",""), "insight": l.get("insight","")}
                    for l in lessons if isinstance(l, dict)
                ]
            }
        elif layer == "CONCEPTUAL":
            ac = content.get("applicable_conditions", {})
            triggers = ac.get("retrieval_triggers", []) if isinstance(ac, dict) else []
            display = {
                "core_insight": content.get("core_insight", ""),
                "triggers":     triggers,
            }

        items.append({
            "exp_id":   d.get("exp_id", ""),
            "layer":    layer,
            "maturity": d.get("maturity", ""),
            "p_fused":  round(float(d.get("p_fused", 0)), 4),
            "n_src":    n_src,
            "sessions": [s[:8] for s in sess],
            "display":  display,
            "content":  content,  # 完整内容供展开
        })

    # 统计摘要
    maturity_cnt = dict(Counter(i["maturity"] for i in items))
    layer_cnt    = dict(Counter(i["layer"]    for i in items))
    avg_pfused   = round(sum(i["p_fused"] for i in items) / len(items), 4) if items else 0
    total_raw    = len(raw_exps)

    return jsonify({
        "success":       True,
        "items":         items,
        "summary": {
            "total_consolidated": len(items),
            "total_raw_exps":     total_raw,
            "compression_ratio":  round(total_raw / max(len(items), 1), 1),
            "avg_p_fused":        avg_pfused,
            "maturity_counts":    maturity_cnt,
            "layer_counts":       layer_cnt,
        },
    })
# ═══════════════════════ KLM 状态 / 冲突 / 缺口 API ═══════════════════════════

@app.route("/api/klm/status")
def api_klm_status():
    """KLM 整体状态：lifecycle 分布、成熟度分布、RAGFlow 同步摘要。"""
    try:
        klm_raw = _load_jsonl(LAYER3_DIR / "phase5_klm_registry.jsonl")
        con     = _load_jsonl(LAYER3_DIR / "phase34_consolidated.jsonl")

        # 合并去重（以 exp_id 为 key，phase5_klm_registry 优先，因其含最新 ragflow_doc_id）
        entries = {}
        for e in con + klm_raw:   # phase5 last → overwrites phase34 for same exp_id
            eid = e.get("exp_id") or e.get("id")
            if eid:
                entries[eid] = e
        all_entries = list(entries.values())

        from collections import Counter
        lifecycle_cnt = dict(Counter(e.get("lifecycle_status", "unknown") for e in all_entries))
        maturity_cnt  = dict(Counter(e.get("maturity", "unknown")         for e in all_entries))

        # RAGflow 同步
        ragflow_entries = [e for e in all_entries if e.get("ragflow_doc_id")]
        ragflow_synced  = len(ragflow_entries)
        ragflow_pending = len([e for e in all_entries
                               if e.get("maturity") == "consolidated"
                               and not e.get("ragflow_doc_id")
                               and e.get("lifecycle_status") == "active"])
        conflicted      = len([e for e in all_entries if e.get("lifecycle_status") == "conflicted"])

        return jsonify({
            "success":       True,
            "total":         len(all_entries),
            "lifecycle":     lifecycle_cnt,
            "maturity":      maturity_cnt,
            "ragflow_synced": ragflow_synced,
            "ragflow_pending": ragflow_pending,
            "conflicted":    conflicted,
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/klm/conflicts")
def api_klm_conflicts():
    """返回所有 conflicted 条目及冲突上下文。"""
    try:
        klm_raw = _load_jsonl(LAYER3_DIR / "phase5_klm_registry.jsonl")
        con     = _load_jsonl(LAYER3_DIR / "phase34_consolidated.jsonl")

        entries = {}
        for e in con + klm_raw:   # phase5 last → overwrites phase34
            eid = e.get("exp_id") or e.get("id")
            if eid:
                entries[eid] = e

        conflict_list = []
        for e in entries.values():
            if e.get("lifecycle_status") != "conflicted":
                continue
            meta = e.get("metadata", {})
            ac   = meta.get("applicable_constraints", {})
            conflict_list.append({
                "exp_id":        e.get("exp_id", ""),
                "knowledge_layer": e.get("knowledge_layer", ""),
                "maturity":      e.get("maturity", ""),
                "conflict_reason":       e.get("conflict_reason", "—"),
                "conflict_triggered_by": e.get("conflict_triggered_by", "—"),
                "conflict_updated_at":   e.get("conflict_updated_at", "—"),
                "target_service": ac.get("target_service", "—"),
                "cve_ids":        ac.get("cve_ids", []),
            })

        # 同步：已上传条目
        ragflow_list = []
        for e in entries.values():
            if e.get("ragflow_doc_id"):
                meta = e.get("metadata", {})
                ac   = meta.get("applicable_constraints", {})
                ragflow_list.append({
                    "exp_id":        e.get("exp_id", ""),
                    "knowledge_layer": e.get("knowledge_layer", ""),
                    "ragflow_doc_id": e.get("ragflow_doc_id", ""),
                    "target_service": ac.get("target_service", "—"),
                })

        return jsonify({
            "success":       True,
            "conflicts":     conflict_list,
            "ragflow_synced": ragflow_list,
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/klm/gaps")
def api_klm_gaps():
    """分析 KLM 中哪些 (target_service, CVE) 组合 consolidated 经验数量少（缺口）。"""
    try:
        klm_raw = _load_jsonl(LAYER3_DIR / "phase5_klm_registry.jsonl")
        con     = _load_jsonl(LAYER3_DIR / "phase34_consolidated.jsonl")

        # 合并
        entries = {}
        for e in con + klm_raw:   # phase5 last → overwrites phase34
            eid = e.get("exp_id") or e.get("id")
            if eid:
                entries[eid] = e

        from collections import defaultdict
        # 按 (target_service, cve) 分组统计
        groups = defaultdict(lambda: {"raw": 0, "consolidated": 0, "cves": set()})
        for e in entries.values():
            meta = e.get("metadata", {})
            ac   = meta.get("applicable_constraints", {})
            svc  = ac.get("target_service") or "Unknown"
            cves = ac.get("cve_ids") or []
            mat  = e.get("maturity", "raw")
            lc   = e.get("lifecycle_status", "active")
            if lc == "conflicted":
                continue
            key = svc
            groups[key]["cves"].update(cves)
            groups[key]["raw"] += 1
            if mat == "consolidated":
                groups[key]["consolidated"] += 1

        # 计算缺口评分（consolidated 越少、raw 越多 → 缺口越大）
        gap_list = []
        for svc, d in groups.items():
            raw  = d["raw"]
            cons = d["consolidated"]
            cves = sorted(d["cves"])
            # 缺口评分：越高表示越缺乏升华
            gap_score = max(0, raw - cons * 3)
            gap_list.append({
                "target_service": svc,
                "cve_list":       cves,
                "raw_count":      raw,
                "consolidated_count": cons,
                "gap_score":      gap_score,
                # 生成建议的搜索关键词（可用于爬虫）
                "suggested_keywords": ([svc.split()[-1]] + cves[:3]) if cves else [svc.split()[-1]],
            })

        # 按缺口评分降序
        gap_list.sort(key=lambda x: x["gap_score"], reverse=True)

        return jsonify({
            "success":  True,
            "gaps":     gap_list[:30],  # 最多30个
            "total_services": len(gap_list),
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


# ════════════════ 缺口爬虫 API（CSDN/GitHub/奇安信/先知社区）═══════════════


@app.route("/api/gap/crawl", methods=["POST"])
def api_gap_crawl():
    """按关键词调用 main_crawler.py --sources csdn,github,qianxin,xianzhi 爬取补充数据。"""
    global _gap_crawler_thread

    if gap_crawler_state["running"]:
        return jsonify({"success": False, "error": "缺口爬虫正在运行，请稍候"})

    data = request.get_json(force=True, silent=True) or {}
    query = (data.get("query") or "").strip()
    max_pages = int(data.get("max_pages", 3))
    sources   = data.get("sources", ["csdn", "github", "qianxin", "xianzhi"])
    if not query:
        return jsonify({"success": False, "error": "缺少搜索关键词 query"})

    sources_str = ",".join(sources)

    def _run():
        gap_crawler_state["running"]     = True
        gap_crawler_state["last_output"] = ""
        gap_crawler_state["last_error"]  = ""
        gap_crawler_state["last_query"]  = query
        try:
            result = subprocess.run(
                [
                    str(PYTHON_EXE), str(CRAWLER_PY),
                    "--sources", sources_str,
                    "-q", query,
                    "--max-pages", str(max_pages),
                    "--yes",
                ],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                cwd=str(LORE_ROOT),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=300,
            )
            gap_crawler_state["last_output"] = (result.stdout or "")[-5000:]
            gap_crawler_state["last_error"]  = (result.stderr or "")[-2000:]
            gap_crawler_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            gap_crawler_state["last_error"] = "爬取超时 (>300s)"
        except Exception as exc:
            gap_crawler_state["last_error"] = str(exc)
        finally:
            gap_crawler_state["running"] = False

    _gap_crawler_thread = threading.Thread(target=_run, daemon=True)
    _gap_crawler_thread.start()
    return jsonify({"success": True, "message": f"已启动缺口爬取：{query}（{sources_str}）"})


@app.route("/api/gap/crawl/status")
def api_gap_crawl_status():
    return jsonify({"success": True, **gap_crawler_state})


# ════════════════════ 全链路反思 Pipeline API ══════════════════════════════════


@app.route("/api/pipeline/full", methods=["POST"])
def api_pipeline_full():
    """全链路反思流水线：Layer1 → Layer2 → Layer3(Phase1-5)。"""
    global _full_pipeline_thread

    if full_pipeline_state["running"]:
        return jsonify({"success": False, "message": "全链路流水线正在运行中，请稍候"})

    steps = [
        ("Layer 1 — LLM 标注提取",    LAYER1_PY),
        ("Layer 2 — 分析验证",        PIPELINE_PY),
        ("Layer 3 Phase 1+2 — 等价聚类", LAYER3_P12_PY),
        ("Layer 3 Phase 3+4 — 规则融合", LAYER3_P34_PY),
        ("Layer 3 Phase 5 — KLM 注册", LAYER3_P5_PY),
    ]

    def _run():
        full_pipeline_state["running"]     = True
        full_pipeline_state["last_output"] = ""
        full_pipeline_state["last_error"]  = ""
        all_out = []
        try:
            for step_name, script_path in steps:
                if not script_path.exists():
                    all_out.append(f"[跳过] {step_name}：脚本不存在 {script_path}")
                    continue
                full_pipeline_state["current_step"] = step_name
                all_out.append(f"\n{'='*50}\n▶ {step_name}\n{'='*50}")
                try:
                    result = subprocess.run(
                        [str(PYTHON_EXE), str(script_path)],
                        capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        cwd=str(LORE_ROOT),
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                        timeout=600,
                    )
                    out = (result.stdout or "")[-3000:]
                    err = (result.stderr or "")[-1000:]
                    all_out.append(out)
                    if err:
                        all_out.append(f"[stderr] {err}")
                    if result.returncode != 0:
                        all_out.append(f"⚠ 退出码 {result.returncode}")
                except subprocess.TimeoutExpired:
                    all_out.append(f"❌ {step_name} 超时 (>600s)")
                    break
                except Exception as exc:
                    all_out.append(f"❌ {step_name} 异常: {exc}")
                    break
            full_pipeline_state["last_output"] = "\n".join(all_out)[-8000:]
            full_pipeline_state["last_run"]    = datetime.now().isoformat()
        except Exception as exc:
            full_pipeline_state["last_error"] = str(exc)
        finally:
            full_pipeline_state["running"]      = False
            full_pipeline_state["current_step"] = ""

    _full_pipeline_thread = threading.Thread(target=_run, daemon=True)
    _full_pipeline_thread.start()
    return jsonify({"success": True, "message": "全链路反思流水线已启动（Layer1→Layer2→Layer3）"})


@app.route("/api/pipeline/full/status")
def api_pipeline_full_status():
    return jsonify({"success": True, **full_pipeline_state})


# ════════════════════ Lore 分阶段流水线 API ═════════════════════════════════

@app.route("/api/pipeline/lore/status")
def api_lore_pipeline_status():
    """返回 lore 分阶段流水线状态（含 .pipeline_state.json 各阶段状态）。"""
    stage_status: Dict = {}
    if LORE_STATE_FILE.exists():
        try:
            stage_status = json.loads(LORE_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 补全所有阶段的定义（含脚本存在性）
    stages_info = []
    for key, label, script_path in LORE_STAGE_DEFINITIONS:
        rec = stage_status.get(key, {})
        stages_info.append({
            "key":        key,
            "label":      label,
            "status":     rec.get("status", "pending"),
            "elapsed":    rec.get("elapsed"),
            "finished_at": rec.get("finished_at", ""),
            "script_exists": (script_path is not None and script_path.exists()),
        })

    # 读取实时日志（最后 10000 字节）
    live_log = ""
    if LORE_LOG_FILE.exists():
        try:
            live_log = LORE_LOG_FILE.read_text(encoding="utf-8", errors="replace")[-10000:]
        except Exception:
            pass

    return jsonify({
        "success":      True,
        "running":      lore_pipeline_state["running"],
        "current_step": lore_pipeline_state["current_step"],
        "last_run":     lore_pipeline_state["last_run"],
        "last_error":   lore_pipeline_state["last_error"],
        "stages":       stages_info,
        "live_log":     live_log,
    })


@app.route("/api/pipeline/lore/run", methods=["POST"])
def api_lore_pipeline_run():
    """启动 lore 分阶段流水线。
    Body JSON: {
      stages:      [str]   -- 空或省略则运行全部阶段
      no_ragflow:  bool    -- 是否跳过 RAGflow 上传
      verbose:     bool    -- 是否详细日志
    }
    """
    global _lore_pipeline_thread

    if lore_pipeline_state["running"]:
        return jsonify({"success": False, "message": "流水线正在运行中，请稍候"})

    body       = request.get_json(silent=True) or {}
    stages     = body.get("stages") or []
    no_ragflow = bool(body.get("no_ragflow", False))
    verbose    = bool(body.get("verbose", False))

    valid_keys = {s[0] for s in LORE_STAGE_DEFINITIONS}
    stages     = [s for s in stages if s in valid_keys] if stages else []

    def _run():
        lore_pipeline_state["running"]      = True
        lore_pipeline_state["current_step"] = ""
        lore_pipeline_state["last_error"]   = ""

        # 清空实时日志文件
        try:
            LORE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            LORE_LOG_FILE.write_text("", encoding="utf-8")
        except Exception:
            pass

        def _append_log(text: str) -> None:
            try:
                with open(LORE_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(text)
            except Exception:
                pass

        try:
            run_stages = stages if stages else [s[0] for s in LORE_STAGE_DEFINITIONS]

            for key, label, script_path in LORE_STAGE_DEFINITIONS:
                if key not in run_stages:
                    continue

                lore_pipeline_state["current_step"] = label
                header = f"\n{'='*60}\n▶ {label}\n{'='*60}\n"
                _append_log(header)

                # upload 阶段：没有独立脚本，由 lore.py upload 子命令处理
                if script_path is None:
                    cmd = [str(PYTHON_EXE), str(LORE_PY), "upload"]
                    if not LORE_PY.exists():
                        _append_log(f"[跳过] lore.py 不存在: {LORE_PY}\n")
                        continue
                else:
                    if not script_path.exists():
                        _append_log(f"[跳过] 脚本不存在: {script_path}\n")
                        continue
                    cmd = [str(PYTHON_EXE), str(script_path)]
                    if verbose:
                        cmd.append("--verbose")

                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        cwd=str(ROOT_DIR),
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                    )
                    # 逐行写入实时日志
                    for line in proc.stdout:  # type: ignore[union-attr]
                        _append_log(line)
                    proc.wait(timeout=900)
                    rc = proc.returncode
                    if rc != 0:
                        _append_log(f"\n⚠ 退出码 {rc}\n")
                except subprocess.TimeoutExpired:
                    _append_log(f"\n❌ {label} 超时 (>900s)\n")
                    try:
                        proc.kill()  # type: ignore[union-attr]
                    except Exception:
                        pass
                    break
                except Exception as exc:
                    _append_log(f"\n❌ {label} 异常: {exc}\n")
                    lore_pipeline_state["last_error"] = str(exc)
                    break

            lore_pipeline_state["last_run"] = datetime.now().isoformat()
            _append_log("\n✔ 流水线执行完毕\n")
        except Exception as exc:
            lore_pipeline_state["last_error"] = str(exc)
            _append_log(f"\n❌ 流水线异常: {exc}\n")
        finally:
            lore_pipeline_state["running"]      = False
            lore_pipeline_state["current_step"] = ""

    _lore_pipeline_thread = threading.Thread(target=_run, daemon=True)
    _lore_pipeline_thread.start()

    stage_desc = "、".join(stages) if stages else "全部阶段"
    return jsonify({"success": True, "message": f"流水线已启动 — {stage_desc}"})


@app.route("/api/pipeline/lore/reset", methods=["POST"])
def api_lore_pipeline_reset():
    """清除 .pipeline_state.json 状态记录。"""
    if lore_pipeline_state["running"]:
        return jsonify({"success": False, "message": "流水线正在运行中，无法重置"})
    try:
        if LORE_STATE_FILE.exists():
            LORE_STATE_FILE.unlink()
        if LORE_LOG_FILE.exists():
            LORE_LOG_FILE.write_text("", encoding="utf-8")
        return jsonify({"success": True, "message": "状态已清除"})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)})


if __name__ == "__main__":
    print("=" * 60)
    print("  LORE 知识提炼系统 Dashboard")
    print(f"  数据路径 : {DATA_DIR}")
    print("  访问地址 : http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=True)

