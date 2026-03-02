"""
RefPenTest 知识提炼系统 — Dashboard 后端
为经验库浏览、会话分析和流水线管理提供 RESTful API
"""

import json
import os
import shutil
import subprocess
import threading
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# ── 路径配置 ─────────────────────────────────────────────────────────────────
ROOT_DIR    = Path(__file__).parent.parent          # RefPenTest/
WORKSPACE   = ROOT_DIR.parent                       # 语料/ (含 .venv)
DATA_DIR    = ROOT_DIR / "data" / "layer2_output"
LAYER3_DIR  = ROOT_DIR / "data" / "layer3_output"
LOGS_DIR    = ROOT_DIR / "logs"
REFPENTEST  = ROOT_DIR                              # 主入口就在 ROOT_DIR 内
PIPELINE_PY = ROOT_DIR / "run_layer2_analysis.py"
CRAWLER_PY  = ROOT_DIR / "main_crawler.py"
SYNC_PY     = ROOT_DIR / "scripts" / "sync_data_light.py"
RAW_DATA_DIR = ROOT_DIR / "raw_data"
PYTHON_EXE  = WORKSPACE / ".venv" / "Scripts" / "python.exe"
# ── Layer 1-3 脚本路径 ────────────────────────────────────────────────────────
LAYER1_PY       = ROOT_DIR / "run_layer1_llm_batch.py"
LAYER3_P12_PY   = ROOT_DIR / "run_layer3_phase12.py"
LAYER3_P34_PY   = ROOT_DIR / "run_layer3_phase34.py"
LAYER3_P5_PY    = ROOT_DIR / "run_layer3_phase5.py"

# ── 微信专属路径 ──────────────────────────────────────────────────────────────
CRAWL_WECHAT_PY = ROOT_DIR / "crawlers" / "wechat_crawler" / "sogou_crawler.py"
SEED_YAML       = ROOT_DIR / "crawlers" / "wechat_crawler" / "seed_accounts.yaml"
WECHAT_RAW_DIR  = RAW_DATA_DIR / "wechat"

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
}
_wechat_crawler_thread: Optional[threading.Thread] = None

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
            return jsonify({"success": True, "experience": e})
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
                cwd=str(REFPENTEST),
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
    max_pages = int(body.get("max_pages", 5))

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
                "-o", str(RAW_DATA_DIR),   # 📁 输出到 raw_data/，与 rawdata 管理一致
                "-y",
            ]
            if query:
                cmd += ["-q", query]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(ROOT_DIR),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=600,
            )
            crawler_state["last_output"] = (result.stdout or "")[-8000:]
            crawler_state["last_error"]  = (result.stderr or "")[-3000:]
            crawler_state["last_run"]    = datetime.now().isoformat()
        except subprocess.TimeoutExpired:
            crawler_state["last_error"] = "爬虫超时 (>600s)"
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


def _count_wechat_articles_by_account() -> Dict[str, int]:
    """统计 raw_data/wechat/ 下每个账号的已采集文章数。"""
    counts: Dict[str, int] = {}
    if not WECHAT_RAW_DIR.exists():
        return counts
    for fp in WECHAT_RAW_DIR.glob("*.json"):
        try:
            obj = json.loads(fp.read_text(encoding="utf-8"))
            acc = (obj.get("account") or "").strip()
            if acc:
                counts[acc] = counts.get(acc, 0) + 1
        except Exception:
            pass
    return counts


@app.route("/api/wechat/seeds")
def api_wechat_seeds():
    """返回种子账号列表（按分类），并附带各账号已采集文章数。"""
    raw = _load_seed_yaml()
    categories_raw = raw.get("categories") or {}
    art_counts = _count_wechat_articles_by_account()

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
                    "article_count": art_counts.get(a.get("name", ""), 0),
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


@app.route("/api/wechat/crawl", methods=["POST"])
def api_wechat_crawl():
    """异步启动微信公众号爬虫。
    Body JSON: { accounts: [str], count: int }
    """
    global _wechat_crawler_thread

    if wechat_crawler_state["running"]:
        return jsonify({"success": False, "message": "微信爬虫正在运行中，请稍候"})

    if not CRAWL_WECHAT_PY.exists():
        return jsonify({"success": False, "message": f"未找到爬虫脚本: {CRAWL_WECHAT_PY}"})

    body     = request.get_json(silent=True) or {}
    accounts = [str(a).strip() for a in body.get("accounts", []) if str(a).strip()]
    count    = max(1, int(body.get("count", 10)))

    if not accounts:
        return jsonify({"success": False, "message": "请至少选择一个公众号账号"})

    def _run():
        wechat_crawler_state["running"]       = True
        wechat_crawler_state["last_output"]   = ""
        wechat_crawler_state["last_error"]    = ""
        wechat_crawler_state["last_accounts"] = accounts
        try:
            cmd = [
                str(PYTHON_EXE), str(CRAWL_WECHAT_PY),
                "--accounts", *accounts,
                "--count", str(count),
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(ROOT_DIR),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                timeout=900,
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
    return jsonify({
        "success": True,
        "message": f"微信爬虫已启动 — 账号: {', '.join(accounts)}，每号采集 {count} 篇",
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
    groups: Dict[str, List] = {}

    if WECHAT_RAW_DIR.exists():
        for fp in sorted(WECHAT_RAW_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                obj = json.loads(fp.read_text(encoding="utf-8"))
                acc = (obj.get("account") or "").strip() or "未知账号"
                if account_filter and acc != account_filter:
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
                groups.setdefault(acc, []).append(entry)
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
        layer   = d.get("knowledge_layer", "")
        content = d.get("content", {})

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
        elif layer in ("FACTUAL_RULE",):
            facts = content.get("discovered_facts", [])
            display = {
                "facts": [
                    {"key": f.get("key",""), "value": f.get("value",""), "count": f.get("count", 1)}
                    for f in facts if isinstance(f, dict)
                ]
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
        elif layer == "RAG_EVALUATION":
            ras = content.get("rag_adoption_stats", {})
            display = {
                "adoption_rate":   ras.get("adoption_rate", 0),
                "avg_bar":         ras.get("avg_bar_score", 0),
                "bar_std":         ras.get("bar_score_std", 0),
                "session_breakdown": content.get("session_breakdown", {}),
                "recommendations": content.get("recommendations", []),
                "query_effectiveness": content.get("query_effectiveness", {}),
            }
        elif layer == "FACTUAL_LLM":
            cem  = content.get("cve_exploitation_map", {})
            display = {
                "cve_map": [
                    {"cve": cve, "status": v.get("consensus_status",""), "conf": v.get("confidence",0)}
                    for cve, v in cem.items() if isinstance(v, dict)
                ],
                "cve_unexplored": content.get("cve_unexplored", []),
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
                cwd=str(REFPENTEST),
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
                        cwd=str(REFPENTEST),
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


if __name__ == "__main__":
    print("=" * 60)
    print("  RefPenTest 知识提炼系统 Dashboard")
    print(f"  数据路径 : {DATA_DIR}")
    print("  访问地址 : http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=True)
