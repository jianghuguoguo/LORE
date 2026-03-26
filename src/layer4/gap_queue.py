# src/layer4/gap_queue.py
"""
基于 JSONL 文件的缺口队列。
线程安全（threading.Lock），Windows/Linux 均可用。
对于多进程写入场景，建议在队列目录上层加外部互斥保护
（或使用 portalocker），本模块以单进程（多线程）为主要使用场景。
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
import re as _re
from typing import Dict, List, Optional
from urllib.parse import urlparse as _urlparse

from .models import GapSignal, GapPriority
from ..utils.config_loader import get_config

logger = logging.getLogger(__name__)

# 队列文件默认存放在 src/layer4/queues/ 目录，支持统一配置覆盖。
_DEFAULT_QUEUE_DIR = Path(__file__).resolve().parent / "queues"
try:
    QUEUE_DIR = Path(get_config().layer4_queue_dir)
except Exception:
    QUEUE_DIR = _DEFAULT_QUEUE_DIR

GAP_QUEUE_FILE = QUEUE_DIR / "gap_queue.jsonl"

# 静态修复结果写入文件（ENV/BINARY_MISSING 等无需爬取的信号）
STATIC_REMEDIATION_FILE = QUEUE_DIR / "static_remediations.jsonl"

# ─────────────────────────────────────────────────────────────────────────────
# BUG-3: Crawl-worthy 过滤表
# True  = 需要外部爬取新文档
# False = 静态修复或知识库已覆盖，无需触发爬虫
# ─────────────────────────────────────────────────────────────────────────────
CRAWL_WORTHY: Dict[str, bool] = {
    # ── 需要爬取：认知/情报缺口 ──────────────────────────────────────────────
    "INCOMPLETE_RECON":   True,   # P0：情报认知缺口，需外部 PoC/writeup
    "MISSING_CONTEXT":    True,   # P0：同上
    "WRONG_ASSUMPTION":   True,   # P1：认知偏差，需外部纠正
    # ── 条件爬取：有一定价值但非紧急 ─────────────────────────────────────────
    "PATCHED":            True,   # P1：搜索替代漏洞 / 绕过技术
    "WRONG_ARGS":         True,   # P1：搜索工具使用文档
    "WRONG_SYNTAX":       True,   # P1：搜索命令语法
    # ── 不触发爬取 ───────────────────────────────────────────────────────────
    "BINARY_MISSING":     False,  # 静态工具安装映射表处理（见 TOOL_INSTALL_MAP）
    "PERMISSION":         False,  # sudo 配置问题，一行命令修复
    "TIMEOUT":            False,  # 基础设施 / 网络问题
    "DEPENDENCY_MISSING": False,  # pip install 静态修复
    "AUTHENTICATION":     False,  # 认证拦截 = 策略调整，外部文档帮不了实时场景
    "ACTIVE_BLOCKING":    False,  # WAF/IDS 逃逸技术知识库已有覆盖
    "BLIND_EXECUTION":    False,  # 执行无回显 = 运维配置问题
    "AUTHORIZATION":      False,  # 权限配置问题
}

# ─────────────────────────────────────────────────────────────────────────────
# BUG-3: 静态工具安装映射表（替代 ENV/BINARY_MISSING 爬取）
# ─────────────────────────────────────────────────────────────────────────────
TOOL_INSTALL_MAP: Dict[str, str] = {
    "dirb":       "sudo apt-get install -y dirb",
    "gobuster":   "sudo apt-get install -y gobuster",
    "hydra":      "sudo apt-get install -y hydra",
    "nmap":       "sudo apt-get install -y nmap",
    "metasploit": (
        "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/"
        "master/config/templates/metasploit-framework-wrappers/msfupdate.erb "
        "| sudo bash"
    ),
    "msfconsole": (
        "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/"
        "master/config/templates/metasploit-framework-wrappers/msfupdate.erb "
        "| sudo bash"
    ),
    "nuclei":     "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "fscan":      "wget https://github.com/shadow1ng/fscan/releases/latest/download/fscan && chmod +x fscan",
    "sqlmap":     "sudo apt-get install -y sqlmap  # or: pip install sqlmap",
    "nikto":      "sudo apt-get install -y nikto",
    "ffuf":       "go install github.com/ffuf/ffuf/v2@latest",
    "feroxbuster":"cargo install feroxbuster  # or: sudo apt-get install -y feroxbuster",
    "wfuzz":      "sudo apt-get install -y wfuzz  # or: pip install wfuzz",
    "netcat":     "sudo apt-get install -y netcat-openbsd",
    "nc":         "sudo apt-get install -y netcat-openbsd",
    "curl":       "sudo apt-get install -y curl",
    "wget":       "sudo apt-get install -y wget",
    "john":       "sudo apt-get install -y john",
    "hashcat":    "sudo apt-get install -y hashcat",
    "crackmapexec": "pip install crackmapexec  # or: sudo apt-get install -y crackmapexec",
    "impacket":   "pip install impacket",
}

# 这些后缀会从 tool_name 中剥离以得到基础工具名
_TOOL_NAME_STRIPS = ("_scan", "_attack", "_run", "_exploit", "_enum", "_brute", "_check")

# ─────────────────────────────────────────────────────────────────────────────
# BUG-6: target_service 规范化——端口→服务名映射表
# ─────────────────────────────────────────────────────────────────────────────
PORT_TO_SERVICE: Dict[str, str] = {
    "80":    "HTTP Web Server",
    "443":   "HTTPS Web Server",
    "8080":  "HTTP Web Application",
    "8888":  "HTTP Web Application",
    "8443":  "HTTPS Web Application",
    "10086": "HTTP Web Application",
    "7001":  "Oracle WebLogic Server",
    "7002":  "Oracle WebLogic Server (SSL)",
    "5984":  "Apache CouchDB",
    "8983":  "Apache Solr",
    "8161":  "Apache ActiveMQ",
    "4848":  "GlassFish Admin",
    "9200":  "Elasticsearch",
    "3306":  "MySQL",
    "5432":  "PostgreSQL",
    "6379":  "Redis",
    "27017": "MongoDB",
    "1433":  "Microsoft SQL Server",
    "1521":  "Oracle Database",
    "9090":  "Cockpit",
    "2375":  "Docker API",
    "6443":  "Kubernetes API",
    "9000":  "PHP-FPM / SonarQube",
    "9300":  "Elasticsearch Transport",
}


# CVE 编号 → 服务名映射（用于 target_raw 解析为通用 HTTP 时的 P0 条件回退）
CVE_TO_SERVICE: Dict[str, str] = {
    "CVE-2017-10271": "Oracle WebLogic Server",
    "CVE-2019-2725":  "Oracle WebLogic Server",
    "CVE-2020-14882": "Oracle WebLogic Server",
    "CVE-2021-2109":  "Oracle WebLogic Server",
    "CVE-2018-2628":  "Oracle WebLogic Server",
    "CVE-2018-2894":  "Oracle WebLogic Server",
    "CVE-2021-25646": "Apache Druid",
    "CVE-2022-24706": "Apache CouchDB",
    "CVE-2019-0232":  "Apache Tomcat",
    "CVE-2021-44228": "Log4Shell (Log4j)",
    "CVE-2021-45046": "Log4Shell (Log4j)",
    "CVE-2022-22965": "Spring Framework (Spring4Shell)",
    "CVE-2017-5638":  "Apache Struts",
}


def infer_service_from_cves(cve_ids: list) -> str:
    """从 CVE 编号推断目标服务名（用于 target 解析为通用 HTTP 时的回退）。"""
    for cve in cve_ids:
        svc = CVE_TO_SERVICE.get(cve)
        if svc:
            return svc
    return ""


def resolve_target_service(target_raw: str) -> str:
    """从 target_raw 解析规范化服务名，供 GapSignal.target_service 使用。

    处理两种格式：
    - 中文靶场描述：'渗透测试靶场：http://127.0.0.1:7001'
    - 纯 URL：'http://192.168.1.1:5984/'
    - 已规范化字符串：直接截断返回

    Examples:
        resolve_target_service('渗透测试靶场：http://127.0.0.1:7001')
        # → 'Oracle WebLogic Server'
        resolve_target_service('渗透测试靶场：http://127.0.0.1:5984/')
        # → 'Apache CouchDB'
    """
    if not target_raw:
        return ""

    # 从字符串中提取 URL
    url_m = _re.search(r'https?://[^\s，。、,]+', target_raw)
    if url_m:
        url = url_m.group(0)
        try:
            parsed = _urlparse(url)
            port = str(
                parsed.port
                if parsed.port
                else (443 if parsed.scheme == "https" else 80)
            )
            svc = PORT_TO_SERVICE.get(port)
            if svc:
                return svc
            # 端口不在映射表中，也比原始中文字符串有用
            return f"HTTP Service port {port}"
        except Exception:
            pass

    # 无 URL：清除中文前缀，返回截断字符串
    cleaned = _re.sub(r'^[\u4e00-\u9fff：:]+', '', target_raw).strip()
    return cleaned[:60] if cleaned else target_raw[:60]


def handle_binary_missing(event: dict) -> Optional[str]:
    """从 all_fail 事件字典中提取工具名，查表返回安装命令。

    Args:
        event: _scan_layer1_gaps.py 内 all_fail 列表中的单条字典，
               含 tool_name（Layer0 原始调用名）和 evidence 字段。
    Returns:
        安装命令字符串，若工具不在映射表中则返回 None。
    """
    # 优先从 tool_name 字段推断
    raw = event.get("tool_name", "")
    base = raw.lower()
    for strip in _TOOL_NAME_STRIPS:
        base = base.replace(strip, "")
    cmd = TOOL_INSTALL_MAP.get(base)
    if cmd:
        return cmd

    # 回退：从 evidence 字符串中提取引号内的工具名
    evidence = event.get("evidence", "")
    m = _re.search(r"['\"]([a-z0-9_\-]+)['\"]", evidence)
    if m:
        cmd = TOOL_INSTALL_MAP.get(m.group(1).lower())
    return cmd


# 全局线程锁（单进程内多线程安全）
_lock = threading.Lock()


class GapQueue:
    """基于 JSONL 文件的缺口队列，支持多线程并发读写。"""

    # ── 写入 ─────────────────────────────────────────────────────────────────

    def push(self, signal: GapSignal) -> None:
        """将缺口信号追加到队列尾部。"""
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        if not signal.gap_id:
            signal.gap_id = str(uuid.uuid4())
        if not signal.created_at:
            signal.created_at = datetime.now(tz=timezone.utc).isoformat()

        with _lock:
            with open(GAP_QUEUE_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(signal.to_dict(), ensure_ascii=False) + "\n")

        logger.debug("GapQueue.push: %s  priority=%s", signal.gap_id, signal.priority)

    # ── 读取 ─────────────────────────────────────────────────────────────────

    def pop_by_priority(
        self, priority: GapPriority, limit: int = 10
    ) -> List[GapSignal]:
        """
        取出指定优先级的 pending 信号，返回前 `limit` 条并将其状态置为
        processing（同时写回文件）。
        """
        if not GAP_QUEUE_FILE.exists():
            return []

        with _lock:
            all_items: list[dict] = []
            picked: list[dict] = []

            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if (
                        item.get("priority") == priority.value
                        and item.get("status") == "pending"
                        and len(picked) < limit
                    ):
                        item["status"] = "processing"
                        picked.append(item)
                    all_items.append(item)

            # 写回（先写临时文件再原子替换，防止写入中途崩溃丢数据）
            tmp = GAP_QUEUE_FILE.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                for item in all_items:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")
            tmp.replace(GAP_QUEUE_FILE)

            signals = [GapSignal.from_dict(p) for p in picked]
            if signals:
                logger.info(
                    "GapQueue.pop: priority=%s  取出 %d 条", priority.value, len(signals)
                )
            return signals

    # ── 状态更新 ─────────────────────────────────────────────────────────────

    def mark_done(self, gap_id: str, success: bool = True) -> None:
        """将指定 gap_id 的条目标记为 done 或 failed。"""
        new_status = "done" if success else "failed"
        processed_at = datetime.now(tz=timezone.utc).isoformat()
        self._update_fields(gap_id, status=new_status, processed_at=processed_at)

    def mark_retry(self, gap_id: str) -> None:
        """重置为 pending 并递增 retry_count（供外部错误处理使用）。"""
        with _lock:
            self._update_fields_locked(
                gap_id,
                status="pending",
                retry_count_inc=True,
            )

    def reset_stale_processing(self) -> int:
        """
        将所有 status="processing" 的条目重置为 "pending"，
        用于脚本重新启动时恢复上次未完成的任务。
        返回重置的条目数。
        """
        if not GAP_QUEUE_FILE.exists():
            return 0
        reset_count = 0
        with _lock:
            all_items: list[dict] = []
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("status") == "processing":
                        item["status"] = "pending"
                        reset_count += 1
                    all_items.append(item)
            if reset_count:
                tmp = GAP_QUEUE_FILE.with_suffix(".tmp")
                with open(tmp, "w", encoding="utf-8") as f:
                    for item in all_items:
                        f.write(json.dumps(item, ensure_ascii=False) + "\n")
                tmp.replace(GAP_QUEUE_FILE)
        if reset_count:
            logger.info("GapQueue.reset_stale: 重置 %d 条 processing→pending", reset_count)
        return reset_count

    def existing_ids(self) -> set:
        """返回队列中所有 gap_id 的集合（用于去重 push）。"""
        result: set = set()
        if not GAP_QUEUE_FILE.exists():
            return result
        with _lock:
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        gid = item.get("gap_id")
                        if gid:
                            result.add(gid)
                    except json.JSONDecodeError:
                        continue
        return result

    def existing_session_subs(self) -> set:
        """返回队列中所有 'session_id:root_cause_sub' 组合的集合。

        用于跨运行去重：即使重新运行 _scan_layer1_gaps.py，
        同一 session 内相同类型的缺口不会被二次入队。
        """
        result: set = set()
        if not GAP_QUEUE_FILE.exists():
            return result
        with _lock:
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        sid = item.get("session_id", "")
                        sub = item.get("root_cause_sub", "")
                        if sid and sub:
                            result.add(f"{sid}:{sub}")
                    except json.JSONDecodeError:
                        continue
        return result

    def existing_target_subs(self) -> set:
        """返回队列中所有 'target_service:root_cause_sub' 的集合（跨 session 去重用）。"""
        result: set = set()
        if not GAP_QUEUE_FILE.exists():
            return result
        with _lock:
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        tgt = item.get("target_service", "")
                        sub = item.get("root_cause_sub", "")
                        if tgt and sub:
                            result.add(f"{tgt}:{sub}")
                    except json.JSONDecodeError:
                        continue
        return result

    def push_static_remediation(self, record: dict) -> None:
        """将静态修复记录（ENV/BINARY_MISSING 等）追加到 static_remediations.jsonl。"""
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        record.setdefault("recorded_at", datetime.now(tz=timezone.utc).isoformat())
        with _lock:
            with open(STATIC_REMEDIATION_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        logger.debug("push_static_remediation: sub=%s  tool=%s",
                     record.get("sub"), record.get("tool_name"))

    def push_if_new(self, signal: GapSignal, known_ids: set | None = None) -> bool:
        """
        仅当 gap_id 不在队列中时才 push，避免重复入队。
        known_ids: 预先取出的 existing_ids() 集合（批量操作时传入可提速）。
        返回是否实际写入。
        """
        if known_ids is None:
            known_ids = self.existing_ids()
        if signal.gap_id in known_ids:
            return False
        self.push(signal)
        known_ids.add(signal.gap_id)  # 更新本地集合，避免同批次重复
        return True

    def _update_fields(self, gap_id: str, **kwargs) -> None:
        with _lock:
            self._update_fields_locked(gap_id, **kwargs)

    def _update_fields_locked(self, gap_id: str, retry_count_inc: bool = False, **kwargs) -> None:
        """必须在 _lock 持有期间调用。"""
        if not GAP_QUEUE_FILE.exists():
            return
        all_items: list[dict] = []
        with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("gap_id") == gap_id:
                    item.update(kwargs)
                    if retry_count_inc:
                        item["retry_count"] = item.get("retry_count", 0) + 1
                all_items.append(item)

        tmp = GAP_QUEUE_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for item in all_items:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        tmp.replace(GAP_QUEUE_FILE)

    # ── 查询 ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """返回各优先级/状态的统计数。"""
        counts: dict = {}
        if not GAP_QUEUE_FILE.exists():
            return counts
        with _lock:
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = f"{item.get('priority','?')}/{item.get('status','?')}"
                    counts[key] = counts.get(key, 0) + 1
        return counts

    def list_all(self) -> list[dict]:
        """返回队列中所有条目的原始字典（调试用）。"""
        if not GAP_QUEUE_FILE.exists():
            return []
        with _lock:
            items = []
            with open(GAP_QUEUE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return items
