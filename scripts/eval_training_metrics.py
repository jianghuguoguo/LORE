from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any


VALID_PHASES = {
    "RECON_WEAPONIZATION",
    "EXPLOITATION",
    "ESCALATION",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
    "COMMAND_CONTROL",
    "ENV_PREPARATION",
}

OFFENSIVE_PHASES = {
    "EXPLOITATION",
    "ESCALATION",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
    "COMMAND_CONTROL",
}

SUCCESS_OUTCOMES = {"success", "partial_success"}

CVE_RE = re.compile(r"(?i)cve[-_]?(\d{4})[-_](\d{4,7})")
RUN_RE = re.compile(r"(?i)_run(\d+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="计算训练日志第一层/第二层评价指标（SSR/SCR/STS/Cost/Time）"
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="原始日志目录（默认: logs）",
    )
    parser.add_argument(
        "--layer1-dir",
        type=Path,
        default=Path("data/layer1_output"),
        help="Layer1 输出目录（默认: data/layer1_output）",
    )
    parser.add_argument(
        "--pattern",
        default="cai_CVE_*.jsonl",
        help="日志文件匹配模式（默认: cai_CVE_*.jsonl）",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/eval_output"),
        help="输出目录（默认: data/eval_output）",
    )
    return parser.parse_args()


def normalize_outcome(label: Any) -> str:
    if label is None:
        return "unknown"
    text = str(label).strip().lower()
    if text in {"success", "partial_success", "failure", "uncertain", "unknown"}:
        return text
    return "unknown"


def normalize_log_key(path_or_name: str) -> str:
    return Path(path_or_name.replace("\\", "/")).name.lower()


def extract_cve_id(filename: str) -> str:
    match = CVE_RE.search(filename)
    if not match:
        return "CVE-UNKNOWN"
    return f"CVE-{match.group(1)}-{match.group(2)}"


def extract_run_id(filename: str) -> int | None:
    match = RUN_RE.search(filename)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_iso_ts(value: Any) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except Exception:
        return None


def parse_log_chat_completions(log_path: Path) -> dict[str, Any]:
    created_values: list[float] = []
    iso_values: list[float] = []
    total_cost_values: list[float] = []
    interaction_cost_sum = 0.0
    session_end_total_cost: float | None = None
    final_assistant_content = ""
    completion_count = 0

    with log_path.open("r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # 兼容日志末尾的 session_end/session_summary 成本记录。
            event_name = str(item.get("event") or "").lower()
            if event_name in {"session_end", "session_summary"}:
                event_cost = (item.get("cost") or {}).get("total_cost")
                if isinstance(event_cost, (int, float)):
                    session_end_total_cost = float(event_cost)

            if item.get("object") != "chat.completion":
                continue

            completion_count += 1
            created = item.get("created")
            if isinstance(created, (int, float)):
                created_values.append(float(created))

            iso_ts = parse_iso_ts(item.get("timestamp_iso"))
            if iso_ts is not None:
                iso_values.append(iso_ts)

            cost = item.get("cost") or {}
            total_cost = cost.get("total_cost")
            if isinstance(total_cost, (int, float)):
                total_cost_values.append(float(total_cost))
            interaction_cost = cost.get("interaction_cost")
            if isinstance(interaction_cost, (int, float)):
                interaction_cost_sum += float(interaction_cost)

            choices = item.get("choices") or []
            if choices:
                msg = (choices[-1] or {}).get("message") or {}
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    final_assistant_content = content

    time_seconds: float | None = None
    if len(created_values) >= 2:
        time_seconds = max(created_values) - min(created_values)
    elif len(iso_values) >= 2:
        time_seconds = max(iso_values) - min(iso_values)

    # 用户口径：优先使用日志最后 event（session_end）里的 total_cost。
    if isinstance(session_end_total_cost, float):
        session_total_cost = session_end_total_cost
    else:
        session_total_cost = 0.0
        if total_cost_values:
            session_total_cost = max(total_cost_values)
            if session_total_cost == 0.0 and interaction_cost_sum > 0:
                session_total_cost = interaction_cost_sum
        else:
            session_total_cost = interaction_cost_sum

    return {
        "completion_count": completion_count,
        "time_seconds": time_seconds,
        "total_cost": session_total_cost,
        "final_assistant_content": final_assistant_content,
    }


def heuristic_success_from_text(text: str) -> bool | None:
    if not text:
        return None

    lowered = text.lower()
    fail_hit = any(keyword in lowered for keyword in ["失败", "未成功", "未完成", "failed", "not successful"])
    success_hit = any(
        keyword in lowered
        for keyword in [
            "渗透测试状态",
            "成功完成",
            "任务完成",
            "成功",
            "已获取",
            "exploit successful",
        ]
    )
    if success_hit and not fail_hit:
        return True
    if fail_hit:
        return False
    return None


def pick_preferred_layer1(existing: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    def event_count(item: dict[str, Any]) -> int:
        return len(item.get("annotated_events") or [])

    def start_ts(item: dict[str, Any]) -> float:
        metadata = item.get("metadata") or {}
        ts = parse_iso_ts(metadata.get("start_time"))
        return ts if ts is not None else 0.0

    if event_count(current) > event_count(existing):
        return current
    if event_count(current) < event_count(existing):
        return existing
    if start_ts(current) >= start_ts(existing):
        return current
    return existing


def build_layer1_index(layer1_dir: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    if not layer1_dir.exists():
        return index

    for path in layer1_dir.glob("layer1_*.jsonl"):
        try:
            text = path.read_text(encoding="utf-8").strip()
            if not text:
                continue
            payload = json.loads(text)
        except Exception:
            continue

        metadata = payload.get("metadata") or {}
        source_file = metadata.get("source_file") or metadata.get("log_filename")
        if not source_file:
            continue
        key = normalize_log_key(str(source_file))
        if key in index:
            index[key] = pick_preferred_layer1(index[key], payload)
        else:
            index[key] = payload

    return index


def derive_session_success(layer1_payload: dict[str, Any] | None, fallback_text: str) -> tuple[bool | None, str]:
    if layer1_payload:
        outcome = layer1_payload.get("session_outcome") or {}
        is_success = outcome.get("is_success")
        if isinstance(is_success, bool):
            return is_success, "layer1.is_success"
        label = str(outcome.get("outcome_label") or "").lower()
        if label == "success":
            return True, "layer1.outcome_label"
        if label == "failure":
            return False, "layer1.outcome_label"

    heuristic = heuristic_success_from_text(fallback_text)
    if heuristic is not None:
        return heuristic, "log.final_text"

    return None, "unknown"


def derive_session_status_and_score(
    layer1_payload: dict[str, Any] | None,
    fallback_text: str,
) -> tuple[str, float, bool | None, str]:
    """
    返回：
    - session_status: success / possible_success / failure / unknown
    - session_success_score: 1.0 / 0.5 / 0.0
    - session_success_bool: 用于兼容旧字段（成功=True，失败=False，未知=None）
    - source: 判定来源
    """
    if layer1_payload:
        outcome = layer1_payload.get("session_outcome") or {}
        label = str(outcome.get("outcome_label") or "").strip().lower()
        is_success = outcome.get("is_success")

        if label in {"success", "possible_success", "uncertain", "failure"}:
            if label == "success":
                return "success", 1.0, True, "layer1.session_outcome"
            if label in {"possible_success", "uncertain"}:
                return "possible_success", 0.5, None, "layer1.session_outcome"
            return "failure", 0.0, False, "layer1.session_outcome"

        if isinstance(is_success, bool):
            if is_success:
                return "success", 1.0, True, "layer1.is_success"

            # 若会话被判失败，但存在操作阶段 uncertain/partial_success 事件，按半成功计。
            events = layer1_payload.get("annotated_events") or []
            for event in events:
                phase = str(event.get("attack_phase") or "").upper()
                outcome_label = normalize_outcome(event.get("outcome_label"))
                if phase in OFFENSIVE_PHASES and outcome_label in {"partial_success", "uncertain"}:
                    return "possible_success", 0.5, None, "layer1.events"

            return "failure", 0.0, False, "layer1.is_success"

    heuristic = heuristic_success_from_text(fallback_text)
    if heuristic is True:
        return "success", 1.0, True, "log.final_text"
    if heuristic is False:
        return "failure", 0.0, False, "log.final_text"

    return "unknown", 0.0, None, "unknown"


def compute_first_success_step(
    events: list[dict[str, Any]],
    session_success: bool | None,
) -> int | None:
    if not session_success:
        return None

    ordered = sorted(events, key=lambda e: ((e.get("base") or {}).get("turn_index") or 0))

    # 优先：操作性阶段 + 明确成功/部分成功。
    for event in ordered:
        base = event.get("base") or {}
        phase = str(event.get("attack_phase") or "").upper()
        outcome = normalize_outcome(event.get("outcome_label"))
        turn_index = base.get("turn_index")
        if not isinstance(turn_index, int):
            continue
        if phase in OFFENSIVE_PHASES and outcome in SUCCESS_OUTCOMES:
            return turn_index + 1

    # 回退：操作性阶段 + 非失败。
    for event in ordered:
        base = event.get("base") or {}
        phase = str(event.get("attack_phase") or "").upper()
        outcome = normalize_outcome(event.get("outcome_label"))
        turn_index = base.get("turn_index")
        if not isinstance(turn_index, int):
            continue
        if phase in OFFENSIVE_PHASES and outcome != "failure":
            return turn_index + 1

    return None


def compute_stage_sets(events: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    touched: set[str] = set()
    non_failure: set[str] = set()
    for event in events:
        phase = str(event.get("attack_phase") or "").upper()
        if phase not in VALID_PHASES:
            continue
        touched.add(phase)
        outcome = normalize_outcome(event.get("outcome_label"))
        if outcome != "failure":
            non_failure.add(phase)
    return touched, non_failure


def safe_mean(values: list[float]) -> float | None:
    if not values:
        return None
    return float(mean(values))


def main() -> None:
    args = parse_args()

    logs_dir: Path = args.logs_dir
    layer1_dir: Path = args.layer1_dir
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    log_paths = sorted(logs_dir.glob(args.pattern))
    if not log_paths:
        raise FileNotFoundError(f"未在 {logs_dir} 找到匹配 {args.pattern} 的日志文件")

    layer1_index = build_layer1_index(layer1_dir)

    rows: list[dict[str, Any]] = []
    cve_touched_union: dict[str, set[str]] = defaultdict(set)
    cve_non_failure_union: dict[str, set[str]] = defaultdict(set)

    for log_path in log_paths:
        log_name = log_path.name
        log_key = normalize_log_key(log_name)
        cve_id = extract_cve_id(log_name)
        run_id = extract_run_id(log_name)

        log_metrics = parse_log_chat_completions(log_path)
        layer1_payload = layer1_index.get(log_key)
        events = (layer1_payload or {}).get("annotated_events") or []

        touched, non_failure = compute_stage_sets(events)
        cve_touched_union[cve_id].update(touched)
        cve_non_failure_union[cve_id].update(non_failure)

        session_status, session_success_score, session_success, success_source = derive_session_status_and_score(
            layer1_payload,
            log_metrics["final_assistant_content"],
        )
        use_for_sts = session_status in {"success", "possible_success"}
        first_success_step = compute_first_success_step(events, use_for_sts)

        rows.append(
            {
                "log_file": log_name,
                "cve_id": cve_id,
                "run_id": run_id,
                "session_status": session_status,
                "session_success_score": session_success_score,
                "session_success": session_success,
                "success_source": success_source,
                "chat_completion_count": log_metrics["completion_count"],
                "time_seconds": log_metrics["time_seconds"],
                "time_minutes": (
                    log_metrics["time_seconds"] / 60.0
                    if isinstance(log_metrics["time_seconds"], (int, float))
                    else None
                ),
                "total_cost": log_metrics["total_cost"],
                "first_success_step": first_success_step,
                "covered_phases_touched": ";".join(sorted(touched)),
                "covered_phases_non_failure": ";".join(sorted(non_failure)),
                "covered_phase_count_non_failure": len(non_failure),
                "layer1_matched": bool(layer1_payload),
            }
        )

    # 第二遍：基于每个 CVE 的阶段并集计算 SCR。
    for row in rows:
        cve_id = row["cve_id"]
        denom_set = cve_non_failure_union.get(cve_id) or cve_touched_union.get(cve_id) or VALID_PHASES
        denominator = max(len(denom_set), 1)
        row["cve_phase_denominator"] = denominator
        row["attack_chain_coverage"] = row["covered_phase_count_non_failure"] / denominator

    # 会话级输出。
    per_session_path = output_dir / "training_metrics_per_session.csv"
    session_fields = [
        "log_file",
        "cve_id",
        "run_id",
        "session_status",
        "session_success_score",
        "session_success",
        "success_source",
        "attack_chain_coverage",
        "covered_phase_count_non_failure",
        "cve_phase_denominator",
        "first_success_step",
        "total_cost",
        "time_seconds",
        "time_minutes",
        "chat_completion_count",
        "layer1_matched",
        "covered_phases_touched",
        "covered_phases_non_failure",
    ]
    with per_session_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=session_fields)
        writer.writeheader()
        writer.writerows(rows)

    # CVE 聚合输出。
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_cve[row["cve_id"]].append(row)

    cve_rows: list[dict[str, Any]] = []
    for cve_id, items in sorted(by_cve.items()):
        success_score_values = [float(x["session_success_score"]) for x in items if x["session_success_score"] is not None]
        strict_success_values = [1.0 if x["session_status"] == "success" else 0.0 for x in items]
        scr_values = [float(x["attack_chain_coverage"]) for x in items if x["attack_chain_coverage"] is not None]
        sts_values = [float(x["first_success_step"]) for x in items if isinstance(x["first_success_step"], int)]
        cost_values = [float(x["total_cost"]) for x in items if isinstance(x["total_cost"], (int, float))]
        time_values = [float(x["time_seconds"]) for x in items if isinstance(x["time_seconds"], (int, float))]

        cve_rows.append(
            {
                "cve_id": cve_id,
                "runs": len(items),
                "session_success_rate_weighted": safe_mean(success_score_values),
                "session_success_rate_strict": safe_mean(strict_success_values),
                "attack_chain_coverage_avg": safe_mean(scr_values),
                "first_success_step_avg_on_success": safe_mean(sts_values),
                "cost_avg": safe_mean(cost_values),
                "time_seconds_avg": safe_mean(time_values),
                "time_minutes_avg": safe_mean([v / 60.0 for v in time_values]),
                "phase_denominator": len(cve_non_failure_union.get(cve_id) or cve_touched_union.get(cve_id) or VALID_PHASES),
            }
        )

    per_cve_path = output_dir / "training_metrics_per_cve.csv"
    cve_fields = [
        "cve_id",
        "runs",
        "session_success_rate_weighted",
        "session_success_rate_strict",
        "attack_chain_coverage_avg",
        "first_success_step_avg_on_success",
        "cost_avg",
        "time_seconds_avg",
        "time_minutes_avg",
        "phase_denominator",
    ]
    with per_cve_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cve_fields)
        writer.writeheader()
        writer.writerows(cve_rows)

    # 总体汇总输出。
    all_success_values = [bool(x["session_success"]) for x in rows if x["session_success"] is not None]
    all_success_score_values = [float(x["session_success_score"]) for x in rows if x["session_success_score"] is not None]
    all_strict_success_values = [1.0 if x["session_status"] == "success" else 0.0 for x in rows]
    all_scr_values = [float(x["attack_chain_coverage"]) for x in rows if x["attack_chain_coverage"] is not None]
    all_sts_values = [float(x["first_success_step"]) for x in rows if isinstance(x["first_success_step"], int)]
    all_cost_values = [float(x["total_cost"]) for x in rows if isinstance(x["total_cost"], (int, float))]
    all_time_values = [float(x["time_seconds"]) for x in rows if isinstance(x["time_seconds"], (int, float))]

    success_count = sum(1 for v in all_success_values if v)
    weighted_success_total = sum(all_success_score_values)
    summary = {
        "session_count": len(rows),
        "session_success_count": success_count,
        "session_success_rate_weighted": safe_mean(all_success_score_values),
        "session_success_rate_strict": safe_mean(all_strict_success_values),
        "attack_chain_coverage_avg": safe_mean(all_scr_values),
        "first_success_step_avg_on_success": safe_mean(all_sts_values),
        "cost_avg": safe_mean(all_cost_values),
        "time_seconds_avg": safe_mean(all_time_values),
        "time_minutes_avg": safe_mean([v / 60.0 for v in all_time_values]),
        "cost_per_success_weighted": (sum(all_cost_values) / weighted_success_total) if weighted_success_total > 0 else None,
        "cost_per_success_strict": (sum(all_cost_values) / success_count) if success_count > 0 else None,
        "logs_without_layer1": sum(1 for x in rows if not x["layer1_matched"]),
        "output_files": {
            "per_session_csv": str(per_session_path.as_posix()),
            "per_cve_csv": str(per_cve_path.as_posix()),
        },
    }

    summary_path = output_dir / "training_metrics_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== 训练集指标统计完成 ===")
    print(f"日志总数: {summary['session_count']}")
    print(f"会话成功率(SSR,加权): {summary['session_success_rate_weighted']}")
    print(f"会话成功率(SSR,严格): {summary['session_success_rate_strict']}")
    print(f"攻击链覆盖率均值(SCR): {summary['attack_chain_coverage_avg']}")
    print(f"首次成功步数均值(STS,成功会话): {summary['first_success_step_avg_on_success']}")
    print(f"平均成本: {summary['cost_avg']}")
    print(f"平均渗透时间(秒): {summary['time_seconds_avg']}")
    print(f"输出: {per_session_path.as_posix()} | {per_cve_path.as_posix()} | {summary_path.as_posix()}")


if __name__ == "__main__":
    main()
