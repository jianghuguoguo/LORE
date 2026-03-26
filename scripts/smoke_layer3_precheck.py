from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from src.layer1.pipeline import load_annotated_turn_sequence
from src.layer2.pipeline import run_layer2
from src.layer2.serializer import experience_to_dict
from src.layer3 import cluster_experiences, run_bcc, run_klm, run_rme, weight_equivalence_sets


DEFAULT_PRIORITY_SESSION_PREFIXES = [
    "2e36e67c",
    "ad44e7ec",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Layer3 smoke precheck on a small Layer1 sample set")
    parser.add_argument(
        "--layer1-dir",
        type=Path,
        default=Path("data/layer1_output"),
        help="Layer1 directory (default: data/layer1_output)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=12,
        help="How many Layer1 sessions to sample (default: 12)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/layer3_output/smoke_precheck_report.json"),
        help="Output JSON report path",
    )
    return parser.parse_args()


def _session_id_from_path(path: Path) -> str:
    stem = path.stem
    if stem.startswith("layer1_"):
        return stem[len("layer1_") :]
    return stem


def pick_layer1_files(layer1_dir: Path, sample_size: int) -> List[Path]:
    candidates = sorted(layer1_dir.glob("layer1_*.jsonl"))
    if not candidates:
        return []

    priority: List[Path] = []
    regular: List[Path] = []
    for path in candidates:
        sid = _session_id_from_path(path).lower()
        if any(sid.startswith(prefix) for prefix in DEFAULT_PRIORITY_SESSION_PREFIXES):
            priority.append(path)
        else:
            regular.append(path)

    selected = priority + regular
    return selected[: max(1, sample_size)]


def _factual_shell_like(content: Dict[str, Any]) -> bool:
    cve_ids = [str(c).strip() for c in content.get("cve_ids", []) if str(c).strip()]
    if cve_ids:
        return False

    facts = content.get("discovered_facts", [])
    if not isinstance(facts, list):
        return True

    for fact in facts:
        if not isinstance(fact, dict):
            continue
        key = str(fact.get("key", "")).lower()
        value = str(fact.get("value", "")).strip()
        if value and ("version" in key or "cve" in key):
            return False
    return True


def run_smoke(layer1_files: List[Path]) -> Dict[str, Any]:
    all_exps: List[Dict[str, Any]] = []
    per_session: List[Dict[str, Any]] = []

    for path in layer1_files:
        ann_seq = load_annotated_turn_sequence(path)
        bundle = run_layer2(ann_seq, client=None, save=False)

        exp_dicts = [experience_to_dict(exp) for exp in bundle.experiences]
        all_exps.extend(exp_dicts)

        layer_counter = Counter(e.get("knowledge_layer", "UNKNOWN") for e in exp_dicts)
        per_session.append(
            {
                "session_id": bundle.session_id,
                "total_exps": len(exp_dicts),
                "layers": dict(layer_counter),
            }
        )

    layer_counter_all = Counter(e.get("knowledge_layer", "UNKNOWN") for e in all_exps)
    pneg_all = [e for e in all_exps if e.get("knowledge_layer") == "PROCEDURAL_NEG"]
    ppos_all = [e for e in all_exps if e.get("knowledge_layer") == "PROCEDURAL_POS"]

    neg_source_missing = sum(
        1
        for e in pneg_all
        if "decision_rule_source" not in (e.get("content") or {})
    )

    raw_neg_subdims = {
        str((e.get("content") or {}).get("failure_sub_dimension", "")).strip().upper()
        for e in pneg_all
        if str((e.get("content") or {}).get("failure_sub_dimension", "")).strip()
    }

    clusters = cluster_experiences(all_exps)
    pneg_clusters = [c for c in clusters if c.knowledge_layer == "PROCEDURAL_NEG"]
    pneg_cluster_subdims = {
        str(c.failure_sub_dim).split("::")[0]
        for c in pneg_clusters
        if str(c.failure_sub_dim).strip()
    }

    wes_list = weight_equivalence_sets(clusters)
    merge_results = run_rme(wes_list)
    wes_map = {wes.cluster.cluster_id: wes for wes in wes_list}
    _, consolidated_exps = run_bcc(merge_results, wes_map)

    exp_map = {e.get("exp_id", ""): e for e in all_exps if e.get("exp_id")}
    _, _, reflux_ready = run_klm(consolidated_exps, exp_map)

    pneg_merges = [m for m in merge_results if m.knowledge_layer == "PROCEDURAL_NEG"]
    factual_merges = [m for m in merge_results if m.knowledge_layer == "FACTUAL"]

    factual_shell_merge_count = sum(
        1 for m in factual_merges if _factual_shell_like(m.fused_content)
    )

    pneg_merge_with_source_breakdown = sum(
        1
        for m in pneg_merges
        if isinstance(m.fused_content.get("decision_rule_source_breakdown"), dict)
        and bool(m.fused_content.get("decision_rule_source_breakdown"))
    )

    checks = {
        "has_procedural_pos_in_layer2": len(ppos_all) > 0,
        "all_pneg_have_decision_rule_source": neg_source_missing == 0,
        "factual_shell_filtered_in_rme": factual_shell_merge_count == 0,
        "pneg_merge_source_breakdown_visible": (
            pneg_merge_with_source_breakdown > 0 if pneg_merges else False
        ),
        "sec_fragmentation_reduced": len(pneg_cluster_subdims) <= len(raw_neg_subdims),
    }

    return {
        "sample_session_count": len(layer1_files),
        "sample_sessions": [_session_id_from_path(p) for p in layer1_files],
        "layer2_total_exps": len(all_exps),
        "layer2_layers": dict(layer_counter_all),
        "layer2_per_session": per_session,
        "layer2_procedural_pos_count": len(ppos_all),
        "layer2_procedural_neg_count": len(pneg_all),
        "layer2_pneg_decision_rule_source_missing": neg_source_missing,
        "sec_pneg_cluster_count": len(pneg_clusters),
        "sec_pneg_singleton_count": sum(1 for c in pneg_clusters if len(c.experiences) == 1),
        "sec_raw_neg_subdim_unique": len(raw_neg_subdims),
        "sec_clustered_neg_subdim_unique": len(pneg_cluster_subdims),
        "rme_total_merges": len(merge_results),
        "rme_pneg_merges": len(pneg_merges),
        "rme_pneg_merge_with_source_breakdown": pneg_merge_with_source_breakdown,
        "rme_factual_merges": len(factual_merges),
        "rme_factual_shell_merge_count": factual_shell_merge_count,
        "phase34_consolidated_count": len(consolidated_exps),
        "phase34_procedural_pos_count": sum(1 for c in consolidated_exps if c.knowledge_layer == "PROCEDURAL_POS"),
        "phase5_reflux_ready_count": len(reflux_ready),
        "phase5_procedural_pos_count": sum(1 for r in reflux_ready if r.get("knowledge_layer") == "PROCEDURAL_POS"),
        "checks": checks,
        "all_checks_passed": all(checks.values()),
    }


def main() -> None:
    args = parse_args()
    layer1_files = pick_layer1_files(args.layer1_dir, args.sample_size)
    if not layer1_files:
        raise FileNotFoundError(f"No layer1_*.jsonl found in {args.layer1_dir}")

    report = run_smoke(layer1_files)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=== Layer3 Smoke Precheck Done ===")
    print(f"report: {args.output.as_posix()}")
    print(f"all_checks_passed: {report['all_checks_passed']}")
    print("checks:")
    for key, value in report["checks"].items():
        print(f"  - {key}: {value}")


if __name__ == "__main__":
    main()
