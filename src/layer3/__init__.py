"""
LORE Layer 3 — XPEC 经验融合框架
=======================================
Phase 1: Semantic Equivalence Clustering (SEC)  — sec.py
Phase 2: Evidence Weight Calculation    (EWC)  — ewc.py
Phase 3: Rule Merge Engine              (RME)  — rme.py
Phase 4: Bayesian Confidence Calibration(BCC)  — bcc.py
Phase 5: Knowledge Lifecycle Management (KLM)  — klm.py
"""

from .models import (
    EquivalenceSet,
    WeightedExperience,
    WeightedEquivalenceSet,
    Provenance,
    MergeResult,
    BccResult,
    ConsolidatedExp,
)
from .sec import cluster_experiences, summarize_clusters
from .ewc import weight_equivalence_sets, summarize_weights
from .rme import run_rme, merge_equivalence_set, summarize_merge_results
from .bcc import run_bcc, calibrate, build_consolidated_exp, summarize_bcc_results
from .klm import run_klm, summarize_klm_result, KlmResult

__all__ = [
    # models
    "EquivalenceSet",
    "WeightedExperience",
    "WeightedEquivalenceSet",
    "Provenance",
    "MergeResult",
    "BccResult",
    "ConsolidatedExp",
    # Phase 1
    "cluster_experiences",
    "summarize_clusters",
    # Phase 2
    "weight_equivalence_sets",
    "summarize_weights",
    # Phase 3
    "run_rme",
    "merge_equivalence_set",
    "summarize_merge_results",
    # Phase 4
    "run_bcc",
    "calibrate",
    "build_consolidated_exp",
    "summarize_bcc_results",
    # Phase 5
    "run_klm",
    "summarize_klm_result",
    "KlmResult",
]

