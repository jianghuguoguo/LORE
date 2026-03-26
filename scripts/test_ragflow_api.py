"""
Retrieval-only RAGFlow API smoke test.

This script does NOT upload any document. It only checks:
1) dataset listing endpoint
2) retrieval endpoint

Usage:
    python scripts/test_ragflow_api.py
    python scripts/test_ragflow_api.py --query "CVE-2019-0193" --top-k 5
    python scripts/test_ragflow_api.py --dataset-id <dataset_id>
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List

import requests

# Ensure workspace root is importable when running as a script.
sys.path.append(os.getcwd())

from src.ragflow.client import RAGFlowExpClient

_DEFAULT_QUERIES: List[str] = ["CVE", "漏洞", "exploit", "RCE"]


def _compact(value: Any, max_len: int = 140) -> str:
    text = " ".join(str(value).split())
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _resolve_queries(cli_query: str) -> List[str]:
    if (cli_query or "").strip():
        return [cli_query.strip()]

    env_query = os.environ.get("RAGFLOW_TEST_QUERY", "").strip()
    if env_query:
        return [env_query]

    return _DEFAULT_QUERIES


def _extract_dataset_items(raw_data: Any) -> List[Dict[str, Any]]:
    if isinstance(raw_data, list):
        return [d for d in raw_data if isinstance(d, dict)]

    if isinstance(raw_data, dict):
        for key in ("datasets", "items", "docs"):
            value = raw_data.get(key)
            if isinstance(value, list):
                return [d for d in value if isinstance(d, dict)]

    return []


def run_retrieval_test(query: str, dataset_id: str, top_k: int) -> int:
    client = RAGFlowExpClient()
    headers = client._headers()

    datasets_url = client.api_url("/datasets")
    retrieval_url = client.api_url("/retrieval")

    print(f"Base URL (normalized): {client.base_url}")
    print(f"Datasets endpoint: {datasets_url}")
    print(f"Retrieval endpoint: {retrieval_url}")

    if dataset_id:
        datasets = [{"id": dataset_id, "name": "user_specified"}]
        print(f"Dataset scope: only {dataset_id}")
    else:
        print("Fetching available datasets...")
        ds_resp = requests.get(datasets_url, headers=headers, timeout=20)
        print(f"Datasets HTTP status: {ds_resp.status_code}")

        if ds_resp.status_code != 200:
            print(f"Datasets request failed: {ds_resp.text}")
            return 1

        ds_data = ds_resp.json() if ds_resp.content else {}
        print(f"Datasets API code: {ds_data.get('code')}")

        if ds_data.get("code") != 0:
            print(f"Datasets API message: {ds_data.get('message')}")
            return 1

        datasets = _extract_dataset_items(ds_data.get("data"))
        datasets = [d for d in datasets if str(d.get("id", "")).strip()]
        print(f"Accessible datasets: {len(datasets)}")

        if not datasets:
            print("No accessible datasets found.")
            return 1

    queries = _resolve_queries(query)
    print(f"Queries to test: {queries}")

    hit_count = 0
    for ds in datasets:
        ds_id = str(ds.get("id", "")).strip()
        ds_name = str(ds.get("name", "")).strip() or "(unnamed)"

        if not ds_id:
            continue

        print(f"\nTesting dataset: {ds_name} ({ds_id})")

        for q in queries:
            payload = {
                "question": q,
                "dataset_ids": [ds_id],
                "datasets": [ds_id],
                "top_k": int(top_k),
                "page": 1,
                "page_size": int(top_k),
                "similarity_threshold": 0.0,
                "vector_similarity_weight": 0.3,
            }

            try:
                ret_resp = requests.post(
                    retrieval_url,
                    headers={**headers, "Content-Type": "application/json"},
                    json=payload,
                    timeout=20,
                )
            except requests.RequestException as exc:
                print(f"  request error: {_compact(exc)}")
                continue
            print(f"  query='{q}' -> HTTP {ret_resp.status_code}")

            if ret_resp.status_code != 200:
                print(f"  retrieval failed: {_compact(ret_resp.text, 220)}")
                continue

            ret_data = ret_resp.json() if ret_resp.content else {}
            ret_code = ret_data.get("code")
            print(f"  API code: {ret_code}")

            if ret_code != 0:
                print(f"  API message: {_compact(ret_data.get('message', ''), 220)}")
                continue

            chunks = ret_data.get("data", {}).get("chunks", [])
            print(f"  chunks: {len(chunks)}")
            if chunks:
                first_chunk = chunks[0]
                preview = (
                    first_chunk.get("content_with_weight")
                    or first_chunk.get("content")
                    or first_chunk
                )
                print(f"  first_chunk_preview: {_compact(preview)}")
                hit_count += 1
                print(f"\nRetrieval test PASSED: dataset '{ds_name}' returned chunks.")
                return 0

    print("\nRetrieval test FAILED: no dataset returned chunks for all tested queries.")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrieval-only RAGFlow API test")
    parser.add_argument("--query", default="", help="single query to test (default: built-in fallback queries)")
    parser.add_argument("--dataset-id", default="", help="optional dataset id; when set, only test this dataset")
    parser.add_argument("--top-k", type=int, default=3, help="retrieval top_k/page_size")
    args = parser.parse_args()

    top_k = max(1, int(args.top_k))
    return run_retrieval_test(query=args.query, dataset_id=args.dataset_id, top_k=top_k)


if __name__ == "__main__":
    raise SystemExit(main())
