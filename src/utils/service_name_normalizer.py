"""Shared service-name normalization utilities.

This module is intentionally deterministic and lightweight:
- No mandatory closed-world service enumeration.
- Optional alias mapping for project-local canonical names.
- Strip version/noise tokens to reduce cross-layer drift.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

_SERVICE_KEY_SANITIZE_RE = re.compile(r"[\[\]\(\),_/]+")
_SERVICE_INLINE_VERSION_RE = re.compile(
    r"\bv?\d+(?:\.(?:\d+|x)){0,5}[a-z0-9_-]*\b",
    re.IGNORECASE,
)
_SERVICE_VERSION_TAIL_RE = re.compile(
    r"(?:\s+v?\d+(?:\.\d+){0,5}[a-z0-9_-]*|\s+\d+\.x)+$",
    re.IGNORECASE,
)
_NOISE_SERVICE_KEYWORDS = re.compile(
    r"(?:\b(?:target|vulnerable|service|exploit|payload|attempted|target_|vulnerability)\b"
    r"|漏洞|服务|目标|存在|的)",
    re.IGNORECASE,
)
_ACRONYMS = {"http", "https", "ssh", "ssl", "tls", "rpc", "rce", "api", "sql", "db"}
_PLACEHOLDER_SERVICE_KEYS = {
    "raw",
    "validated",
    "consolidated",
    "consolidates",
    "active",
    "archived",
    "conflicted",
    "suspended",
    "unknown",
    "anysvc",
    "none",
    "null",
    "service",
    "target service",
}
_PLACEHOLDER_SERVICE_KEYS_COMPACT = {
    re.sub(r"[^a-z0-9]+", "", v) for v in _PLACEHOLDER_SERVICE_KEYS
}


def _is_placeholder_service_key(key: str) -> bool:
    compact = re.sub(r"[^a-z0-9]+", "", str(key or "").strip().lower())
    if not compact:
        return True
    if compact in _PLACEHOLDER_SERVICE_KEYS_COMPACT:
        return True
    if compact.startswith("consolidat") or compact.startswith("validat"):
        return True
    if compact.startswith("expconsolidated"):
        return True
    return False


def _canonicalize_service_key(raw: str) -> str:
    """Normalize service text to a lowercase key without version tails."""
    # 移除噪声关键字
    cleaned = _NOISE_SERVICE_KEYWORDS.sub(" ", str(raw).strip().lower())
    # 移除 CVE 这种标记
    cleaned = re.sub(r"cve[-\s]?\d{4}[-\s]?\d+", " ", cleaned, flags=re.IGNORECASE)

    key = _SERVICE_KEY_SANITIZE_RE.sub(" ", cleaned)
    key = re.sub(r"\b(?:version|ver)\b", " ", key)
    key = _SERVICE_INLINE_VERSION_RE.sub(" ", key)
    key = re.sub(r"\s+", " ", key).strip()

    prev = ""
    while key and key != prev:
        prev = key
        key = _SERVICE_VERSION_TAIL_RE.sub("", key).strip()
    return key


def _build_alias_candidates(key: str) -> list[str]:
    """Generate lightweight fallback candidates for alias lookup."""
    candidates = [key]
    if key.startswith("apache "):
        candidates.append(key[len("apache "):].strip())
    else:
        candidates.append(f"apache {key}")
    if key.endswith(" framework"):
        candidates.append(key[: -len(" framework")].strip())
    if key.endswith(" server"):
        candidates.append(key[: -len(" server")].strip())
    return candidates


def _format_service_display(key: str) -> str:
    """Convert normalized key into a human-readable canonical display."""
    words = []
    for token in key.split():
        low = token.lower()
        if low in _ACRONYMS:
            words.append(low.upper())
        elif len(token) <= 3 and token.isupper():
            words.append(token)
        else:
            words.append(token[0].upper() + token[1:] if token else token)
    return " ".join(words).strip()


def normalize_service_name(raw: str, aliases: Optional[Mapping[str, str]] = None) -> str:
    """Normalize service names across layers.

    Args:
        raw: Raw service text from LLM or extracted content.
        aliases: Optional lower-case alias map to canonical names.

    Returns:
        Canonical service name string (version stripped when possible).
    """
    if not raw:
        return ""

    display = re.sub(r"\s+", " ", str(raw)).strip()
    key = _canonicalize_service_key(display)
    if not key:
        return ""

    if _is_placeholder_service_key(key):
        return ""

    if aliases:
        seen = set()
        for cand in _build_alias_candidates(key):
            if not cand or cand in seen:
                continue
            seen.add(cand)
            mapped = aliases.get(cand)
            if mapped:
                mapped_name = str(mapped).strip()
                mapped_key = _canonicalize_service_key(mapped_name)
                if _is_placeholder_service_key(mapped_key):
                    return ""
                return mapped_name

    return _format_service_display(key) or display
