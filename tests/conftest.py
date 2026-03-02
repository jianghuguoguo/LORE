"""
pytest 配置与共享 fixture
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List

import pytest

from tests.fixtures.make_fixtures import (
    make_failure_session_jsonl,
    make_full_session_jsonl,
    make_minimal_session_jsonl,
)


@pytest.fixture(scope="session")
def fixture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """创建临时目录并写入所有 fixture JSONL 文件。"""
    d = tmp_path_factory.mktemp("fixtures")
    _write(d / "cai_full.jsonl", make_full_session_jsonl())
    _write(d / "cai_empty.jsonl", make_minimal_session_jsonl())
    _write(d / "cai_failure.jsonl", make_failure_session_jsonl())
    return d


@pytest.fixture(scope="session")
def full_log_path(fixture_dir: Path) -> Path:
    return fixture_dir / "cai_full.jsonl"


@pytest.fixture(scope="session")
def empty_log_path(fixture_dir: Path) -> Path:
    return fixture_dir / "cai_empty.jsonl"


@pytest.fixture(scope="session")
def failure_log_path(fixture_dir: Path) -> Path:
    return fixture_dir / "cai_failure.jsonl"


def _write(path: Path, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
