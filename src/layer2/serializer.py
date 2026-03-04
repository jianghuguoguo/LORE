"""
Layer 2 序列化工具
==================
负责 ExperienceBundle 的 JSON 序列化和反序列化，
以及与 JSONL 文件系统的读写。

输出格式（JSONL）：
  - data/layer2_output/{session_id}/experiences.jsonl
    每行一条 Experience 的 JSON（顺序写入）
  - data/layer2_output/{session_id}/bundle_meta.json
    ExperienceBundle 的聚合元数据

  - data/layer2_output/experience_raw.jsonl
    全量 raw 经验库（追加写入，供 Layer 3 消费）
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .experience_models import (
    Experience,
    ExperienceBundle,
    ExperienceMaturity,
    ExperienceMetadata,
    ExperienceSource,
    KnowledgeLayer,
)


# ─────────────────────────────────────────────────────────────────────────────
# 序列化工具函数
# ─────────────────────────────────────────────────────────────────────────────

def _to_dict(obj: Any) -> Any:
    """递归将 dataclass / enum / datetime 转为可 JSON 序列化对象。"""
    from dataclasses import fields, is_dataclass
    from enum import Enum

    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_dict(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def experience_to_dict(exp: Experience) -> Dict[str, Any]:
    """将单条 Experience 转为 JSON 可序列化字典。

    后处理：去除 metadata.applicable_constraints 为空字典的噪声字段。
    FACTUAL/PROCEDURAL 会填充该字段；METACOGNITIVE/CONCEPTUAL 默认为 {} 无意义。
    """
    d = _to_dict(exp)
    meta = d.get("metadata", {})
    if meta.get("applicable_constraints") == {}:
        meta.pop("applicable_constraints", None)
    return d


# ── 用于 RAG 向量化的文本表示 ─────────────────────────────────────────────────

_RAG_EXCLUDE_META_KEYS = frozenset({
    "source_event_ids",
    "source_turn_indices",
})


def experience_to_rag_text(exp: Experience) -> str:
    """生成用于 RAG 向量化的纯文本表示。

    规则：
    - 保留所有 content 字段（语义核心）
    - 从 metadata 中排除 source_event_ids / source_turn_indices
      （这两个字段是溯源辅助信息，不应出现在 embedding 文本中，
       会增加噪声并稀释语义相似度）
    - metadata 中保留：source_session_id、extraction_source、session_outcome、
      target_raw、tags、applicable_constraints（若非空）
    """
    d = experience_to_dict(exp)
    # 清理 metadata 中的溯源字段
    meta_clean = {k: v for k, v in d.get("metadata", {}).items()
                  if k not in _RAG_EXCLUDE_META_KEYS}
    rag_dict = {
        "exp_id": d.get("exp_id"),
        "knowledge_layer": d.get("knowledge_layer"),
        "content": d.get("content"),
        "metadata": meta_clean,
        "confidence": d.get("confidence"),
    }
    return json.dumps(rag_dict, ensure_ascii=False)


def _parse_datetime_safe(value: Optional[str]) -> datetime:
    """安全解析 ISO 时间字符串，失败时返回 epoch。"""
    if not value:
        return datetime.utcfromtimestamp(0)
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.utcfromtimestamp(0)


def dict_to_experience(d: Dict[str, Any]) -> Experience:
    """从字典反序列化单条 Experience。"""
    meta_d = d.get("metadata", {})
    meta_ac = meta_d.get("applicable_constraints")
    if not isinstance(meta_ac, dict):
        meta_ac = {}
    metadata = ExperienceMetadata(
        source_session_id=meta_d.get("source_session_id", ""),
        source_event_ids=meta_d.get("source_event_ids", []),
        source_turn_indices=meta_d.get("source_turn_indices", []),
        extraction_source=ExperienceSource(meta_d.get("extraction_source", "rule")),
        session_outcome=meta_d.get("session_outcome", "unknown"),
        target_raw=meta_d.get("target_raw"),
        created_at=_parse_datetime_safe(meta_d.get("created_at")),
        extractor_version=meta_d.get("extractor_version", "1.0.0"),
        tags=meta_d.get("tags", []),
        applicable_constraints=meta_ac,
    )

    return Experience(
        exp_id=d.get("exp_id", ""),
        knowledge_layer=KnowledgeLayer(d.get("knowledge_layer", "FACTUAL")),
        content=d.get("content", {}),
        metadata=metadata,
        maturity=ExperienceMaturity(d.get("maturity", "raw")),
        confidence=float(d.get("confidence", 0.7)),
        content_hash=d.get("content_hash"),
        merged_into=d.get("merged_into"),
        refluxed=bool(d.get("refluxed", False)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 文件 I/O
# ─────────────────────────────────────────────────────────────────────────────

def save_experience_bundle(
    bundle: ExperienceBundle,
    output_dir: Path,
    append_to_global_raw: bool = True,
) -> None:
    """将 ExperienceBundle 保存到磁盘。

    目录结构：
        output_dir/
            {session_id}/
                experiences.jsonl   ← 逐条写入（每行一条 Experience）
        output_dir/
            experience_raw.jsonl   ← 全局 raw 库（追加写入）

    Args:
        bundle                : 要保存的 ExperienceBundle
        output_dir            : layer2_output 目录
        append_to_global_raw  : 是否追加写入到全局 raw 库
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. 会话级目录
    session_dir = output_dir / bundle.session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    # 2. 逐条写入 experiences.jsonl
    exp_path = session_dir / "experiences.jsonl"
    with open(exp_path, "w", encoding="utf-8") as f:
        for exp in bundle.experiences:
            f.write(json.dumps(experience_to_dict(exp), ensure_ascii=False))
            f.write("\n")

    # 3. 全局 raw 库追加写入（跳过跨 session 去重标记的经验）
    if append_to_global_raw and bundle.experiences:
        global_raw_path = output_dir / "experience_raw.jsonl"
        with open(global_raw_path, "a", encoding="utf-8") as f:
            for exp in bundle.experiences:
                # P1 META 去重: 跨 session 被标记为重复的经验不写入全局 raw
                if exp.merged_into == "deduped_cross_session_meta":
                    continue
                f.write(json.dumps(experience_to_dict(exp), ensure_ascii=False))
                f.write("\n")


def load_experience_bundle(session_dir: Path) -> ExperienceBundle:
    """从会话目录反序列化 ExperienceBundle。

    Args:
        session_dir : layer2_output/{session_id}/ 目录

    Returns:
        ExperienceBundle 实例
    """
    session_id = session_dir.name

    # 加载经验条目
    exp_path = session_dir / "experiences.jsonl"
    experiences: List[Experience] = []
    if exp_path.exists():
        with open(exp_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        d = json.loads(line)
                        experiences.append(dict_to_experience(d))
                    except Exception:
                        pass  # 跳过损坏的行

    bundle = ExperienceBundle(
        session_id=session_id,
        experiences=experiences,
        session_outcome="unknown",
        target_raw=None,
    )
    return bundle


def load_all_raw_experiences(output_dir: Path) -> List[Experience]:
    """从全局 experience_raw.jsonl 加载所有 raw 经验条目。

    Args:
        output_dir : layer2_output 目录

    Returns:
        所有 raw 经验条目列表（不去重）
    """
    global_raw_path = output_dir / "experience_raw.jsonl"
    if not global_raw_path.exists():
        return []

    experiences: List[Experience] = []
    with open(global_raw_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    d = json.loads(line)
                    experiences.append(dict_to_experience(d))
                except Exception:
                    pass
    return experiences


def iter_session_bundles(output_dir: Path) -> Iterator[ExperienceBundle]:
    """迭代 output_dir 下所有已保存的 ExperienceBundle。"""
    for session_dir in sorted(output_dir.iterdir()):
        if session_dir.is_dir() and (session_dir / "experiences.jsonl").exists():
            yield load_experience_bundle(session_dir)
