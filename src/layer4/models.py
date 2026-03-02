# src/layer4/models.py
"""
Layer 4 核心数据模型。
"""
from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum


class GapPriority(str, Enum):
    P0 = "P0"  # 立即触发：INT 类失败，情报认知缺口
    P1 = "P1"  # 每日批量：ENV/INV 类工具知识缺口
    P2 = "P2"  # 每周更新：CVE 库/工具文档常规刷新


@dataclass
class GapSignal:
    """知识缺口信号——由 Layer 1 在 has_rag_context=false 的失败事件后写入队列。"""
    gap_id:          str              # 缺口唯一 ID（uuid）
    session_id:      str
    event_id:        str              # 触发该缺口的 Layer1 事件 ID
    priority:        GapPriority
    root_cause_dim:  str              # ENV / INV / INT / DEF / EFF
    root_cause_sub:  str              # 子维度（如 WRONG_TOPOLOGY）
    target_service:  str              # 关联的服务（如 Oracle WebLogic）
    cve_ids:         List[str] = field(default_factory=list)  # 关联 CVE（可为空）
    gap_description: str = ""         # LLM 生成的缺口描述（自然语言）
    search_queries:  List[str] = field(default_factory=list)  # 预生成的搜索关键词
    status:          str = "pending"  # pending / processing / done / failed
    created_at:      str = ""
    processed_at:    str = ""
    retry_count:     int = 0

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        # priority 枚举→字符串
        if isinstance(d.get("priority"), GapPriority):
            d["priority"] = d["priority"].value
        return d

    @staticmethod
    def from_dict(d: dict) -> "GapSignal":
        d = dict(d)
        if "priority" in d:
            d["priority"] = GapPriority(d["priority"])
        # 兼容旧记录缺字段
        for f in ("cve_ids", "search_queries"):
            if f not in d:
                d[f] = []
        for f in ("gap_description", "status", "created_at", "processed_at"):
            if f not in d:
                d[f] = "" if f != "status" else "pending"
        if "retry_count" not in d:
            d["retry_count"] = 0
        return GapSignal(**d)


@dataclass
class CrawlResult:
    """单篇爬取结果。"""
    gap_id:        str
    source:        str    # csdn / github / xianzhi / qianxin / rss_xianzhi …
    url:           str
    title:         str
    content:       str    # 正文（经 trafilatura 提取或原始）
    quality_score: float  # 0.0~1.0
    has_poc:       bool
    has_commands:  bool
    doc_id:        str = ""  # 入库后 RAGFlow document_id（暂为空）
    chunk_count:   int = 0


@dataclass
class ConflictRequest:
    """冲突检测请求——由 Layer 2 在新增负向经验后写入队列。"""
    request_id:           str
    triggered_by:         str       # 'new_neg_exp' / 'patch_info'
    exp_id:               str       # Layer2 负向经验 ID
    conflict_description: str       # 要搜索什么类型的冲突文档
    search_query:         str       # 在 RAGFlow 中搜索的查询词
    status:               str = "pending"
    created_at:           str = ""
