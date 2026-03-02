"""
discovery/models.py — 账号候选数据模型
========================================
AccountCandidate：从各发现渠道生成的账号候选记录。
"""

from __future__ import annotations

import dataclasses
from typing import List


@dataclasses.dataclass
class AccountCandidate:
    """
    代表一个待评审的公众号候选。

    Attributes
    ----------
    name              : 公众号显示名称（微信内搜索用）
    biz               : 微信公众号唯一 ID（__biz 参数），可为空
    description       : 公众号简介
    source            : 发现渠道，如 sogou / citation / community / manual
    discovery_keyword : 触发发现的关键词（来自搜狗搜索时为搜索词；引用提取时为原文 URL）
    first_seen        : ISO-8601 格式的首次发现时间
    tags              : 关键词标签列表，如 ['内网渗透', '漏洞挖掘']
    score             : 质量评分（AccountQualityScorer 打分后填充，0-100）
    grade             : 质量等级 A/B/C/D
    auto_add          : 是否已自动加入目标账号列表（score≥40 时自动设为 True）
    """
    name:               str
    biz:                str   = ''
    description:        str   = ''
    source:             str   = ''
    discovery_keyword:  str   = ''
    first_seen:         str   = ''
    tags:               List[str] = dataclasses.field(default_factory=list)
    score:              float = 0.0
    grade:              str   = 'D'
    auto_add:           bool  = False
    mention_count:      int   = 0     # 通道 B 批量提取时被引用的次数

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'AccountCandidate':
        return cls(**{k: v for k, v in d.items() if k in {f.name for f in dataclasses.fields(cls)}})
