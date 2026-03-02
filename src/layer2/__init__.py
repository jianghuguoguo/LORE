"""
Layer 2：经验提取层（Experience Extraction Layer）
===================================================
从 Layer 1 标注完毕的 AnnotatedTurnSequence 中，按四层知识模型提取
结构化经验条目，写入原始经验库（raw 状态）。

知识层次（技术方案 R-03 / R-05）：
  FACTUAL       - 侦察阶段的有效发现（服务/端口/路径/版本等事实）
  CONCEPTUAL    - 高层次规律总结（LLM 归纳，单 session 内）
  PROCEDURAL_POS- 成功的操作序列（含参数化命令模板）
  PROCEDURAL_NEG- 失败的操作（含根因 + 修正建议）
  METACOGNITIVE - 会话级决策反思与经验总结（LLM 生成）

公开 API：
  run_layer2(ann_seq, client=None) -> ExperienceBundle
  run_layer2_batch(input_dir, output_dir, client) -> Iterator[ExperienceBundle]
"""

from .experience_models import (
    Experience,
    ExperienceBundle,
    ExperienceMaturity,
    ExperienceMetadata,
    KnowledgeLayer,
)
from .pipeline import run_layer2, run_layer2_batch

__all__ = [
    "Experience",
    "ExperienceBundle",
    "ExperienceMaturity",
    "ExperienceMetadata",
    "KnowledgeLayer",
    "run_layer2",
    "run_layer2_batch",
]
