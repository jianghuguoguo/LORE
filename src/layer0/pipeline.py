"""
Layer 0 完整流水线（Pipeline）
================================
职责：串联 LogParser → EventExtractor → TurnSequenceAssembler，
对单个日志文件或整个日志目录输出 TurnSequence 对象。

这是 Layer 0 的唯一对外入口，Layer 1 仅需调用 run_layer0()。

技术方案对应输入/输出：
    输入：原始 JSONL 日志文件（logs/ 目录下的 cai_*.jsonl）
    输出：结构化但语义中性的 TurnSequence
          不含任何阶段判断、失败类型、成功/失败标注
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List, Optional

from ..models import TurnSequence
from ..utils.config_loader import Config, get_config
from ..utils.log_utils import get_logger
from ..utils.serializer import save_turn_sequence
from .assembler import TurnSequenceAssembler
from .extractor import EventExtractor
from .parser import LogParser

logger = get_logger(__name__)


def run_layer0(
    log_path: Path,
    config: Optional[Config] = None,
) -> TurnSequence:
    """对单个 JSONL 日志文件执行完整的 Layer 0 处理流水线。

    Args:
        log_path: 原始 JSONL 日志文件路径
        config  : 配置对象（None 时使用全局默认配置）

    Returns:
        完整的 TurnSequence（语义中性，供 Layer 1 消费）
    """
    cfg = config or get_config()
    parser    = LogParser(cfg)
    extractor = EventExtractor(cfg)
    assembler = TurnSequenceAssembler(cfg)

    # Step 1：轮次重建
    metadata, turns = parser.parse_file(log_path)

    # Step 2：事件原子提取（原地填充 Turn.events / Turn.rag_queries）
    for turn in turns:
        events, rag_queries = extractor.extract(turn)
        turn.events = events
        turn.rag_queries = rag_queries

    # Step 3/4：序列构建 + has_rag_context + 脚本关联标注
    sequence = assembler.assemble(metadata, turns)

    return sequence


def run_layer0_batch(
    log_dir: Path,
    output_dir: Optional[Path] = None,
    config: Optional[Config] = None,
    save: bool = True,
) -> Iterator[TurnSequence]:
    """批量处理日志目录下所有日志文件。

    Args:
        log_dir   : 日志文件目录
        output_dir: 输出目录（None 时使用 config.output_dir）
        config    : 配置对象
        save      : 是否将每个 TurnSequence 序列化保存

    Yields:
        TurnSequence（每文件一个）
    """
    cfg = config or get_config()
    parser = LogParser(cfg)
    extractor = EventExtractor(cfg)
    assembler = TurnSequenceAssembler(cfg)

    if output_dir is None:
        # 输出目录相对于日志目录
        output_dir = log_dir.parent / "data" / "processed"

    pattern = cfg.log_glob
    files = sorted(log_dir.glob(pattern))
    logger.info("Layer 0 batch: found %d files in %s", len(files), log_dir)

    for log_path in files:
        try:
            logger.info("Processing: %s", log_path.name)

            metadata, turns = parser.parse_file(log_path)
            for turn in turns:
                events, rag_queries = extractor.extract(turn)
                turn.events = events
                turn.rag_queries = rag_queries

            sequence = assembler.assemble(metadata, turns)

            if save:
                filename = cfg.output_filename_template.format(
                    session_id=metadata.session_id
                )
                out_path = output_dir / filename
                save_turn_sequence(sequence, out_path)
                logger.info(
                    "Saved: %s  (turns=%d, events=%d)",
                    out_path.name, sequence.turn_count, sequence.event_count,
                )

            yield sequence

        except Exception as exc:
            logger.error("Failed to process %s: %s", log_path.name, exc, exc_info=True)
