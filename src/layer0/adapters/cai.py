"""
adapters/cai.py – CAI 框架日志适配器（原生支持，信息最完整）
===============================================================
通过封装现有 LogParser → EventExtractor 流水线，将 CAI JSONL 日志
转换为 CanonicalAgentTurn 序列。向后兼容：不修改 LogParser 任何逻辑。

CAI 日志格式特征（嗅探 key）：
  - 每行是 JSON 对象
  - 前若干行存在 {"event": "session_start", "session_id": "..."}

信息完整度：⭐⭐⭐⭐⭐（最完整）
  - return_code / timed_out / success：✅ 来自工具自报告
  - RAG 查询内容 + 结果：✅ 来自 RagQueryRecord
  - assistant 推理文本：✅ 来自 assistant_message.content
  - 多工具并行（slot_in_turn）：✅ 来自 AtomicEvent.slot_in_turn
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ..canonical_types import CanonicalAgentTurn, RagQueryInfo, SessionMeta
from ..log_adapter import AdapterRegistry, LogAdapter

logger = logging.getLogger(__name__)

# 最多读取的嗅探行数
_SNIFF_LINES = 10


@AdapterRegistry.register
class CaiAdapter(LogAdapter):
    """CAI（Cybersecurity AI）框架日志适配器。

    通过封装现有 Layer0 解析流水线（LogParser + EventExtractor），
    将 CAI 三段式 Turn 结构转换为 CanonicalAgentTurn 序列。

    向后兼容保证：
      CaiAdapter 的解析行为与直接调用 run_layer0() 完全一致；
      所有现有单元测试（针对 parser/extractor 的）继续有效。
    """

    @property
    def adapter_name(self) -> str:
        return "cai"

    # ─── 格式嗅探 ────────────────────────────────────────────────────────────

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        """嗅探前 _SNIFF_LINES 行，查找 event=session_start 标志。"""
        try:
            with open(file_path, encoding="utf-8") as fh:
                for _ in range(_SNIFF_LINES):
                    raw = fh.readline()
                    if not raw:
                        break
                    obj = json.loads(raw.strip())
                    if obj.get("event") == "session_start":
                        return True
        except Exception:  # noqa: BLE001
            pass
        return False

    # ─── 解析主入口 ──────────────────────────────────────────────────────────

    def parse(
        self,
        file_path: Path,
    ) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        """解析 CAI JSONL 日志，返回 (SessionMeta, CanonicalAgentTurn 迭代器)。"""
        self.validate_file(file_path)

        # 懒导入，避免模块级循环依赖
        from src.layer0.extractor import EventExtractor  # noqa: PLC0415
        from src.layer0.parser import LogParser          # noqa: PLC0415
        from src.utils.config_loader import get_config   # noqa: PLC0415

        cfg = get_config()
        parser = LogParser(cfg)
        extractor = EventExtractor(cfg)

        # Step 1：解析出 (SessionMetadata, List[Turn])
        raw_metadata, turns = parser.parse_file(file_path)

        # Step 2：原子事件提取（填充 Turn.events / Turn.rag_queries）
        for turn in turns:
            events, rag_queries = extractor.extract(turn)
            turn.events = events
            turn.rag_queries = rag_queries

        # 构建 SessionMeta
        meta = SessionMeta(
            session_id=raw_metadata.session_id,
            start_time=_fmt_dt(raw_metadata.start_time),
            end_time=_fmt_dt(raw_metadata.end_time),
            target_raw=raw_metadata.target_raw,
            total_cost=raw_metadata.total_cost,
            session_end_type=raw_metadata.session_end_type,
            total_turns=len(turns),
            raw_metadata={
                "source_file": raw_metadata.source_file,
                "log_filename": raw_metadata.log_filename,
                "timing_metrics": raw_metadata.timing_metrics,
            },
        )

        # 惰性转换：Turn → CanonicalAgentTurn 迭代器
        return meta, _iter_canonical(raw_metadata.session_id, turns)


# ─────────────────────────────────────────────────────────────────────────────
# 内部转换逻辑（模块级私有函数）
# ─────────────────────────────────────────────────────────────────────────────

def _iter_canonical(
    session_id: str,
    turns,
) -> Iterator[CanonicalAgentTurn]:
    """将 Turn 列表中的 AtomicEvent 逐个转换为 CanonicalAgentTurn。"""
    for turn in turns:
        # 提取 assistant 推理文本（来自 assistant_message.content 字段）
        assistant_reasoning = _extract_reasoning(turn.assistant_message)

        # 建立 tool_call_id → RagQueryRecord 索引（用于快速关联）
        rag_by_call_id = {rq.tool_call_id: rq for rq in (turn.rag_queries or [])}

        for event in turn.events:
            call = event.call
            result = event.result

            # 构建 RagQueryInfo（仅 RAG 调用填充）
            rag_info: Optional[RagQueryInfo] = None
            if event.call.action_category.value == "RAG_QUERY":
                rq = rag_by_call_id.get(call.tool_call_id)
                if rq is not None:
                    rag_info = RagQueryInfo(
                        query=rq.query,
                        results_raw=rq.rag_result or "",
                        result_count=-1,
                    )

            yield CanonicalAgentTurn(
                session_id=session_id,
                turn_index=event.turn_index,
                timestamp=_fmt_dt(call.call_timestamp),
                tool_name=call.tool_name,
                tool_args=call.call_args or {},
                stdout=result.stdout_raw if result else None,
                stderr=result.stderr_raw if result else None,
                return_code=result.return_code if result else None,
                success=result.success if result else None,
                timed_out=result.timed_out if result else False,
                rag_info=rag_info,
                assistant_reasoning=assistant_reasoning,
                slot_in_turn=event.slot_in_turn,
                raw_metadata={
                    "event_id": event.event_id,
                    "action_category": event.call.action_category.value,
                    "has_rag_context": event.has_rag_context,
                    "rag_query_ref": event.rag_query_ref,
                    "code_script_ref": event.code_script_ref,
                    "partial_results": result.partial_results if result else False,
                },
            )


def _extract_reasoning(assistant_message: Optional[dict]) -> Optional[str]:
    """从 assistant_message 中提取 Agent 推理/规划文本。

    CAI 格式中，assistant_message.content 可以是字符串（纯文本推理）
    或 None（纯 tool_call 回合，无自然语言内容）。
    """
    if not assistant_message:
        return None
    content = assistant_message.get("content")
    if not content:
        return None
    if isinstance(content, str):
        return content.strip() or None
    # 极少数情况：content 是 list（如多 part content）
    if isinstance(content, list):
        texts = [
            part.get("text", "") for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        ]
        joined = " ".join(t.strip() for t in texts if t.strip())
        return joined or None
    return None


def _fmt_dt(dt: Optional[datetime]) -> str:
    """将 datetime 格式化为 ISO 8601 字符串；None 时返回空字符串。"""
    if dt is None:
        return ""
    return dt.isoformat()
