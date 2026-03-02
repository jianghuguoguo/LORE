"""
Layer 0 – Step 3/4：序列构建（TurnSequence Assembly）
======================================================
职责：将提取后的 (Turn, events, rag_queries) 列表组装为完整的
TurnSequence 对象，完成两个关键标注：

Step 3 – has_rag_context 标注（技术方案 六.Layer0 Step3）：
    每个 AtomicEvent 检查其 turn_index 前 N=3 步内是否有 RAG 调用。
    has_rag_context = true/false（仅表示时间窗口内存在 RAG 调用，不判断采纳）

Step 4 – 脚本关联标注（技术方案 六.Layer0 Step3 续）：
    识别 execute_code 事件生成的脚本文件名，与后续 GENERIC_COMMAND_CALL 中
    执行同名脚本的事件建立关联（code_script_ref 字段）。
    在没有明确文件名时，通过内容哈希建立关联。

技术方案原文：
    "标记 execute_code 事件与后续 generic_linux_command 中执行对应脚本
     的关联关系（通过文件名匹配，与工具名无关）。"

设计约束：
    - 不改变事件内容，只填充 has_rag_context 和 code_script_ref 字段
    - has_rag_context 窗口大小由 config.rag_context_window_turns 控制
    - code_script_ref 只做文本特征匹配，不涉及任何语义理解
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    ActionCategory,
    AtomicEvent,
    RagQueryRecord,
    SessionMetadata,
    Turn,
    TurnSequence,
)
from ..utils.config_loader import Config, get_config
from ..utils.log_utils import get_logger

logger = get_logger(__name__)


class TurnSequenceAssembler:
    """Layer 0 Step 3/4：将 Turn + Event 列表组装为 TurnSequence。

    调用顺序：
        assembler = TurnSequenceAssembler()
        seq = assembler.assemble(metadata, turns_with_events)
    """

    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or get_config()

    def assemble(
        self,
        metadata: SessionMetadata,
        turns: List[Turn],  # 每个 Turn 已由 EventExtractor 填充 events/rag_queries
    ) -> TurnSequence:
        """构建 TurnSequence，完成 has_rag_context 标注和脚本关联标注。

        Args:
            metadata: 会话元数据（来自 LogParser）
            turns   : 已填充 events/rag_queries 的 Turn 列表

        Returns:
            完整的 TurnSequence（Layer 0 输出）
        """
        # ── 1. 展平所有事件为全局有序列表 ────────────────────────────────
        all_events: List[AtomicEvent] = []
        rag_index: Dict[str, RagQueryRecord] = {}

        for turn in turns:
            all_events.extend(turn.events)
            for rq in turn.rag_queries:
                rag_index[rq.tool_call_id] = rq

        logger.info(
            "Assembling TurnSequence: session=%s  turns=%d  events=%d  rag_calls=%d",
            metadata.session_id, len(turns), len(all_events), len(rag_index),
        )

        # ── 2. has_rag_context 标注 ────────────────────────────────────
        all_events = self._annotate_rag_context(turns, all_events, rag_index)

        # ── 3. CODE_WRITE → GENERIC_COMMAND_CALL 脚本关联 ────────────
        all_events, code_write_index = self._annotate_code_script_refs(all_events)

        # ── 4. 将事件写回 Turn 对象（同步更新 has_rag_context 字段）─────
        event_map: Dict[str, AtomicEvent] = {e.event_id: e for e in all_events}
        for turn in turns:
            turn.events = [event_map.get(e.event_id, e) for e in turn.events]

        # ── 5. 统计日志 ───────────────────────────────────────────────
        rag_ctx_count = sum(1 for e in all_events if e.has_rag_context)
        code_write_count = sum(1 for e in all_events if e.call.action_category == ActionCategory.CODE_WRITE)
        logger.info(
            "Annotation complete: has_rag_context=%d/%d  code_writes=%d  script_links=%d",
            rag_ctx_count, len(all_events), code_write_count, len(code_write_index),
        )

        return TurnSequence(
            metadata=metadata,
            turns=turns,
            all_events=all_events,
            rag_index=rag_index,
            code_write_index=code_write_index,
        )

    # ─── has_rag_context 标注 ─────────────────────────────────────────────

    def _annotate_rag_context(
        self,
        turns: List[Turn],
        all_events: List[AtomicEvent],
        rag_index: Dict[str, RagQueryRecord],
    ) -> List[AtomicEvent]:
        """为每个 AtomicEvent 标注 has_rag_context 和 rag_query_ref。

        技术方案定义：
            "每个 tool_call 判断：前 N=3 步内是否有 RAG 调用
             has_rag_context = true / false
            （仅表示时间窗口内是否有 RAG 调用，不判断是否采纳）"

        实现：
            构建 {turn_index: List[RagQueryRecord]} 索引，
            对每个事件向前查找 window_turns 个 turn 是否有 RAG 调用。
            rag_query_ref 指向时间上最近的那次 RAG 调用的 tool_call_id。
        """
        window = self.cfg.rag_context_window_turns

        # 按 turn_index 构建 RAG 调用分布索引
        rag_by_turn: Dict[int, List[RagQueryRecord]] = defaultdict(list)
        for rq in rag_index.values():
            rag_by_turn[rq.turn_index].append(rq)

        annotated: List[AtomicEvent] = []
        for event in all_events:
            ti = event.turn_index
            # 查找前 window 步内（不含本步）的 RAG 调用
            nearest_rag_id: Optional[str] = None
            latest_rag_turn: int = -1

            for delta in range(1, window + 1):
                check_turn = ti - delta
                if check_turn < 0:
                    continue
                if check_turn in rag_by_turn and rag_by_turn[check_turn]:
                    # 找到最近的 RAG 调用 turn
                    if check_turn > latest_rag_turn:
                        latest_rag_turn = check_turn
                        # 取该 turn 内最后一个 RAG 调用
                        nearest_rag_id = rag_by_turn[check_turn][-1].tool_call_id

            # 同 turn 内的 RAG 调用也应标记（RAG_QUERY 事件本身的后续 slot）
            if ti in rag_by_turn:
                for rq in rag_by_turn[ti]:
                    if rq.tool_call_id != event.call.tool_call_id:
                        # 同一 turn 内有早于当前 slot 的 RAG 调用
                        if event.call.action_category != ActionCategory.RAG_QUERY:
                            nearest_rag_id = rq.tool_call_id
                            break

            has_ctx = nearest_rag_id is not None
            # 使用对象替换（dataclass 不可变，创建新对象）
            annotated.append(_replace_event(event,
                has_rag_context=has_ctx,
                rag_query_ref=nearest_rag_id,
            ))

        return annotated

    # ─── 脚本关联标注 ─────────────────────────────────────────────────────

    def _annotate_code_script_refs(
        self,
        all_events: List[AtomicEvent],
    ) -> Tuple[List[AtomicEvent], Dict[str, AtomicEvent]]:
        """标注 CODE_WRITE 事件与后续执行该脚本的 GENERIC_COMMAND_CALL 之间的关联。

        技术方案定义：
            "通过 filename/标识符 建立与后续执行该脚本的调用之间的关联"
            "标注：code_write_event，关联后续 script_execute_event"

        匹配策略（优先级从高到低）：
        1. code_filename 完全匹配：call_args["command"] 中包含同名文件
        2. 代码内容哈希匹配：若无 filename，用代码内容前 64 字节的哈希作为标识
        3. 语言 + 执行前缀匹配：如 python3 xxx.py、bash xxx.sh

        Returns:
            (annotated_events, code_write_index)
            code_write_index: {code_write_event_id -> AtomicEvent}
        """
        # 第一遍：收集所有 CODE_WRITE 事件
        code_writes: List[AtomicEvent] = [
            e for e in all_events if e.call.action_category == ActionCategory.CODE_WRITE
        ]

        if not code_writes:
            return all_events, {}

        # 构建文件名索引
        # filename → [code_write_event_id, ...]
        filename_to_cw: Dict[str, List[str]] = defaultdict(list)
        hash_to_cw: Dict[str, List[str]] = defaultdict(list)

        for cw in code_writes:
            fn = cw.call.code_filename
            if fn:
                filename_to_cw[fn].append(cw.event_id)
                filename_to_cw[fn.split("/")[-1]].append(cw.event_id)  # basename
            # 内容哈希（用于 filename=None 的情况）
            code_str = cw.call.call_args.get("code", "")
            if code_str:
                h = hashlib.md5(code_str[:256].encode("utf-8", errors="replace")).hexdigest()[:8]
                hash_to_cw[h].append(cw.event_id)

        # 第二遍：扫描 GENERIC_COMMAND_CALL，匹配脚本执行
        # {code_write_event_id → Set[execute_event_id]}
        cw_to_exec: Dict[str, Set[str]] = defaultdict(set)

        for event in all_events:
            if event.call.action_category != ActionCategory.GENERIC_COMMAND_CALL:
                continue
            command = event.call.call_args.get("command", "")
            if not command:
                continue

            # 匹配策略 1：文件名出现在命令中
            for fn, cw_ids in filename_to_cw.items():
                if fn in command:
                    for cw_id in cw_ids:
                        # 只关联在时序上早于当前事件的 CODE_WRITE
                        cw_event = next((e for e in code_writes if e.event_id == cw_id), None)
                        if cw_event and cw_event.turn_index <= event.turn_index:
                            cw_to_exec[cw_id].add(event.event_id)

        # 反向构建：exec_event_id → code_write_event_id（用于在 GLC 事件上填充后向引用）
        exec_to_cw: Dict[str, str] = {}
        for cw_id, exec_ids in cw_to_exec.items():
            for eid in exec_ids:
                exec_to_cw[eid] = cw_id

        # 第三遇：填充 code_script_ref 字段
        # 设计方向（已按技术方案修正）：
        #   GENERIC_COMMAND_CALL 事件持有对 CODE_WRITE 的后向引用
        #   （“我执行的脚本来自哪个 CODE_WRITE”）
        #   CODE_WRITE 事件的 code_script_ref 保持为空列表。
        annotated: List[AtomicEvent] = []
        code_write_index: Dict[str, AtomicEvent] = {}

        for event in all_events:
            if event.call.action_category == ActionCategory.CODE_WRITE:
                # CODE_WRITE 不再存前向引用，保持 code_script_ref=[]
                updated = _replace_event(event, code_script_ref=[])
                annotated.append(updated)
                code_write_index[event.event_id] = updated
            elif event.call.action_category == ActionCategory.GENERIC_COMMAND_CALL:
                # GLC 持有对生成其脚本的 CODE_WRITE event_id 的后向引用
                cw_id = exec_to_cw.get(event.event_id)
                ref = [cw_id] if cw_id else []
                annotated.append(_replace_event(event, code_script_ref=ref))
            else:
                annotated.append(event)

        return annotated, code_write_index


# ─────────────────────────────────────────────────────────────────────────────
# 工具函数：dataclass 字段替换（因 dataclass 无 replace 方法）
# ─────────────────────────────────────────────────────────────────────────────

def _replace_event(event: AtomicEvent, **kwargs) -> AtomicEvent:
    """返回 AtomicEvent 的浅拷贝，替换指定字段值。"""
    return AtomicEvent(
        event_id=kwargs.get("event_id", event.event_id),
        turn_index=kwargs.get("turn_index", event.turn_index),
        slot_in_turn=kwargs.get("slot_in_turn", event.slot_in_turn),
        call=kwargs.get("call", event.call),
        result=kwargs.get("result", event.result),
        has_rag_context=kwargs.get("has_rag_context", event.has_rag_context),
        rag_query_ref=kwargs.get("rag_query_ref", event.rag_query_ref),
        code_script_ref=kwargs.get("code_script_ref", list(event.code_script_ref)),
    )
