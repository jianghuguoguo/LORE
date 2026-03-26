"""
Layer 0 – Step 1：轮次重建（Turn Reconstruction）
===================================================
职责：从原始 JSONL 日志流中识别三段式结构，重建 Turn 对象序列。

技术方案定义（六.Layer0 Step1）：
    识别三段式结构：assistant_message + API_request + chat.completion
    构建 Turn 对象，每个 Turn 是最小分析单元。

实际日志格式（通过逆向工程真实日志确认）：
    每条记录有顶层 event 字段区分类型：
    - event=session_start        → 会话开始元数据
    - event=session_end          → 会话结束元数据（含 timing_metrics / cost）
    - event=user_message         → 用户侧输入（含渗透任务描述 / TUI 控制信号）
    - event=assistant_message    → Agent 本轮决策（含 tool_calls 数组）
    - event=UNKNOWN, object=""   → LLM API 请求对象（完整 messages 历史链）
    - event=UNKNOWN, object=chat.completion → LLM 响应（choices[0].message.tool_calls）

Turn 边界规则：
    每次出现带有 tool_calls 的 assistant_message 时，开始新的 Turn。
    Turn 结构：assistant_message → UNKNOWN(API request) → UNKNOWN(chat.completion)
    工具执行结果（role=tool）嵌套在 UNKNOWN(API request) 的 messages 数组中。

工具结果提取逻辑：
    API request 的 messages[-1] 或倒数几条中的 role=tool 消息，
    其 content 格式为 JSON 字符串：{"type": "text", "text": "<inner_json>"}
    inner_json 为 {"return_code": int, "timed_out": bool, "success": bool,
                    "stderr": str, "stdout": str, "partial_results": bool}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..models import SessionMetadata, Turn
from ..utils.config_loader import Config, get_config
from ..utils.log_utils import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 内部枚举：原始行类型（仅用于解析器内部，不暴露到上层）
# ─────────────────────────────────────────────────────────────────────────────

class _LineType:
    SESSION_START   = "session_start"
    SESSION_END     = "session_end"
    USER_MESSAGE    = "user_message"
    ASSISTANT_MSG   = "assistant_message"
    API_REQUEST     = "api_request"       # event=UNKNOWN, object=""
    COMPLETION      = "chat.completion"   # event=UNKNOWN, object=chat.completion


def _classify_line(obj: Dict[str, Any]) -> str:
    """识别一行 JSONL 记录的类型。"""
    event = obj.get("event", "")
    obj_type = obj.get("object", "")

    if event == _LineType.SESSION_START:
        return _LineType.SESSION_START
    if event == _LineType.SESSION_END:
        return _LineType.SESSION_END
    if event == _LineType.USER_MESSAGE:
        return _LineType.USER_MESSAGE
    if event == _LineType.ASSISTANT_MSG:
        return _LineType.ASSISTANT_MSG
    # 无 event 字段的 UNKNOWN 对象（源自原始 API 交互记录）
    if event == "UNKNOWN" or (not event and "messages" in obj):
        if obj_type == "chat.completion":
            return _LineType.COMPLETION
        return _LineType.API_REQUEST
    # 兼容：部分日志中 event 字段缺失但有 messages 关键字
    if "messages" in obj and "choices" not in obj:
        return _LineType.API_REQUEST
    if "choices" in obj:
        return _LineType.COMPLETION
    return "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# 工具结果解析（源自 API request 的 messages[role=tool]）
# ─────────────────────────────────────────────────────────────────────────────

def _parse_tool_result_content(raw_content: Any) -> Dict[str, Any]:
    """从 role=tool 消息的 content 字段中解析工具执行结果。

    日志中的格式（双层 JSON）：
        content = '{"type":"text","text":"{\\"return_code\\":0,...}"}'
    Return:
        dict with keys: return_code, timed_out, success, stderr, stdout,
                        partial_results (部分工具有），以及 _raw_text
    """
    if isinstance(raw_content, dict):
        # 已解析为 dict 的直接格式
        return raw_content

    if not isinstance(raw_content, str):
        logger.warning("Unexpected tool result content type: %s", type(raw_content))
        return {}

    # 外层解析
    try:
        outer = json.loads(raw_content)
    except json.JSONDecodeError:
        # content 本身就是内层 JSON（无外层包装）
        try:
            return json.loads(raw_content)
        except json.JSONDecodeError:
            return {"_raw_text": raw_content}

    # 标准双层格式：{"type": "text", "text": "<inner_json>"}
    if isinstance(outer, dict) and outer.get("type") == "text":
        inner_text = outer.get("text", "")
        try:
            result = json.loads(inner_text)
            result["_raw_text"] = inner_text
            return result
        except json.JSONDecodeError:
            return {"_raw_text": inner_text}

    # 若 outer 已经是结果 dict（type != "text"）
    if isinstance(outer, dict):
        return outer
    # outer 是非 dict 的 JSON 值（整数、字符串、列表等，如纯状态码 "200" → 200）
    # 包装为结构化 dict，以便 ResultDescriptor 能正常读取
    return {"_raw_text": str(outer)}


def _extract_tool_results_from_api_request(
    api_request: Dict[str, Any],
    tool_call_ids: List[str],
) -> Dict[str, Dict[str, Any]]:
    """从 API request 的 messages 数组中提取指定 tool_call_id 的执行结果。

    Args:
        api_request  : 原始 API 请求对象（包含完整 messages 历史链）
        tool_call_ids: 当前 Turn 的 tool_call_id 列表

    Returns:
        {tool_call_id -> parsed_result_dict}
    """
    results: Dict[str, Dict[str, Any]] = {}
    messages = api_request.get("messages", [])
    id_set = set(tool_call_ids)

    for msg in messages:
        if msg.get("role") != "tool":
            continue
        tc_id = msg.get("tool_call_id", "")
        if tc_id not in id_set:
            continue
        if tc_id in results:
            # 历史记录中可能出现重复（messages 是累积的），只取最后一次
            pass
        content = msg.get("content", "")
        results[tc_id] = _parse_tool_result_content(content)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 目标字符串提取（从首批 user_message 中提取渗透目标）
# ─────────────────────────────────────────────────────────────────────────────

def _try_extract_target(content: str, keywords: List[str]) -> Optional[str]:
    """尝试从 user_message content 中提取渗透目标描述。

    只做轻量级关键词检测，不做深度解析（语义解析交 Layer 1）。
    """
    if not content or not isinstance(content, str):
        return None
    c = content.strip()
    # 过滤 TUI 控制信号（如 '--tui'）
    if c.startswith("--"):
        return None
    for kw in keywords:
        if kw in c:
            # 返回完整 content（原始保留，不截断）
            return c
    # 若包含 URL 格式也认为是目标描述
    if re.search(r'https?://', c) or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', c):
        return c
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 内部状态机：TurnBuffer
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _TurnBuffer:
    """收集单个 Turn 三段式组件的临时缓冲区。"""
    assistant_message: Optional[Dict[str, Any]] = None
    api_request: Optional[Dict[str, Any]] = None
    completion: Optional[Dict[str, Any]] = None
    turn_index: int = 0
    session_id: str = ""

    def is_complete(self) -> bool:
        """三段式结构全部到位"""
        return (
            self.assistant_message is not None
            and self.api_request is not None
            and self.completion is not None
        )

    def has_tool_calls(self) -> bool:
        """assistant_message 是否携带 tool_calls"""
        am = self.assistant_message or {}
        return bool(am.get("tool_calls"))


# ─────────────────────────────────────────────────────────────────────────────
# 主解析器
# ─────────────────────────────────────────────────────────────────────────────

class LogParser:
    """Layer 0 Step 1：将 JSONL 日志文件解析为 (SessionMetadata, List[Turn]) 对。

    状态机设计原则：
    - 一次遍历，O(N) 内存，N = 日志行数
    - Turn 边界由 assistant_message 触发
    - 工具结果从紧随其后的 API request 的 messages 中提取
    - 不做任何语义理解，仅做结构识别
    """

    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or get_config()

    # ─── 公共接口 ──────────────────────────────────────────────────────────

    def parse_file(self, log_path: Path) -> Tuple[SessionMetadata, List[Turn]]:
        """解析单个 JSONL 日志文件。

        Args:
            log_path: JSONL 日志文件路径

        Returns:
            (SessionMetadata, List[Turn]) 元组
            若文件中有多个 session_id，仅处理第一个（正常日志只有一个）

        Raises:
            FileNotFoundError: 文件不存在
            json.JSONDecodeError: JSONL 格式错误（行级报错，跳过并警告）
        """
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        logger.info("Parsing log file: %s", log_path.name)
        objs = list(self._iter_json_lines(log_path))
        metadata, turns = self._run_state_machine(objs, log_path)
        logger.info(
            "Parsed session=%s  turns=%d  file=%s",
            metadata.session_id, len(turns), log_path.name,
        )
        return metadata, turns

    def parse_directory(self, log_dir: Path) -> Iterator[Tuple[SessionMetadata, List[Turn]]]:
        """遍历目录下所有匹配 config.log_glob 的 JSONL 文件并依次解析。

        Yields:
            (SessionMetadata, List[Turn]) 元组
        """
        pattern = self.cfg.log_glob
        files = sorted(log_dir.glob(pattern))
        logger.info("Found %d log files in %s", len(files), log_dir)
        for fp in files:
            try:
                yield self.parse_file(fp)
            except Exception as exc:
                logger.error("Failed to parse %s: %s", fp.name, exc)

    # ─── 内部方法 ──────────────────────────────────────────────────────────

    def _iter_json_lines(self, path: Path) -> Iterator[Dict[str, Any]]:
        """逐行读取并解析 JSONL 文件，跳过空行和解析失败行。"""
        with open(path, encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict):
                        yield obj
                    else:
                        logger.debug("Skip non-object JSON at line %d in %s", lineno, path.name)
                except json.JSONDecodeError as exc:
                    logger.warning("JSON parse error at line %d: %s", lineno, exc)

    def _run_state_machine(
        self,
        objs: List[Dict[str, Any]],
        log_path: Path,
    ) -> Tuple[SessionMetadata, List[Turn]]:
        """核心状态机：扫描对象列表，重建 Turn 序列。

        状态转换：
            IDLE → SESSION_OPEN（遇 session_start）
            SESSION_OPEN:
                user_message   → 尝试提取目标，更新 target_raw
                assistant_msg  → 刷新 current buffer，开始新 Turn buffer
                api_request    → 填充当前 buffer 的 api_request 字段
                completion     → 填充当前 buffer 的 completion 字段
                               → 若 buffer 完整，finalize Turn
                session_end    → finalize 最后 Turn（即使不完整），关闭 Session
        """
        # 初始化元数据（先用占位值，遇 session_start 后替换）
        session_id = log_path.stem.split("_")[1] if "_" in log_path.stem else log_path.stem
        start_time: Optional[datetime] = None
        end_time: Optional[datetime] = None
        timing_metrics: Dict[str, Any] = {}
        total_cost: float = 0.0
        target_raw: Optional[str] = None

        turns: List[Turn] = []
        turn_index: int = 0
        buf: Optional[_TurnBuffer] = None
        session_end_seen: bool = False   # 用于 Bug2: 判断 session 是否正常结束

        # 用于记录所有已发现的工具结果（按 tool_call_id 索引）
        # 由于 API request 的 messages 是完整历史链，新出现的每次都覆盖旧值
        accumulated_results: Dict[str, Dict[str, Any]] = {}

        user_msg_count: int = 0
        max_target_scan = self.cfg.target_extraction_max_scan_lines
        target_keywords = self.cfg.target_extraction_keywords

        for obj in objs:
            line_type = _classify_line(obj)

            # ── session_start ─────────────────────────────────────────────
            if line_type == _LineType.SESSION_START:
                session_id = obj.get("session_id", session_id)
                start_time = _parse_ts(obj.get("timestamp"))
                logger.debug("session_start: id=%s  ts=%s", session_id, start_time)

            # ── session_end ───────────────────────────────────────────────
            elif line_type == _LineType.SESSION_END:
                end_time = _parse_ts(obj.get("timestamp"))
                timing_metrics = obj.get("timing_metrics", {})
                cost_obj = obj.get("cost", {})
                total_cost = float(cost_obj.get("total_cost", 0.0))
                session_end_seen = True  # Bug2: 标记正常结束
                # 刷新最后一个未完成的 buffer
                if buf is not None:
                    turns.extend(self._finalize_buffer(buf, accumulated_results))
                    buf = None

            # ── user_message ──────────────────────────────────────────────
            elif line_type == _LineType.USER_MESSAGE:
                if user_msg_count < max_target_scan and target_raw is None:
                    content = obj.get("content", "")
                    extracted = _try_extract_target(content, target_keywords)
                    if extracted:
                        target_raw = extracted
                        logger.debug("Extracted target_raw: %s", target_raw[:80])
                user_msg_count += 1

            # ── assistant_message ─────────────────────────────────────────
            elif line_type == _LineType.ASSISTANT_MSG:
                # 刷新旧 buffer（如果旧的尚未完成，说明结构异常，也保存下来）
                if buf is not None:
                    turns.extend(self._finalize_buffer(buf, accumulated_results))

                buf = _TurnBuffer(
                    assistant_message=obj,
                    turn_index=turn_index,
                    session_id=session_id,
                )

                # 记录 turn 时间戳（来自 assistant_message）
                if start_time is None:
                    start_time = _parse_ts(obj.get("timestamp"))

                turn_index += 1

            # ── API request ───────────────────────────────────────────────
            elif line_type == _LineType.API_REQUEST:
                # 从完整 messages 历史中增量更新 accumulated_results
                messages = obj.get("messages", [])
                for msg in messages:
                    if msg.get("role") != "tool":
                        continue
                    tc_id = msg.get("tool_call_id", "")
                    if not tc_id:
                        continue
                    raw_content = msg.get("content", "")
                    accumulated_results[tc_id] = _parse_tool_result_content(raw_content)

                if buf is not None:
                    buf.api_request = obj
                else:
                    # API request 出现在任何 assistant_message 之前（首轮可能发生）
                    logger.debug("API request before any assistant_message (ignored for Turn)")

            # ── chat.completion ───────────────────────────────────────────
            elif line_type == _LineType.COMPLETION:
                if buf is not None:
                    buf.completion = obj
                    # 三段式完整，立即 finalize
                    turns.extend(self._finalize_buffer(buf, accumulated_results))
                    buf = None
                else:
                    logger.debug("chat.completion without active buffer (skipped)")

        # 扫描结束后，若 buffer 未被 session_end 刷新，强制结束
        if buf is not None:
            logger.warning(
                "Unclosed Turn buffer at end of file (turn_index=%d). Finalizing.", buf.turn_index
            )
            turns.extend(self._finalize_buffer(buf, accumulated_results))

        # ── 后处理：将全量 accumulated_results 回填到每个 Turn ──────────
        # 根本原因：Turn N 的工具结果存在于 Turn N+1 的 API_REQUEST 的 messages 中
        # （累积历史消息模式）。全局扫描完成后 accumulated_results 才完整，
        # 此时统一回注，确保每个 Turn 都能看到自己的结果。
        for turn in turns:
            if turn.api_request is not None:
                # 找出本 Turn 实际拥有的 tool_call_id
                # Bug1 修复：优先从 assistant_message 取，为空时回退到
                # completion.choices[0].message（两者理论上相同，但部分
                # Turn 的 assistant_message 事件不含 tool_calls）
                own_ids = _extract_own_tool_call_ids(turn)
                tool_results = {k: v for k, v in accumulated_results.items() if k in own_ids}
                # 设计问题1 修复：裁剪 api_request 为最小字段集，去掉 O(n²) 的
                # 完整历史 messages[] ，仅保留 model 和 _tool_results。
                # 完整日志已在原始 JSONL 中， Layer 0 无需重复存储。
                turn.api_request = {
                    "model": turn.api_request.get("model"),
                    "_tool_results": tool_results,
                }

        # 构建 SessionMetadata
        # Bug2: 根据 session_end_seen 判断结束类型
        session_end_type = "normal" if session_end_seen else "interrupted"
        metadata = SessionMetadata(
            session_id=session_id,
            start_time=start_time or datetime.utcnow(),
            end_time=end_time,
            timing_metrics=timing_metrics,
            total_cost=total_cost,
            target_raw=target_raw,
            source_file=str(log_path),
            log_filename=log_path.name,
            session_end_type=session_end_type,
        )
        return metadata, turns

    def _finalize_buffer(
        self,
        buf: _TurnBuffer,
        accumulated_results: Dict[str, Dict[str, Any]],
    ) -> List[Turn]:
        """将一个 _TurnBuffer 转换为 Turn 对象（含工具结果注入）。

        若 buffer 没有 tool_calls（例如纯 content 的 assistant_message），
        也会生成 Turn，但其 events 为空，供 Layer 0 extractor 处理时跳过。

        Returns:
            List[Turn]，通常长度为 1；无 tool_calls 时也返回，但 events=[]
        """
        am = buf.assistant_message or {}
        ts = _parse_ts(am.get("timestamp"))

        # 将 accumulated_results 注入 api_request（逻辑只读，不修改原始对象）
        # 实际 extractor 需要的结果已在 accumulated_results 中，Turn 只保存原始对象
        turn = Turn(
            turn_index=buf.turn_index,
            timestamp=ts or datetime.utcnow(),
            session_id=buf.session_id,
            assistant_message=buf.assistant_message,
            api_request=buf.api_request,
            completion=buf.completion,
            # events / rag_queries 由 EventExtractor 填充
        )

        # 将工具结果注入到 Turn 对象的可访问存储
        # 使用侧信道属性（不破坏数据模型）：存储到 api_request 的 _tool_results 键
        # 这样 Extractor 可以直接从 Turn.api_request["_tool_results"] 读取
        if turn.api_request is not None:
            turn.api_request = dict(turn.api_request)  # shallow copy，避免污染原始对象
            turn.api_request["_tool_results"] = {
                k: v for k, v in accumulated_results.items()
            }

        return [turn]


# ─────────────────────────────────────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────────────────────────────────────

def _extract_own_tool_call_ids(turn: "Turn") -> set:
    """提取 Turn 所拥有的全部 tool_call_id 集合。

    Bug1 修复：assistant_message（本地 agent 事件记录）和
    completion.choices[0].message（LLM 原始响应）理论上携带相同的 tool_calls，
    但部分 Turn 的 assistant_message 事件里 tool_calls 为空列表，
    而 completion 里有完整的 tool_calls（如 Turn 10/11 in session 5db69512）。

    修复策略：优先使用 assistant_message.tool_calls；
    为空时回退到 completion.choices[0].message.tool_calls。
    """
    # 优先：assistant_message
    am = turn.assistant_message or {}
    ids = {tc.get("id", "") for tc in am.get("tool_calls", []) if tc.get("id")}
    if ids:
        return ids
    # 回退：chat.completion → choices[0].message.tool_calls
    completion = turn.completion or {}
    choices = completion.get("choices", [])
    if choices:
        msg = choices[0].get("message", {})
        ids = {tc.get("id", "") for tc in (msg.get("tool_calls") or []) if tc.get("id")}
    return ids


def _parse_ts(value: Any) -> Optional[datetime]:
    """将字符串解析为 datetime，容忍多种 ISO 8601 变体格式。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value)
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # 去掉时区偏移后重试
        s_clean = re.sub(r'[+-]\d{2}:\d{2}$', '', s)
        try:
            return datetime.fromisoformat(s_clean)
        except ValueError:
            logger.warning("Cannot parse timestamp: %s", value)
            return None
