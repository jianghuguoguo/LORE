import json
import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import logging
from processors.evo_config import config

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EvoPentest.AutoLabeler")

@dataclass
class KBResult:
    query: str
    documents: List[str]
    timestamp: str

@dataclass
class AttackStep:
    tool_name: str
    arguments: Dict[str, Any]
    result: str
    success: bool
    timestamp: str

class AutoLabeler:
    """
    Evo-Pentest 自动化标注引擎
    实现事后诸葛亮式标注逻辑 (Hindsight Labeling)
    """
    def __init__(self, logs_dir: Path, output_path: Path):
        self.logs_dir = logs_dir
        self.output_path = output_path
        self.success_indicators = config.SUCCESS_INDICATORS

    def parse_log_file(self, file_path: Path) -> List[Dict]:
        """解析单个 JSONL 日志文件并按会话逻辑重组"""
        events = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def is_step_successful(self, result_text: str) -> bool:
        """基于预定义的指纹判断动作是否成功"""
        if not result_text:
            return False
        for pattern in self.success_indicators:
            if re.search(pattern, result_text, re.IGNORECASE):
                return True
        return False

    def extract_training_pairs(self, events: List[Dict]) -> List[Dict]:
        """
        核心算法：回溯标注。
        逐步扫描日志，识别 KB 搜索及其后续结果。
        """
        training_data = []
        last_kb_search: Optional[KBResult] = None
        context_window = []

        # 展平所有可能的事件（包括嵌套在 messages 里的）
        flat_events = []
        for e in events:
            if "event" in e:
                flat_events.append(e)
            if "messages" in e:
                for msg in e["messages"]:
                    # 将 message 转换成类似 event 的格式方便统一处理
                    flat_events.append({
                        "event": "message",
                        "role": msg.get("role"),
                        "content": msg.get("content"),
                        "tool_calls": msg.get("tool_calls"),
                        "tool_call_id": msg.get("tool_call_id"),
                        "timestamp": e.get("timestamp_iso", e.get("timestamp"))
                    })

        for i, event in enumerate(flat_events):
            # 记录上下文
            if event.get("role") == "user" or event.get("event") == "user_message":
                content = event.get("content")
                if content: context_window.append(content)
            
            # 1. 识别检索动作
            tool_calls = event.get("tool_calls") or []
            for call in tool_calls:
                func = call.get("function", {})
                if func.get("name") == "make_kb_search":
                    query_json = func.get("arguments", "{}")
                    try:
                        query = json.loads(query_json).get("query", "")
                    except:
                        query = query_json
                    
                    # 寻找该 call_id 对应的输出
                    docs = self._find_docs_in_flat_events(flat_events, call.get("id"), i)
                    if docs:
                        last_kb_search = KBResult(query=query, documents=docs, timestamp=event["timestamp"])
                        logger.debug(f"Found KB Search: {query} with {len(docs)} docs")

            # 2. 识别后续执行动作并判定效用
            # 如果当前事件是 tool 返回（非 KB 搜索），且之前有未标记的 KB 搜索
            if event.get("role") == "tool" or event.get("event") == "tool":
                # 排除 KB 搜索自身的返回
                if last_kb_search and event.get("tool_call_id") != getattr(last_kb_search, 'call_id', None):
                    result_content = str(event.get("content", ""))
                    
                    if self.is_step_successful(result_content):
                        # Positive sample
                        for doc in last_kb_search.documents:
                            training_data.append({
                                "query": last_kb_search.query,
                                "document": doc[:1000], # 限制文档长度
                                "label": 1.0,
                                "context": " ".join(context_window[-3:])
                            })
                        last_kb_search = None 
                    elif "error" in result_content.lower() or "failed" in result_content.lower():
                        # Negative sample
                        for doc in last_kb_search.documents:
                            training_data.append({
                                "query": last_kb_search.query,
                                "document": doc[:1000],
                                "label": 0.0,
                                "context": " ".join(context_window[-3:])
                            })
                        last_kb_search = None

        return training_data

    def _find_docs_in_flat_events(self, events: List[Dict], call_id: str, start_idx: int) -> List[str]:
        """在展平的事件流中寻找 tool 输出"""
        for j in range(start_idx, min(start_idx + 20, len(events))):
            ev = events[j]
            if (ev.get("role") == "tool" or ev.get("event") == "tool") and ev.get("tool_call_id") == call_id:
                content = ev.get("content", "")
                # 渗透工具通常会在输出中包含文本，我们需要提取它
                if "EXTERNAL CONTENT START" in content:
                    # 提取原文内容
                    return [content]
                try:
                    data = json.loads(content)
                    if isinstance(data, list): return [str(x) for x in data]
                    return [str(data)]
                except:
                    return [content]
        return []

    def process_all(self):
        """遍历所有日志提取数据并持久化"""
        all_samples = []
        log_files = list(self.logs_dir.glob("cai_*.jsonl"))
        logger.info(f"Found {len(log_files)} log files.")

        for log_file in log_files:
            events = self.parse_log_file(log_file)
            samples = self.extract_training_pairs(events)
            all_samples.extend(samples)
            logger.info(f"Processed {log_file.name}, extracted {len(samples)} samples.")

        # 保存结果
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, 'w', encoding='utf-8') as f:
            for sample in all_samples:
                f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        
        logger.info(f"Finished! Total samples: {len(all_samples)}")
        logger.info(f"Dataset saved to: {self.output_path}")

if __name__ == "__main__":
    labeler = AutoLabeler(
        logs_dir=config.LOGS_DIR,
        output_path=config.DATA_DIR / "utility_dataset.jsonl"
    )
    labeler.process_all()
