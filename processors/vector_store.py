import os
import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any
from processors.failure_detector import RetrievalResult

logger = logging.getLogger("EvoPentest.SearchEngine")

class SimpleSearchEngine:
    """
    轻量级搜索引擎
    实现对 raw_data 目录下爬取数据的真实索引与搜索
    """
    
    def __init__(self, data_dir: str = "raw_data"):
        self.data_dir = Path(data_dir)
        self.index: List[Dict[str, Any]] = []
        self._build_index()

    def _build_index(self):
        """遍历目录构建索引"""
        logger.info(f"Building index from {self.data_dir}...")
        if not self.data_dir.exists():
            logger.warning(f"Data directory {self.data_dir} not found.")
            return

        # 遍历所有 json 和 jsonl 文件
        for file_path in self.data_dir.rglob("*"):
            if file_path.suffix in ['.json', '.jsonl']:
                try:
                    self._process_file(file_path)
                except Exception as e:
                    logger.error(f"Failed to index {file_path}: {e}")
        
        logger.info(f"Index built with {len(self.index)} snippets.")

    def _process_file(self, file_path: Path):
        """解析文件内容"""
        if file_path.suffix == '.jsonl':
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        self._add_to_index(data, file_path.name)
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        self._add_to_index(item, file_path.name)
                elif isinstance(data, dict):
                    self._add_to_index(data, file_path.name)

    def _add_to_index(self, data: Dict[str, Any], source: str):
        """标准化数据并存入索引"""
        # 兼容不同爬虫的数据格式
        title = data.get('title') or data.get('name') or data.get('summary', 'Untitled')
        content = data.get('content') or data.get('body') or data.get('description', '')
        
        if len(content) < 20: # 过滤太短的内容
            return
            
        self.index.append({
            'title': str(title),
            'content': str(content),
            'source': source
        })

    def search(self, query: str, top_k: int = 5) -> List[RetrievalResult]:
        """关键词基础搜索 (模拟 BM25 逻辑)"""
        query_words = set(re.findall(r'\w+', query.lower()))
        if not query_words:
            return []

        scored_results = []
        for doc in self.index:
            content_lower = (doc['title'] + " " + doc['content']).lower()
            
            # 计算简单的词频重叠
            matches = sum(1 for word in query_words if word in content_lower)
            if matches > 0:
                # 基础得分 = 匹配词数 / 总词数 + 长度惩罚
                score = matches / len(query_words)
                scored_results.append((doc, score))

        # 按得分排序
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        # 转换为 RetrievalResult
        results = []
        for doc, score in scored_results[:top_k]:
            results.append(RetrievalResult(
                title=doc['title'],
                content=doc['content'],
                score=score,
                source=doc['source']
            ))
            
        return results
