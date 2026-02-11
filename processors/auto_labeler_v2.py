"""
Evo-Pentest Auto-Labeler V2
改进版: 生成平衡的查询-文档标注数据
主要改进:
1. 只标注成功攻击前的最近一次搜索
2. 基于文档内容相关性打分(0-1)
3. 确保每个查询有合理的正负样本分布
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict
from difflib import SequenceMatcher

try:
    from processors.evo_config import config
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from processors.evo_config import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AutoLabelerV2")


class ImprovedAutoLabeler:
    """改进版自动标注器"""
    
    # 渗透测试无关的停用词，防止干扰关键词匹配
    STOPWORDS = {
        'the', 'and', 'with', 'from', 'this', 'that', 'your', 'will', 'have', 
        'been', 'data', 'user', 'info', 'event', 'status', 'time', 'type',
        'content', 'input', 'output', 'result', 'name', 'call', 'tool'
    }
    
    def __init__(self, min_positive_ratio=0.1, max_positive_ratio=0.9):
        """
        Args:
            min_positive_ratio: 每个查询最小正样本比例
            max_positive_ratio: 每个查询最大正样本比例
        """
        self.min_pos_ratio = min_positive_ratio
        self.max_pos_ratio = max_positive_ratio
        
    def extract_solution_keywords(self, event: Dict) -> set:
        """
        从成功event中提取解决方案关键词，并过滤停用词
        """
        keywords = set()
        raw_words = []
        
        # 从内容和工具输出中提取
        text_source = f"{event.get('content', '')} {event.get('tool_output', '')}"
        
        # 1. 提取 CVE (保留核心语义)
        keywords.update(re.findall(r'cve-\d{4}-\d+', text_source.lower()))
        
        # 2. 提取技术单词并过滤停用词
        raw_words = re.findall(r'\b[a-z]{3,15}\b', text_source.lower())
        keywords.update([w for w in raw_words if w not in self.STOPWORDS])
        
        return keywords
    
    def calculate_relevance(self, document: str, keywords: set) -> float:
        """
        计算文档与关键词集合的相关度
        
        Returns:
            0-1的相关度分数
        """
        if not keywords:
            return 0.0
        
        doc_lower = document.lower()
        
        # 方法1: 关键词匹配率
        matched = sum(1 for kw in keywords if kw in doc_lower)
        keyword_score = matched / len(keywords)
        
        # 方法2: 字符级相似度(取文档前500字符)
        doc_sample = doc_lower[:500]
        keywords_str = ' '.join(keywords)
        similarity = SequenceMatcher(None, doc_sample, keywords_str).ratio()
        
        # 综合评分
        relevance = 0.7 * keyword_score + 0.3 * similarity
        
        return min(1.0, relevance)
    
    def _find_success_events(self, events: List[Dict]) -> List[Dict]:
        """找到表现出成功的事件 (V2: 增强型判定)"""
        success_events = []
        
        for event in events:
            # 1. 显式的成功标记
            if event.get('success') is True:
                success_events.append(event)
                continue
            
            # 2. 角色为tool且content包含成功迹象
            content = event.get('content', '')
            if event.get('role') == 'tool' and isinstance(content, str):
                content_lower = content.lower()
                # 显式的JSON成功字段
                if '"success": true' in content_lower or '"success":true' in content_lower:
                    success_events.append(event)
                    continue
                # 关键资产发现
                if any(ind in content_lower for ind in ['flag{', 'root:', 'id=0(root)', 'uid=0']):
                    success_events.append(event)
                    continue
            
            # 3. 检查 result, content, tool_output 字段
            text_fields = [
                str(event.get('content', '')),
                str(event.get('tool_output', '')),
                str(event.get('result', '')),
            ]
            
            combined_text = ' '.join(str(f) for f in text_fields).lower()
            
            # 使用正则匹配
            is_success = any(
                re.search(indicator, combined_text, re.IGNORECASE)
                for indicator in config.SUCCESS_INDICATORS
            )
            
            if is_success:
                success_events.append(event)
        
        return success_events
    
    def _find_nearest_search(self, events: List[Dict], success_event: Dict) -> Tuple[Dict, List[Dict]]:
        """
        找到成功event前最近的一次make_kb_search或search_knowledge调用及其文档
        
        Returns:
            (search_event, documents)
        """
        try:
            success_idx = events.index(success_event)
        except ValueError:
            return (None, [])
        
        # 从成功event向前查找 (增加到50步以处理长对话)
        for i in range(success_idx - 1, max(0, success_idx - 50), -1):
            event = events[i]
            
            # 处理多种日志格式中可能出现的工具调用
            tool_calls = []
            if event.get('event') == 'assistant_message' or 'tool_calls' in event:
                tool_calls = event.get('tool_calls', [])
            elif 'choices' in event:
                try:
                    tool_calls = event['choices'][0]['message'].get('tool_calls', [])
                except: pass
            
            # 也可以检查 legacy tool_name 格式
            if not tool_calls and event.get('tool_name') in ['make_kb_search', 'search_knowledge']:
                # 构造伪 tool_call 以统一处理
                tool_calls = [{'function': {'name': event.get('tool_name'), 
                                            'arguments': event.get('tool_input', {})}}]

            for tc in tool_calls:
                func = tc.get('function', {})
                tool_name = func.get('name')
                
                if tool_name in ['make_kb_search', 'search_knowledge']:
                    try:
                        args = func.get('arguments', '{}')
                        if isinstance(args, str):
                            args = json.loads(args)
                        query = args.get('query', '')
                        
                        # 查找紧随其后的工具结果 (通常在接下来的几步内)
                        call_id = tc.get('id', '')
                        for j in range(i + 1, min(len(events), i + 8)):
                            res_event = events[j]
                            # 匹配 call_id 或其 role=="tool" 且包含搜索结果特征
                            is_match = (call_id and res_event.get('tool_call_id') == call_id) or \
                                       (res_event.get('role') == 'tool' and 'EXTERNAL CONTENT START' in str(res_event.get('content', '')))
                            
                            if is_match:
                                content = res_event.get('content', '')
                                if not content: continue
                                
                                # 解析搜索结果 (V2 兼容更多格式)
                                docs = []
                                # 格式 1: 带分隔符的 log 格式
                                if "====================EXTERNAL CONTENT START====================" in content:
                                    snippets = content.split("====================EXTERNAL CONTENT START====================")
                                    raw_docs = re.split(r'# \d+\.', snippets[1])
                                    for rd in raw_docs:
                                        if rd.strip():
                                            docs.append({'title': 'Search Result', 'content': rd.strip()})
                                # 格式 2: JSON 结果格式
                                elif isinstance(content, str) and content.strip().startswith('{'):
                                    try:
                                        data = json.loads(content)
                                        for r in data.get('results', []):
                                            docs.append({
                                                'title': r.get('title', 'Result'),
                                                'content': r.get('content', r.get('snippet', ''))
                                            })
                                    except: pass

                                if query and docs:
                                    # 构造统一的 search_event
                                    search_event = {'query': query, 'original_event': event}
                                    return (search_event, docs)
                    except:
                        continue
        
        return (None, [])
    
    def extract_training_pairs_v2(self, log_file: Path) -> List[Dict]:
        """
        V2版本: 提取平衡的训练样本
        修正: 逐行读取JSONL并实现Top-1强制正样本策略
        """
        logger.info(f"Processing {log_file.name}...")
        
        all_events = []
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip(): continue
                    event = json.loads(line)
                    all_events.append(event)
                    # 展平嵌套的 messages
                    if 'messages' in event:
                        all_events.extend(event['messages'])
        except Exception as e:
            logger.error(f"Error reading {log_file}: {e}")
            return []
        
        if not all_events:
            return []
        
        # 找到所有成功事件
        success_events = self._find_success_events(all_events)
        
        if not success_events:
            logger.warning(f"No success events found in {log_file.name}")
            return []
        
        logger.info(f"Found {len(success_events)} success events")
        
        # 收集训练样本
        samples = []
        query_doc_pairs = set()  # 去重
        
        for success_event in success_events:
            # 提取解决方案关键词
            solution_keywords = self.extract_solution_keywords(success_event)
            
            # 找到最近的一次搜索
            search_event, docs = self._find_nearest_search(all_events, success_event)
            
            if not search_event or not docs:
                continue
            
            # V2版从 search_event 直接拿 query
            query = search_event.get('query', '')
            if not query:
                continue

            # 为当前检索的一组文档记录评分，用于 Top-1 策略
            iter_results = []
            max_rel = -1.0
            
            for doc in docs:
                doc_text = f"{doc['title']}\n{doc['content']}"
                relevance = self.calculate_relevance(doc_text, solution_keywords)
                iter_results.append((doc_text, relevance))
                if relevance > max_rel:
                    max_rel = relevance

            # 标注逻辑
            for doc_text, relevance in iter_results:
                # 去重
                pair_key = (query, doc_text[:100])
                if pair_key in query_doc_pairs:
                    continue
                query_doc_pairs.add(pair_key)
                
                # 判定规则: 
                # 1. 超过阈值 0.3 即为正样本
                # 2. 如果没过阈值但它是本组最高分, 且最高分 > 0, 强制作为正样本 (Top-1 策略)
                is_top_one = (relevance == max_rel and max_rel > 0)
                label = 1.0 if (relevance >= 0.3 or is_top_one) else 0.0
                
                samples.append({
                    "query": query,
                    "document": doc_text[:config.MAX_LENGTH],
                    "label": label,
                    "relevance_score": relevance,
                    "context": f"Success event: {success_event.get('event_id', 'unknown')}"
                })
        
        return samples
    
    def process_all_logs(self, log_dir: Path, output_path: Path):
        """处理所有日志文件并生成平衡数据集"""
        all_samples = []
        
        for log_file in log_dir.glob("*.jsonl"):
            samples = self.extract_training_pairs_v2(log_file)
            all_samples.extend(samples)
        
        logger.info(f"\nTotal raw samples: {len(all_samples)}")
        
        # 按查询分组
        query_groups = defaultdict(list)
        for sample in all_samples:
            query_groups[sample['query']].append(sample)
        
        # 过滤并平衡每个查询
        balanced_samples = []
        filtered_queries = 0
        
        for query, samples in query_groups.items():
            total = len(samples)
            positive = sum(1 for s in samples if s['label'] == 1.0)
            pos_ratio = positive / total if total > 0 else 0
            
            # 过滤掉不平衡的查询
            if pos_ratio < self.min_pos_ratio or pos_ratio > self.max_pos_ratio:
                logger.warning(
                    f"Filtered query with {pos_ratio:.1%} positive ratio: {query[:60]}"
                )
                filtered_queries += 1
                continue
            
            balanced_samples.extend(samples)
        
        logger.info(f"\n{'='*60}")
        logger.info("Data Balancing Results:")
        logger.info(f"  Original queries: {len(query_groups)}")
        logger.info(f"  Filtered queries: {filtered_queries}")
        logger.info(f"  Balanced queries: {len(query_groups) - filtered_queries}")
        logger.info(f"  Original samples: {len(all_samples)}")
        logger.info(f"  Balanced samples: {len(balanced_samples)}")
        logger.info(f"{'='*60}\n")
        
        # 保存数据集
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            for sample in balanced_samples:
                # 移除调试字段
                clean_sample = {
                    'query': sample['query'],
                    'document': sample['document'],
                    'label': sample['label'],
                    'context': sample['context']
                }
                f.write(json.dumps(clean_sample, ensure_ascii=False) + '\n')
        
        logger.info(f"✓ Saved balanced dataset to {output_path}")
        
        # 生成统计报告
        self._generate_stats_report(balanced_samples)
    
    def _generate_stats_report(self, samples: List[Dict]):
        """生成数据统计报告"""
        query_groups = defaultdict(list)
        for sample in samples:
            query_groups[sample['query']].append(sample)
        
        logger.info("\nQuery Distribution:")
        for query, group in sorted(query_groups.items(), key=lambda x: len(x[1]), reverse=True):
            total = len(group)
            positive = sum(1 for s in group if s['label'] == 1.0)
            ratio = positive / total
            logger.info(f"  {total:3d} samples ({positive:2d} pos, {ratio:.1%}): {query[:60]}")


def main():
    """主函数"""
    logger.info("=" * 80)
    logger.info("Evo-Pentest Auto-Labeler V2 - Balanced Dataset Generation")
    logger.info("=" * 80)
    
    labeler = ImprovedAutoLabeler(
        min_positive_ratio=0.1,  # 至少10%正样本
        max_positive_ratio=0.9   # 至多90%正样本
    )
    
    log_dir = Path("logs")
    output_path = config.DATA_DIR / "utility_dataset_balanced.jsonl"
    
    labeler.process_all_logs(log_dir, output_path)
    
    logger.info("\n✓ V2 Labeling completed successfully!")


if __name__ == "__main__":
    main()
