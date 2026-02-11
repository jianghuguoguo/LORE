"""
数据平衡工具: 从现有utility_dataset.jsonl中过滤出平衡的查询子集
"""

import json
import logging
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DataBalancer")


def balance_dataset(input_path: Path, output_path: Path, 
                   min_ratio=0.1, max_ratio=0.9, min_samples=5):
    """
    Args:
        min_ratio: 最小正样本比例
        max_ratio: 最大正样本比例
        min_samples: 每个查询最少样本数
    """
    # 读取原始数据
    samples = []
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            samples.append(json.loads(line))
    
    logger.info(f"Loaded {len(samples)} samples")
    
    # 按查询分组
    query_groups = defaultdict(list)
    for sample in samples:
        query_groups[sample['query']].append(sample)
    
    logger.info(f"Found {len(query_groups)} unique queries\n")
    
    # 过滤平衡的查询
    balanced_samples = []
    
    logger.info("Query Analysis:")
    for query, group in sorted(query_groups.items(), key=lambda x: len(x[1]), reverse=True):
        total = len(group)
        positive = sum(1 for s in group if s['label'] == 1.0)
        ratio = positive / total
        
        status = "✓ KEEP" if (min_ratio <= ratio <= max_ratio and total >= min_samples) else "✗ FILTER"
        logger.info(f"  [{status}] {total:3d} samples ({positive:2d} pos, {ratio:.1%}): {query[:60]}")
        
        if status == "✓ KEEP":
            balanced_samples.extend(group)
    
    # 保存平衡数据集
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in balanced_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    # 统计
    final_queries = len(set(s['query'] for s in balanced_samples))
    final_positive = sum(1 for s in balanced_samples if s['label'] == 1.0)
    
    logger.info(f"\n{'='*60}")
    logger.info("Balancing Results:")
    logger.info(f"  Original: {len(samples)} samples, {len(query_groups)} queries")
    logger.info(f"  Balanced: {len(balanced_samples)} samples, {final_queries} queries")
    logger.info(f"  Positive ratio: {final_positive}/{len(balanced_samples)} = {final_positive/len(balanced_samples):.1%}")
    logger.info(f"  Saved to: {output_path}")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    from processors.evo_config import config
    
    balance_dataset(
        input_path=config.DATA_DIR / "utility_dataset_balanced.jsonl",
        output_path=config.DATA_DIR / "utility_dataset_final.jsonl",
        min_ratio=0.05,  # 5%-95% 
        max_ratio=0.95,
        min_samples=2  # 至少2个样本
    )
