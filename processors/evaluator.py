"""
Evo-Pentest 评估指标模块
实现学术界公认的信息检索评估指标：MRR, NDCG@K, MAP, Precision@K
"""

import numpy as np
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger("EvoPentest.Evaluator")


class RankingMetrics:
    """排序任务评估指标计算器"""
    
    @staticmethod
    def mean_reciprocal_rank(rankings: List[List[Tuple[str, float]]]) -> float:
        """
        平均倒数排名 (MRR)
        衡量第一个相关文档的平均排名
        
        Args:
            rankings: List of [(doc_id, relevance_score), ...]
                      relevance_score: 1.0 for relevant, 0.0 for irrelevant
        
        Returns:
            MRR score (0-1)
        """
        reciprocal_ranks = []
        for ranking in rankings:
            for rank, (doc_id, relevance) in enumerate(ranking, start=1):
                if relevance > 0.5:  # 认为是正样本
                    reciprocal_ranks.append(1.0 / rank)
                    break
            else:
                # 如果没有找到相关文档，贡献 0
                reciprocal_ranks.append(0.0)
        
        return np.mean(reciprocal_ranks) if reciprocal_ranks else 0.0
    
    @staticmethod
    def ndcg_at_k(rankings: List[List[Tuple[str, float]]], k: int = 10) -> float:
        """
        归一化折损累积增益 (NDCG@K)
        考虑了排序位置和多级相关性的综合指标
        
        Args:
            rankings: List of [(doc_id, relevance_score), ...]
            k: 只考虑前 K 个结果
        
        Returns:
            NDCG@K score (0-1)
        """
        ndcg_scores = []
        
        for ranking in rankings:
            # 截断到前 K
            ranking_k = ranking[:k]
            
            # 计算 DCG (Discounted Cumulative Gain)
            dcg = 0.0
            for i, (doc_id, relevance) in enumerate(ranking_k, start=1):
                dcg += relevance / np.log2(i + 1)
            
            # 计算 IDCG (Ideal DCG) - 理想情况下的排序
            ideal_relevances = sorted([rel for _, rel in ranking], reverse=True)[:k]
            idcg = 0.0
            for i, relevance in enumerate(ideal_relevances, start=1):
                idcg += relevance / np.log2(i + 1)
            
            # 归一化
            ndcg = dcg / idcg if idcg > 0 else 0.0
            ndcg_scores.append(ndcg)
        
        return np.mean(ndcg_scores) if ndcg_scores else 0.0
    
    @staticmethod
    def precision_at_k(rankings: List[List[Tuple[str, float]]], k: int = 5) -> float:
        """
        Precision@K: 前 K 个结果中相关文档的比例
        
        Args:
            rankings: List of [(doc_id, relevance_score), ...]
            k: 只考虑前 K 个结果
        
        Returns:
            Precision@K score (0-1)
        """
        precisions = []
        
        for ranking in rankings:
            ranking_k = ranking[:k]
            relevant_count = sum(1 for _, rel in ranking_k if rel > 0.5)
            precision = relevant_count / len(ranking_k) if ranking_k else 0.0
            precisions.append(precision)
        
        return np.mean(precisions) if precisions else 0.0
    
    @staticmethod
    def average_precision(ranking: List[Tuple[str, float]]) -> float:
        """
        单个查询的 Average Precision
        
        Args:
            ranking: [(doc_id, relevance_score), ...]
        
        Returns:
            AP score (0-1)
        """
        precisions = []
        relevant_count = 0
        
        for i, (doc_id, relevance) in enumerate(ranking, start=1):
            if relevance > 0.5:
                relevant_count += 1
                precision_at_i = relevant_count / i
                precisions.append(precision_at_i)
        
        return np.mean(precisions) if precisions else 0.0
    
    @staticmethod
    def mean_average_precision(rankings: List[List[Tuple[str, float]]]) -> float:
        """
        Mean Average Precision (MAP)
        所有查询的 AP 的平均值
        
        Args:
            rankings: List of [(doc_id, relevance_score), ...]
        
        Returns:
            MAP score (0-1)
        """
        aps = [RankingMetrics.average_precision(r) for r in rankings]
        return np.mean(aps) if aps else 0.0


class UtilityEvaluator:
    """渗透知识效用度评估器"""
    
    def __init__(self):
        self.metrics = RankingMetrics()
    
    def evaluate(self, predictions: List[Tuple[str, str, float]], 
                 ground_truth: List[Tuple[str, str, float]],
                 k_values: List[int] = [3, 5, 10]) -> Dict[str, float]:
        """
        综合评估模型性能
        
        Args:
            predictions: [(query, doc, predicted_score), ...]
            ground_truth: [(query, doc, true_label), ...]
            k_values: 需要计算的 K 值列表
        
        Returns:
            评估指标字典
        """
        # 按查询分组
        query_groups = {}
        for query, doc, pred_score in predictions:
            if query not in query_groups:
                query_groups[query] = []
            
            # 找到对应的真实标签
            true_label = 0.0
            for q, d, label in ground_truth:
                if q == query and d == doc:
                    true_label = label
                    break
            
            query_groups[query].append((doc, true_label))
        
        # 按预测分数排序
        rankings = []
        for query in query_groups:
            # 获取该查询的所有（文档，真实标签）
            docs_labels = query_groups[query]
            
            # 按预测分数排序（需要重新获取预测分数）
            query_preds = [(doc, label, pred_score) 
                          for q, doc, pred_score in predictions if q == query]
            
            # 合并真实标签
            ranked = []
            for doc, _, pred_score in query_preds:
                true_label = next((label for d, label in docs_labels if d == doc), 0.0)
                ranked.append((doc, true_label, pred_score))
            
            # 按预测分数降序排列
            ranked.sort(key=lambda x: x[2], reverse=True)
            rankings.append([(doc, label) for doc, label, _ in ranked])
        
        # 计算各项指标
        results = {
            "MRR": self.metrics.mean_reciprocal_rank(rankings),
            "MAP": self.metrics.mean_average_precision(rankings),
        }
        
        for k in k_values:
            results[f"NDCG@{k}"] = self.metrics.ndcg_at_k(rankings, k)
            results[f"Precision@{k}"] = self.metrics.precision_at_k(rankings, k)
        
        return results
    
    def print_results(self, results: Dict[str, float]):
        """格式化打印评估结果"""
        logger.info("=" * 60)
        logger.info("Evaluation Results:")
        logger.info("-" * 60)
        for metric, score in sorted(results.items()):
            logger.info(f"  {metric:20s}: {score:.4f}")
        logger.info("=" * 60)


if __name__ == "__main__":
    # 测试评估指标
    logging.basicConfig(level=logging.INFO)
    
    evaluator = UtilityEvaluator()
    
    # 模拟数据
    predictions = [
        ("WebLogic exploit", "doc1", 0.9),
        ("WebLogic exploit", "doc2", 0.7),
        ("WebLogic exploit", "doc3", 0.3),
    ]
    
    ground_truth = [
        ("WebLogic exploit", "doc1", 1.0),
        ("WebLogic exploit", "doc2", 0.0),
        ("WebLogic exploit", "doc3", 1.0),
    ]
    
    results = evaluator.evaluate(predictions, ground_truth)
    evaluator.print_results(results)
