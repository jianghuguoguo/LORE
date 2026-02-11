"""
Evo-Pentest 自适应检索器
整合失败检测、反思诊断、查询改写和重排序的完整系统
"""

import logging
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from processors.failure_detector import FailureDetector, RetrievalResult, FailureAnalysis
from processors.reflection_diagnoser import ReflectionDiagnoser, DiagnosisResult
from processors.query_rewriter import QueryRewriter, RewrittenQuery
from processors.llm_client import DeepSeekClient
from processors.evo_config import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.AdaptiveRetriever")


@dataclass
class RetrievalStep:
    """单次检索步骤记录"""
    iteration: int
    query: str
    query_source: str  # 'original' or 'rewritten'
    num_results: int
    failure_detected: bool
    diagnoses: List[str]  # 诊断类型列表
    rewritten_queries: List[str]  # 改写查询列表


@dataclass
class AdaptiveRetrievalResult:
    """自适应检索完整结果"""
    final_results: List[RetrievalResult]  # 最终检索结果
    reranked_results: List[RetrievalResult]  # 重排序后结果
    total_iterations: int  # 总迭代次数
    retrieval_history: List[RetrievalStep]  # 检索历史
    success: bool  # 是否成功
    final_query: str  # 最终使用的查询
    
    def to_dict(self):
        """转为字典便于序列化"""
        return {
            'final_results': [asdict(r) for r in self.final_results],
            'reranked_results': [asdict(r) for r in self.reranked_results],
            'total_iterations': self.total_iterations,
            'retrieval_history': [asdict(step) for step in self.retrieval_history],
            'success': self.success,
            'final_query': self.final_query
        }


class UtilityScorer:
    """
    效用度评分器
    使用训练好的Cross-Encoder模型对文档重排序
    """
    
    def __init__(self, model_path: Path = None, device: str = 'cpu'):
        """
        Args:
            model_path: 模型路径
            device: 设备 (cpu/cuda)
        """
        self.device = torch.device(device)
        
        if model_path and model_path.exists():
            logger.info(f"Loading trained utility scorer from {model_path}")
            self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            self.model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
            self.model.to(self.device)
            self.model.eval()
            self.enabled = True
        else:
            logger.warning(f"Utility scorer model not found at {model_path}, using score passthrough")
            self.enabled = False
    
    def score(self, query: str, documents: List[str]) -> List[float]:
        """
        为查询-文档对打分
        
        Args:
            query: 查询文本
            documents: 文档列表
        
        Returns:
            分数列表(与documents顺序对应)
        """
        if not self.enabled:
            # 如果模型未加载,返回原始分数
            return [1.0] * len(documents)
        
        scores = []
        
        with torch.no_grad():
            for doc in documents:
                # Cross-Encoder输入格式
                encoding = self.tokenizer(
                    query,
                    doc,
                    max_length=512,
                    padding='max_length',
                    truncation=True,
                    return_tensors='pt'
                )
                
                input_ids = encoding['input_ids'].to(self.device)
                attention_mask = encoding['attention_mask'].to(self.device)
                
                # 前向传播
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                score = outputs.logits.squeeze(-1).item()
                scores.append(score)
        
        return scores
    
    def rerank(self, query: str, results: List[RetrievalResult]) -> List[RetrievalResult]:
        """
        重排序检索结果
        
        Args:
            query: 查询文本
            results: 检索结果列表
        
        Returns:
            重排序后的结果列表
        """
        if not results:
            return results
        
        # 提取文档文本
        documents = [f"{r.title}\n{r.content}" for r in results]
        
        # 打分
        utility_scores = self.score(query, documents)
        
        # 创建新的结果列表(更新score)
        reranked = []
        for res, score in zip(results, utility_scores):
            new_res = RetrievalResult(
                title=res.title,
                content=res.content,
                score=score,
                source=res.source
            )
            reranked.append(new_res)
        
        # 按分数降序排列
        reranked.sort(key=lambda x: x.score, reverse=True)
        return reranked


class AdaptiveRetriever:
    """
    自适应检索器 - System 2 Reflection核心
    实现探索-利用平衡的迭代检索策略
    """
    
    def __init__(self,
                 knowledge_base_search_func,
                 utility_scorer: UtilityScorer = None,
                 max_iterations: int = 3,
                 top_k: int = 10):
        """
        Args:
            knowledge_base_search_func: 知识库搜索函数 (query: str) -> List[RetrievalResult]
            utility_scorer: 效用度评分器
            max_iterations: 最大迭代次数
            top_k: 每次检索返回的文档数
        """
        self.kb_search = knowledge_base_search_func
        self.utility_scorer = utility_scorer or UtilityScorer(model_path=config.UTILITY_MODEL_PATH)
        self.max_iterations = max_iterations
        self.top_k = top_k
        
        # 初始化 LLM 客户端
        self.llm_client = DeepSeekClient(api_key=config.DEEPSEEK_API_KEY)
        
        # 初始化子模块
        self.failure_detector = FailureDetector(llm_client=self.llm_client, top_k=top_k)
        self.diagnoser = ReflectionDiagnoser(llm_client=self.llm_client)
        self.rewriter = QueryRewriter(llm_client=self.llm_client)
        
        # 优化策略：成功路径缓存 (Query Mapping DB)
        self.cache_path = config.DATA_DIR / "hit_query_cache.json"
        self.query_cache = self._load_cache()
        
        # 检索历史
        self.retrieval_history = []

    def _load_cache(self) -> Dict[str, str]:
        """加载成功路径缓存"""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load query cache: {e}")
        return {}

    def _save_cache(self):
        """持久化缓存"""
        try:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.query_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save query cache: {e}")

    def summarize_experience(self, query: str, result: AdaptiveRetrievalResult) -> str:
        """
        对本次检索过程总结经验 (System 2 总结)
        """
        # 构建总结提示词
        history_text = ""
        for step in result.retrieval_history:
            history_text += f"\nRound {step.iteration}: Query: {step.query}\n"
            history_text += f"  Status: {'Failed' if step.failure_detected else 'Success'}\n"
            if step.diagnoses:
                history_text += f"  Diagnosis: {', '.join(step.diagnoses)}\n"
            if step.rewritten_queries:
                history_text += f"  Rewrites: {', '.join(step.rewritten_queries)}\n"

        prompt = f"""
你是一个高级渗透测试专家。请根据以下[检索轨迹]总结针对“{query}”这一目标的渗透测试经验。

[检索轨迹]
{{history_text}}

[最终结果]
是否成功找到有效工具/Payload: {{"是" if result.success else "否"}}
最终查询: {{result.final_query}}

请输出一段精炼的经验总结，包含：
1. 遇到的主要难点 (如术语漂移、粒度过细等)
2. 成功的改写策略或关键词
3. 对未来类似攻击的建议
"""
        # 填充 prompt (手动格式化以避免嵌套字典冲突)
        prompt = prompt.replace("{{history_text}}", history_text)
        prompt = prompt.replace("{{\"是\" if result.success else \"否\"}}", "是" if result.success else "否")
        prompt = prompt.replace("{{result.final_query}}", str(result.final_query))

        try:
            summary = self.llm_client.chat(prompt)
            return summary
        except Exception as e:
            return f"总结失败: {str(e)}"
    
    def retrieve(self, 
                 query: str,
                 target_info: str = "") -> AdaptiveRetrievalResult:
        """
        自适应检索主流程
        
        Args:
            query: 原始查询
            target_info: 目标系统信息
        
        Returns:
            完整检索结果
        """
        logger.info("=" * 80)
        logger.info(f"Starting Adaptive Retrieval for: {query}")
        logger.info("=" * 80)
        
        self.retrieval_history = []
        
        # 优化策略 1: 检查缓存 (Experience Replay)
        current_query = query
        if query.lower() in self.query_cache:
            current_query = self.query_cache[query.lower()]
            logger.info(f"✨ Cache Hit! Redirecting '{query}' to proven successful query: '{current_query}'")
        
        best_results = []
        iteration = 0
        
        while iteration < self.max_iterations:
            iteration += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"Iteration {iteration}/{self.max_iterations}")
            logger.info(f"Query: {current_query}")
            logger.info(f"{'='*60}")
            
            # Step 1: 执行检索
            results = self.kb_search(current_query)
            logger.info(f"Retrieved {len(results)} documents")
            
            # Step 2: 失败检测
            failure_analysis = self.failure_detector.detect(
                query=current_query,
                results=results,
                target_info=target_info
            )
            
            logger.info(f"\nFailure Detection:")
            logger.info(failure_analysis)
            
            # 记录本次迭代
            step = RetrievalStep(
                iteration=iteration,
                query=current_query,
                query_source='original' if iteration == 1 and current_query == query else 'rewritten',
                num_results=len(results),
                failure_detected=failure_analysis.is_failed,
                diagnoses=[],
                rewritten_queries=[]
            )
            
            # Step 3: 如果成功,执行重排序并返回
            if not failure_analysis.is_failed:
                logger.info("\n✓ Retrieval successful!")
                
                # 优化策略 1: 更新缓存
                if query.lower() != current_query.lower():
                    self.query_cache[query.lower()] = current_query
                    self._save_cache()
                    logger.info(f"💾 Saved success path to cache: {query} -> {current_query}")
                
                # 使用Utility Scorer重排序
                reranked = self.utility_scorer.rerank(current_query, results)
                logger.info(f"Reranked with Utility Scorer")
                
                step.diagnoses = []
                step.rewritten_queries = []
                self.retrieval_history.append(step)
                
                return AdaptiveRetrievalResult(
                    final_results=results,
                    reranked_results=reranked[:self.top_k],
                    total_iterations=iteration,
                    retrieval_history=self.retrieval_history,
                    success=True,
                    final_query=current_query
                )
            
            # Step 4: 失败诊断
            diagnoses = self.diagnoser.diagnose(
                query=current_query,
                failure_analysis=failure_analysis,
                results=results,
                target_info=target_info
            )
            
            logger.info(f"\nDiagnosis Results ({len(diagnoses)} issues found):")
            for diag in diagnoses:
                logger.info(f"\n{diag}")
            
            step.diagnoses = [d.diagnosis_type.value for d in diagnoses]
            
            # Step 5: 查询改写 (带锚点约束)
            rewritten_queries = self.rewriter.rewrite_with_anchors(
                original_query=current_query,
                diagnoses=diagnoses,
                target_info=target_info,
                num_variants=3
            )
            
            logger.info(f"\nRewritten Queries ({len(rewritten_queries)} variants):")
            for i, rq in enumerate(rewritten_queries, 1):
                logger.info(f"\n  Variant {i}: {rq.query}")
                logger.info(f"  Strategy: {rq.strategy.value}")
                logger.info(f"  Rationale: {rq.rationale}")
            
            step.rewritten_queries = [rq.query for rq in rewritten_queries]
            self.retrieval_history.append(step)
            
            # Step 6: 选择最佳改写查询进入下一轮
            if rewritten_queries:
                # 选择置信度最高的查询
                best_rewrite = rewritten_queries[0]
                current_query = best_rewrite.query
                logger.info(f"\n→ Selected query for next iteration: {current_query}")
            else:
                logger.warning("No rewritten queries generated, stopping")
                break
            
            # 保存当前最佳结果
            if not best_results or len(results) > len(best_results):
                best_results = results
        
        # 达到最大迭代次数仍未成功
        logger.info(f"\n✗ Reached max iterations ({self.max_iterations}) without success")
        
        # 返回最佳结果(可能不完美)
        reranked = self.utility_scorer.rerank(query, best_results)
        
        return AdaptiveRetrievalResult(
            final_results=best_results,
            reranked_results=reranked[:self.top_k],
            total_iterations=iteration,
            retrieval_history=self.retrieval_history,
            success=False,
            final_query=current_query
        )
    
    def save_retrieval_log(self, result: AdaptiveRetrievalResult, output_path: Path):
        """保存检索日志用于分析"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        
        logger.info(f"Retrieval log saved to {output_path}")


if __name__ == "__main__":
    from processors.ragflow_client import RAGFlowClient
    from processors.evo_config import config

    # 初始化 RAGFlow 客户端
    ragflow_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)
    
    # 真实知识库搜索函数 (读取语料库)
    def real_kb_search(query: str) -> List[RetrievalResult]:
        """从 RAGFlow 语料库实时检索"""
        logger.info(f"🔍 Searching RAGFlow corpus for: {query}")
        response = ragflow_client.search(
            query=query,
            dataset_id=config.RAGFLOW_DATASET_ID,
            top_k=10
        )
        
        # 转换为 RetrievalResult 格式
        results = []
        chunks = response.get('data', {}).get('chunks', [])
        for item in chunks:
            results.append(RetrievalResult(
                title=item.get('document_name', 'Unknown'),
                content=item.get('content_with_weight', item.get('content', '')),
                score=item.get('similarity', 0.0),
                source='ragflow_corpus'
            ))
        
        return results
    
    # 初始化自适应检索器
    retriever = AdaptiveRetriever(
        knowledge_base_search_func=real_kb_search,
        max_iterations=3,
        top_k=5
    )
    
    # 执行检索任务
    test_query = "CVE-2017-10271 exploit"
    target_env = "WebLogic 10.3.6.0"
    
    logger.info(f"🚀 Starting Real Adaptive Retrieval: {test_query}")
    result = retriever.retrieve(
        query=test_query,
        target_info=target_env
    )
    
    # 如果检索成功且有高质量结果，则生成经验并填写到经验库
    if result.success and result.reranked_results:
        logger.info("✨ Retrieval successful, generating experience summary...")
        experience = retriever.summarize_experience(test_query, result)
        
        logger.info(f"📝 Pushing experience to Experience Library ({config.RAGFLOW_EXPR_ID})...")
        push_success = ragflow_client.push_structured_summary(
            dataset_id=config.RAGFLOW_EXPR_ID,
            title=f"Pentest Experience: {test_query}",
            content=experience
        )
        
        if push_success:
            logger.info("✅ Experience successfully recorded in RAGFlow!")
        else:
            logger.error("❌ Failed to push experience to RAGFlow")
    
    # 打印最终结果
    logger.info("\n" + "=" * 80)
    logger.info("FINAL RESULTS SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Status: {'Success' if result.success else 'Failed'}")
    logger.info(f"Total Iterations: {result.total_iterations}")
    logger.info(f"Final Optimized Query: {result.final_query}")
    
    if result.reranked_results:
        logger.info(f"\nTop Result: {result.reranked_results[0].title}")
        logger.info(f"Snippet: {result.reranked_results[0].content[:200]}...")
