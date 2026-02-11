import logging
import sys
from pathlib import Path
from typing import List

# 添加项目根目录到路径
sys.path.append(str(Path(__file__).parent.parent))

from processors.adaptive_retriever import AdaptiveRetriever, RetrievalResult
from processors.llm_client import DeepSeekClient
from processors.vector_store import SimpleSearchEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Test.LLM")

def test_real_llm_flow():
    """测试真实 LLM 集成的完整流程"""
    logger.info("🚀 Starting Real LLM Integration Test...")
    
    # 使用真实搜索引擎
    search_engine = SimpleSearchEngine(data_dir=str(Path(__file__).parent.parent / "raw_data"))
    
    retriever = AdaptiveRetriever(
        knowledge_base_search_func=search_engine.search,
        max_iterations=2,
        top_k=5
    )
    
    # 一个非常模糊且带有 CVE 的查询，预期触发：
    # 1. 失败检测 (Heuristic + LLM)
    # 2. 诊断 (Heuristic + LLM)
    # 3. 改写 (LLM)
    query = "CVE-2017-10271"
    target = "WebLogic server 10.3.6"
    
    result = retriever.retrieve(query, target)
    
    logger.info(f"✅ Final Result Success: {result.success}")
    logger.info(f"Final Query Used: {result.final_query}")
    
    for i, step in enumerate(result.retrieval_history):
        logger.info(f"Step {i+1}: Query='{step.query}', FailureDetected={step.failure_detected}")
        if step.diagnoses:
            logger.info(f"  Diagnoses: {step.diagnoses}")
        if step.rewritten_queries:
            logger.info(f"  Rewrites: {step.rewritten_queries}")

if __name__ == "__main__":
    test_real_llm_flow()
