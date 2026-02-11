"""
Evo-Pentest Step 3 使用示例
展示如何在实际渗透测试场景中使用自适应检索系统
"""

import logging
from pathlib import Path
from typing import List

from processors.adaptive_retriever import (
    AdaptiveRetriever, 
    UtilityScorer, 
    RetrievalResult
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Usage.Example")


def integrate_with_ragflow():
    """
    配置并返回 RAGFlow 集成的自适应检索器
    """
    from processors.ragflow_client import RAGFlowClient
    from processors.evo_config import config
    
    ragflow_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)
    
    # 1. 定义知识库搜索函数 (读取语料库)
    def kb_search(query: str) -> List[RetrievalResult]:
        """调用RAGFlow的搜索API"""
        response = ragflow_client.search(
            query=query,
            dataset_id=config.RAGFLOW_DATASET_ID,
            top_k=10
        )
        
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
    
    # 2. 加载训练好的 Utility Scorer (如果存在)
    model_path = config.UTILITY_MODEL_PATH
    utility_scorer = UtilityScorer(model_path=model_path if model_path.exists() else None)
    
    # 3. 创建自适应检索器
    retriever = AdaptiveRetriever(
        knowledge_base_search_func=kb_search,
        utility_scorer=utility_scorer,
        max_iterations=3,
        top_k=10
    )
    
    return retriever, ragflow_client


def penetration_test_scenario():
    """
    完整渗透测试场景演示
    """
    logger.info("=" * 80)
    logger.info("渗透测试场景：WebLogic服务器攻击")
    logger.info("=" * 80)
    
    # 真实知识库搜索（读取语料库）
    from processors.ragflow_client import RAGFlowClient
    from processors.evo_config import config
    
    ragflow_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)

    def real_kb_search(query: str) -> List[RetrievalResult]:
        """从 RAGFlow 语料库实时检索"""
        logger.info(f"🔍 实时检索语料库: {query}")
        response = ragflow_client.search(
            query=query,
            dataset_id=config.RAGFLOW_DATASET_ID,
            top_k=10
        )
        
        results = []
        chunks = response.get('data', {}).get('chunks', [])
        for item in chunks:
            results.append(RetrievalResult(
                title=item.get('document_name', 'Unknown'),
                content=item.get('content_with_weight', item.get('content', '')),
                score=item.get('similarity', 0.0),
                source='ragflow'
            ))
        return results
    
    # 创建检索器
    retriever = AdaptiveRetriever(
        knowledge_base_search_func=real_kb_search,
        utility_scorer=UtilityScorer(),  # 如果模型未训练，使用passthrough
        max_iterations=3,
        top_k=5
    )
    
    # 场景：渗透测试员发现目标运行WebLogic
    target_info = "WebLogic Server 10.3.6.0 on Windows Server 2012"
    
    # 第一次尝试：使用CVE编号搜索（可能失败）
    logger.info("\n步骤1：初始搜索")
    logger.info(f"目标系统：{target_info}")
    logger.info("查询：CVE-2017-10271\n")
    
    result = retriever.retrieve(
        query="CVE-2017-10271",
        target_info=target_info
    )
    
    # 输出结果
    logger.info("\n" + "=" * 80)
    logger.info("检索结果摘要")
    logger.info("=" * 80)
    logger.info(f"成功状态：{'✓ 成功' if result.success else '✗ 失败'}")
    logger.info(f"迭代次数：{result.total_iterations}")
    logger.info(f"最终查询：{result.final_query}")
    
    logger.info("\n检索历史：")
    for step in result.retrieval_history:
        logger.info(f"\n  迭代 {step.iteration}:")
        logger.info(f"    查询: {step.query}")
        if step.failure_detected:
            logger.info(f"    状态: ✗ 检测到失败")
            logger.info(f"    诊断: {', '.join(step.diagnoses)}")
            logger.info(f"    改写变体: {len(step.rewritten_queries)} 个")
        else:
            logger.info(f"    状态: ✓ 成功")
    
    logger.info("\n" + "=" * 80)
    logger.info("Top 3 可执行攻击方案")
    logger.info("=" * 80)
    
    for i, doc in enumerate(result.reranked_results[:3], 1):
        logger.info(f"\n{i}. {doc.title}")
        logger.info(f"   相关度: {doc.score:.3f}")
        logger.info(f"   来源: {doc.source}")
        logger.info(f"   预览: {doc.content[:200]}...")
    
    # 保存检索日志供后续分析
    log_path = Path("attack_kb/logs/pentest_scenario.json")
    retriever.save_retrieval_log(result, log_path)
    logger.info(f"\n详细日志已保存: {log_path}")
    
    # --- 新增结果：回填经验到经验库 ---
    if result.success:
        from processors.evo_config import config
        logger.info(f"\n📝 自动总结经验并推送至经验库 ({config.RAGFLOW_EXPR_ID})...")
        experience = retriever.summarize_experience("WebLogic exploit", result)
        
        push_success = ragflow_client.push_structured_summary(
            dataset_id=config.RAGFLOW_EXPR_ID,
            title=f"Exploit Experience: WebLogic",
            content=experience
        )
        if push_success:
            logger.info("✅ 经验回填成功！")
        else:
            logger.error("❌ 经验回填失败")
    
    return result


def agent_integration_example():
    """
    智能体集成示例：作为MCP工具使用
    """
    logger.info("\n" + "=" * 80)
    logger.info("智能体集成示例")
    logger.info("=" * 80)
    
    # 假设这是智能体的工具调用
    class PentestAgent:
        def __init__(self):
            self.retriever = AdaptiveRetriever(
                knowledge_base_search_func=self._search_kb,
                utility_scorer=UtilityScorer(),
                max_iterations=3,
                top_k=5
            )
        
        def _search_kb(self, query: str):
            """实际调用知识库"""
            # 这里接入真实的知识库系统
            pass
        
        def search_attack_knowledge(self, 
                                   vulnerability: str,
                                   target: str) -> dict:
            """
            MCP工具：自适应搜索攻击知识
            
            Args:
                vulnerability: 漏洞描述或CVE编号
                target: 目标系统信息
            
            Returns:
                包含攻击方案的结构化数据
            """
            result = self.retriever.retrieve(
                query=vulnerability,
                target_info=target
            )
            
            # 转换为智能体可理解的格式
            return {
                'success': result.success,
                'attack_plans': [
                    {
                        'title': doc.title,
                        'payload': doc.content,
                        'confidence': doc.score,
                        'source': doc.source
                    }
                    for doc in result.reranked_results
                ],
                'search_iterations': result.total_iterations,
                'final_query': result.final_query
            }
    
    # 使用示例
    agent = PentestAgent()
    
    logger.info("智能体工具调用：")
    logger.info('  search_attack_knowledge(')
    logger.info('    vulnerability="WebLogic deserialization",')
    logger.info('    target="WebLogic 10.3.6.0"')
    logger.info('  )')
    
    logger.info("\n返回的攻击方案会自动经过3步优化：")
    logger.info("  1. 失败检测 → 发现低质量结果")
    logger.info("  2. 反思诊断 → 分析查询问题")
    logger.info("  3. 查询改写 → 生成优化变体")
    logger.info("  4. 重新检索 → 获取高质量结果")
    logger.info("  5. 效用重排 → 最相关的排在前面")


if __name__ == "__main__":
    print("\n" + "#" * 80)
    print("# Evo-Pentest Step 3: 自适应查询自反思系统 使用示例")
    print("#" * 80)
    
    # 运行渗透测试场景
    penetration_test_scenario()
    
    # 显示智能体集成方式
    agent_integration_example()
    
    print("\n" + "#" * 80)
    print("# 使用指南")
    print("#" * 80)
    print("""
核心组件：
  1. FailureDetector     - 多维度失败检测（5个启发式规则）
  2. ReflectionDiagnoser - 6种诊断类型（漂移/粒度/术语/上下文）
  3. QueryRewriter       - 探索-利用平衡改写（3个策略）
  4. UtilityScorer       - 基于训练模型的重排序
  5. AdaptiveRetriever   - 完整的迭代检索流程

快速开始：
  1. 准备知识库搜索函数：search_func(query) -> List[RetrievalResult]
  2. 创建检索器：retriever = AdaptiveRetriever(search_func)
  3. 执行检索：result = retriever.retrieve(query, target_info)
  4. 使用结果：result.reranked_results

高级配置：
  - 加载Utility Scorer：提供 model_path
  - 调整迭代次数：设置 max_iterations（默认3）
  - 自定义失败阈值：FailureDetector(min_useful_docs=N)

集成方式：
  - RAGFlow集成：见 integrate_with_ragflow()
  - 智能体工具：见 agent_integration_example()
  - 独立使用：见 penetration_test_scenario()

论文要点：
  ✓ System 2 Reflection机制
  ✓ 探索-利用平衡策略（Exploration-Exploitation）
  ✓ 多维度失败诊断（6种诊断类型）
  ✓ 效用驱动的重排序（Utility-driven Reranking）
  ✓ 自适应迭代检索（最多3轮）
    """)
