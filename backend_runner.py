import os
import sys
import logging
import traceback
from pathlib import Path

# 设置 Hugging Face 镜像，解决国内网络连接超时问题
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
# 禁用某些版本的 Transformers 尝试联网检查库更新
os.environ["TRANSFORMERS_OFFLINE"] = "0" 

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BackendRunner")

def run_pipeline():
    """
    全流程后端运行测试：
    1. 自动标注 (HER)
    2. 模型训练 (Evolution)
    3. 自适应检索 + RAGFlow 语料库读取 + 经验回填
    """
    
    # 获取项目根目录
    root_dir = Path(__file__).parent.absolute()
    sys.path.append(str(root_dir))
    
    try:
        # --- Step 1: 自动标注 (HER) ---
        logger.info("\n" + "="*50)
        logger.info("Step 1: 运行 Hindsight Experience Replay 标注...")
        logger.info("="*50)
        from processors.auto_labeler_v2 import ImprovedAutoLabeler
        from processors.evo_config import config
        
        labeler = ImprovedAutoLabeler()
        dataset_path = config.DATA_DIR / "utility_dataset_balanced.jsonl"
        labeler.process_all_logs(config.LOGS_DIR, dataset_path)
        logger.info(f"✓ 已生成数据集: {dataset_path}")

        # --- Step 2: 模型训练 (Evolution) ---
        logger.info("\n" + "="*50)
        logger.info("Step 2: 启动 Cross-Encoder 模型全量训练...")
        logger.info("="*50)
        from processors.dataset import DatasetLoader
        from processors.trainer import CrossEncoderTrainer
        
        loader = DatasetLoader(dataset_path)
        samples = loader.load_from_jsonl()
        train_data, test_data = loader.split_dataset(samples)
        
        trainer = CrossEncoderTrainer()
        trainer.train(train_data, test_data)
        logger.info("✓ Cross-Encoder 进化训练完成！")

        # --- Step 3: 自适应检索任务 (真实 RAGFlow 联动) ---
        logger.info("\n" + "="*50)
        logger.info("Step 3: 启动真实自适应检索 (RAGFlow 语料库 -> 经验库)...")
        logger.info("="*50)
        from processors.adaptive_retriever import AdaptiveRetriever, UtilityScorer
        from processors.ragflow_client import RAGFlowClient
        
        # 实例化检索器
        rf_client = RAGFlowClient(config.RAGFLOW_API_KEY, config.RAGFLOW_BASE_URL)
        
        def real_kb_search(query: str):
            logger.info(f"🔍 正在从 RAGFlow 语料库检索: {query}")
            from processors.adaptive_retriever import RetrievalResult
            try:
                response = rf_client.search(query, config.RAGFLOW_DATASET_ID)
                if not response or not isinstance(response, dict):
                    logger.warning("⚠️ RAGFlow 返回了无效的响应对象")
                    return []
                
                # 深度判空：某些情况下 data 字段可能为 null
                data = response.get('data')
                if data is None:
                    logger.warning("⚠️ RAGFlow 响应中的 'data' 字段为 null")
                    return []
                
                # 兼容不同版本的 RAGFlow API 结构
                if isinstance(data, list):
                    # 某些版本直接返回列表
                    chunks = data
                elif isinstance(data, dict):
                    # 某些版本返回 {'chunks': [...]}
                    chunks = data.get('chunks', [])
                    if chunks is None: chunks = []
                else:
                    chunks = []
                
                results = []
                for item in chunks:
                    if not item or not isinstance(item, dict):
                        continue
                        
                    results.append(RetrievalResult(
                        title=item.get('document_name', item.get('title', 'Unknown')),
                        content=item.get('content', item.get('content_with_weight', '')),
                        score=item.get('similarity', item.get('vector_similarity', 0.0)),
                        source='ragflow'
                    ))
                return results
            except Exception as e:
                logger.error(f"❌ 检索执行中发生错误: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return []

        retriever = AdaptiveRetriever(
            knowledge_base_search_func=real_kb_search,
            utility_scorer=UtilityScorer(model_path=config.UTILITY_MODEL_PATH),
            max_iterations=3
        )
        
        # 运行一个高难度的真实测试用例
        test_query = "CVE-2017-10271 exploit payload WebLogic XMLDecoder"
        logger.info(f"🚀 输入查询: {test_query}")
        result = retriever.retrieve(query=test_query)
        
        # 无论成功与否，都生成经验总结 (System 2 反思不仅针对成功，也针对失败的尝试)
        status_str = "成功" if result.success else "未找到匹配结果"
        logger.info(f"💡 流程执行完毕 ({status_str})，正在生成检索过程反思总结...")
        
        experience = retriever.summarize_experience(test_query, result)
        
        logger.info(f"📝 正在将本次迭代经验回填至 RAGFlow 经验库 ({config.RAGFLOW_EXPR_ID})...")
        
        # 构建一个更有意义的标题 (简化以避免文件名非法字符)
        status_tag = "SUCCESS" if result.success else "LESSON"
        exp_title = f"{status_tag}_CVE_2017_10271"
        
        upload_success = rf_client.push_structured_summary(
            dataset_id=config.RAGFLOW_EXPR_ID,
            title=exp_title,
            content=experience
        )
        
        if upload_success:
            logger.info("✨ 经验回填成功！流程圆满完成。")
        else:
            logger.error("❌ 经验回填失败，请检查 RAGFlow API Key 或 Dataset ID。")

    except Exception as e:
        logger.error(f"❌ 后端流程运行失败: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    # 自动安装缺失依赖
    # os.system('pip install torch transformers flask flask-cors requests beautifulsoup4 tqdm sentence-transformers -i https://pypi.tuna.tsinghua.edu.cn/simple')
    
    run_pipeline()
