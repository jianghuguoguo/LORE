"""
Evo-Pentest 训练框架测试脚本
验证各个模块的功能是否正常
"""

import logging
from pathlib import Path

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Test")

def test_config():
    """测试配置文件"""
    logger.info("Testing configuration...")
    from processors.evo_config import config
    
    assert config.BASE_DIR.exists(), "Base directory not found"
    assert config.LOGS_DIR.exists(), "Logs directory not found"
    logger.info(f"✓ Config loaded: {config.RANKER_MODEL}")
    logger.info(f"✓ Device: {config.DEVICE}")
    return True

def test_dataset_loader():
    """测试数据集加载器"""
    logger.info("\nTesting dataset loader...")
    from processors.dataset import DatasetLoader
    from processors.evo_config import config
    
    dataset_path = config.DATA_DIR / "utility_dataset.jsonl"
    if not dataset_path.exists():
        logger.warning(f"Dataset not found: {dataset_path}")
        logger.warning("Please run auto_labeler.py first")
        return False
    
    loader = DatasetLoader(dataset_path, test_size=0.2)
    samples = loader.load_from_jsonl()
    
    assert len(samples) > 0, "No samples loaded"
    logger.info(f"✓ Loaded {len(samples)} samples")
    
    loader.analyze_dataset(samples)
    train_ds, test_ds = loader.split_dataset(samples)
    
    logger.info(f"✓ Train: {len(train_ds)}, Test: {len(test_ds)}")
    return True

def test_evaluator():
    """测试评估指标"""
    logger.info("\nTesting evaluator...")
    from processors.evaluator import UtilityEvaluator
    
    evaluator = UtilityEvaluator()
    
    # 模拟数据
    predictions = [
        ("query1", "doc1", 0.9),
        ("query1", "doc2", 0.7),
        ("query1", "doc3", 0.3),
    ]
    
    ground_truth = [
        ("query1", "doc1", 1.0),
        ("query1", "doc2", 0.0),
        ("query1", "doc3", 1.0),
    ]
    
    results = evaluator.evaluate(predictions, ground_truth)
    
    assert "MRR" in results, "MRR not calculated"
    assert "NDCG@5" in results, "NDCG@5 not calculated"
    
    evaluator.print_results(results)
    logger.info("✓ Evaluator working correctly")
    return True

def test_model_loading():
    """测试模型加载"""
    logger.info("\nTesting model loading...")
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from processors.evo_config import config
    
    try:
        tokenizer = AutoTokenizer.from_pretrained(config.RANKER_MODEL)
        model = AutoModelForSequenceClassification.from_pretrained(
            config.RANKER_MODEL,
            num_labels=1
        )
        logger.info(f"✓ Model loaded: {config.RANKER_MODEL}")
        logger.info(f"✓ Model parameters: {sum(p.numel() for p in model.parameters()):,}")
        return True
    except Exception as e:
        logger.error(f"✗ Model loading failed: {e}")
        return False

def main():
    """运行所有测试"""
    logger.info("=" * 80)
    logger.info("Evo-Pentest Framework Test Suite")
    logger.info("=" * 80)
    
    tests = [
        ("Configuration", test_config),
        ("Dataset Loader", test_dataset_loader),
        ("Evaluator", test_evaluator),
        ("Model Loading", test_model_loading),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            logger.error(f"✗ {name} failed with error: {e}")
            results.append((name, False))
    
    # 打印总结
    logger.info("\n" + "=" * 80)
    logger.info("Test Summary:")
    logger.info("=" * 80)
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        logger.info(f"  {name:30s} {status}")
    
    all_pass = all(success for _, success in results)
    logger.info("=" * 80)
    if all_pass:
        logger.info("✓ All tests passed! Ready to train.")
    else:
        logger.warning("✗ Some tests failed. Please check the errors above.")
    
    return all_pass

if __name__ == "__main__":
    main()
