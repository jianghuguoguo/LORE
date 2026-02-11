"""
使用平衡数据集训练Utility Scorer
"""

import logging
from pathlib import Path

from processors.dataset import DatasetLoader
from processors.trainer import CrossEncoderTrainer
from processors.evo_config import config
from torch.utils.data import DataLoader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.TrainBalanced")


def main():
    dataset_path = Path("attack_kb/data/utility_dataset_balanced.jsonl")
    
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        logger.error("Please run balance_dataset.py first.")
        return
    
    # 加载平衡数据集
    loader = DatasetLoader(
        dataset_path,
        test_size=0.25,  # 80样本 -> 60训练/20测试
        random_seed=config.RANDOM_SEED
    )
    
    samples = loader.load_from_jsonl()
    loader.analyze_dataset(samples)
    
    train_dataset, test_dataset = loader.split_dataset(samples)
    
    # 训练
    trainer = CrossEncoderTrainer()
    trainer.train(train_dataset, test_dataset)
    
    # 最终评估
    logger.info("\n" + "=" * 80)
    logger.info("Final Evaluation on Balanced Test Set:")
    logger.info("=" * 80)
    
    def collate_fn(batch):
        return batch
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=trainer.batch_size,
        shuffle=False,
        collate_fn=collate_fn
    )
    final_metrics = trainer.evaluate(test_loader)
    trainer.evaluator.print_results(final_metrics)


if __name__ == "__main__":
    main()
