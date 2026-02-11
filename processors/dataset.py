"""
Evo-Pentest 数据集加载器
用于加载 utility_dataset.jsonl 并构建训练/验证集
"""

import json
import random
from typing import List, Tuple, Dict
from pathlib import Path
from dataclasses import dataclass
import logging

import torch
from torch.utils.data import Dataset
from sklearn.model_selection import train_test_split

logger = logging.getLogger("EvoPentest.Dataset")


@dataclass
class TrainSample:
    """训练样本数据结构"""
    query: str
    document: str
    label: float
    context: str = ""


class UtilityDataset(Dataset):
    """
    渗透知识效用度数据集
    用于训练 Cross-Encoder 重排序模型
    """
    
    def __init__(self, samples: List[TrainSample]):
        self.samples = samples
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx) -> Dict:
        sample = self.samples[idx]
        return {
            "query": sample.query,
            "document": sample.document,
            "label": sample.label,
            "context": sample.context
        }


class DatasetLoader:
    """数据集加载与预处理管理器"""
    
    def __init__(self, data_path: Path, test_size: float = 0.2, random_seed: int = 42):
        self.data_path = data_path
        self.test_size = test_size
        self.random_seed = random_seed
        random.seed(random_seed)
    
    def load_from_jsonl(self) -> List[TrainSample]:
        """从 JSONL 文件加载数据"""
        samples = []
        with open(self.data_path, 'r', encoding='utf-8') as f:
            for line in f:
                data = json.loads(line)
                samples.append(TrainSample(
                    query=data.get("query", ""),
                    document=data.get("document", ""),
                    label=float(data.get("label", 0.0)),
                    context=data.get("context", "")
                ))
        logger.info(f"Loaded {len(samples)} samples from {self.data_path}")
        return samples
    
    def analyze_dataset(self, samples: List[TrainSample]):
        """分析数据集统计信息"""
        positive = sum(1 for s in samples if s.label > 0.5)
        negative = len(samples) - positive
        
        logger.info("=" * 60)
        logger.info("Dataset Statistics:")
        logger.info(f"  Total samples: {len(samples)}")
        logger.info(f"  Positive samples (Label=1.0): {positive} ({positive/len(samples)*100:.2f}%)")
        logger.info(f"  Negative samples (Label=0.0): {negative} ({negative/len(samples)*100:.2f}%)")
        logger.info(f"  Label distribution: {positive}/{negative}")
        
        # 查询长度统计
        query_lengths = [len(s.query) for s in samples]
        doc_lengths = [len(s.document) for s in samples]
        logger.info(f"  Avg query length: {sum(query_lengths)/len(query_lengths):.1f} chars")
        logger.info(f"  Avg document length: {sum(doc_lengths)/len(doc_lengths):.1f} chars")
        logger.info("=" * 60)
    
    def split_dataset(self, samples: List[TrainSample]) -> Tuple[UtilityDataset, UtilityDataset]:
        """划分训练集和测试集"""
        # 按标签分层抽样确保正负样本比例一致
        labels = [s.label for s in samples]
        
        train_samples, test_samples = train_test_split(
            samples, 
            test_size=self.test_size,
            random_state=self.random_seed,
            stratify=labels
        )
        
        logger.info(f"Split dataset: {len(train_samples)} train, {len(test_samples)} test")
        
        return UtilityDataset(train_samples), UtilityDataset(test_samples)
    
    def create_balanced_batch(self, samples: List[TrainSample], batch_size: int = 16) -> List[List[TrainSample]]:
        """
        创建平衡批次（每个批次中正负样本数量相近）
        这对于训练稳定性很重要
        """
        positive_samples = [s for s in samples if s.label > 0.5]
        negative_samples = [s for s in samples if s.label <= 0.5]
        
        random.shuffle(positive_samples)
        random.shuffle(negative_samples)
        
        batches = []
        half_batch = batch_size // 2
        
        for i in range(0, min(len(positive_samples), len(negative_samples)), half_batch):
            batch = (
                positive_samples[i:i+half_batch] + 
                negative_samples[i:i+half_batch]
            )
            random.shuffle(batch)
            batches.append(batch)
        
        logger.info(f"Created {len(batches)} balanced batches (batch_size={batch_size})")
        return batches


if __name__ == "__main__":
    # 测试数据加载
    logging.basicConfig(level=logging.INFO)
    from processors.evo_config import config
    
    loader = DatasetLoader(config.DATA_DIR / "utility_dataset.jsonl")
    samples = loader.load_from_jsonl()
    loader.analyze_dataset(samples)
    
    train_ds, test_ds = loader.split_dataset(samples)
    print(f"\nTrain dataset size: {len(train_ds)}")
    print(f"Test dataset size: {len(test_ds)}")
    
    # 打印一个样本示例
    sample = train_ds[0]
    print(f"\nSample example:")
    print(f"Query: {sample['query'][:100]}...")
    print(f"Label: {sample['label']}")
