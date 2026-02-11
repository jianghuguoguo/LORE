"""
Evo-Pentest 重排序模型训练器
使用 Cross-Encoder 架构训练渗透知识效用度评分模型
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import get_linear_schedule_with_warmup
from torch.optim import AdamW
from tqdm import tqdm
import numpy as np

from processors.dataset import DatasetLoader, TrainSample
from processors.evaluator import UtilityEvaluator
from processors.evo_config import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EvoPentest.Trainer")


class CrossEncoderTrainer:
    """
    Cross-Encoder 训练器
    实现渗透知识效用度评分的端到端训练流程
    """
    
    def __init__(
        self,
        model_name: str = None,
        device: str = None,
        max_length: int = None,
        batch_size: int = None,
        learning_rate: float = None,
        num_epochs: int = None,
        warmup_steps: int = None,
        weight_decay: float = None
    ):
        # 从配置文件加载默认参数
        self.model_name = model_name or config.RANKER_MODEL
        self.device = device or config.DEVICE
        self.max_length = max_length or config.MAX_LENGTH
        self.batch_size = batch_size or config.TRAIN_BATCH_SIZE
        self.learning_rate = learning_rate or config.LEARNING_RATE
        self.num_epochs = num_epochs or config.NUM_EPOCHS
        self.warmup_steps = warmup_steps or config.WARMUP_STEPS
        self.weight_decay = weight_decay or config.WEIGHT_DECAY
        
        logger.info(f"Initializing trainer with device: {self.device}")
        
        # 加载模型和分词器
        try:
            logger.info(f"Loading model and tokenizer: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=1,  # 回归任务，输出单个分数
                trust_remote_code=True
            )
        except Exception as e:
            logger.error(f"Failed to load model from {self.model_name}: {e}")
            logger.info("Tip: Checking internet connection or if HuggingFace mirror (HF_ENDPOINT) is set.")
            raise
            
        self.model.to(self.device)
        
        # 评估器
        self.evaluator = UtilityEvaluator()
        
        # 训练历史记录
        self.history = {
            "train_loss": [],
            "eval_metrics": [],
            "best_ndcg": 0.0
        }
    
    def prepare_batch(self, samples: List[Dict]) -> Dict:
        """准备批次数据"""
        # 增加类型转换，防止非字符串类型导致 tokenizer 报错
        queries = [str(s.get("query", "")) for s in samples]
        documents = [str(s.get("document", "")) for s in samples]
        labels = torch.tensor([float(s.get("label", 0.0)) for s in samples], dtype=torch.float32)
        
        # Cross-Encoder 输入格式: [CLS] query [SEP] document [SEP]
        encodings = self.tokenizer(
            queries,
            documents,
            max_length=self.max_length,
            padding=True,
            truncation=True,
            return_tensors="pt"
        )
        
        return {
            "input_ids": encodings["input_ids"].to(self.device),
            "attention_mask": encodings["attention_mask"].to(self.device),
            "labels": labels.to(self.device)
        }

    @staticmethod
    def collate_fn(batch):
        """自定义 collate_fn 保持字典列表格式"""
        return batch
    
    def train_epoch(self, dataloader: DataLoader, optimizer, scheduler) -> float:
        """训练一个 epoch"""
        self.model.train()
        total_loss = 0.0
        progress_bar = tqdm(dataloader, desc="Training")
        
        # 使用自动混合精度 (AMP) 加速训练
        # 注意: torch 2.x 推荐使用 torch.amp 替代 torch.cuda.amp
        use_amp = self.device == "cuda" and getattr(config, "FP16", False)
        device_type = "cuda" if "cuda" in str(self.device) else "cpu"
        scaler = torch.amp.GradScaler(device_type, enabled=use_amp)
        
        for batch_samples in progress_bar:
            batch = self.prepare_batch(batch_samples)
            
            # 前向传播 (AMP)
            with torch.amp.autocast(device_type, enabled=use_amp):
                outputs = self.model(
                    input_ids=batch["input_ids"],
                    attention_mask=batch["attention_mask"]
                )
                logits = outputs.logits.squeeze(-1)  # (batch_size,)
                
                # 计算 MSE Loss（回归任务）
                loss_fn = nn.MSELoss()
                loss = loss_fn(logits, batch["labels"])
            
            # 反向传播 (AMP)
            optimizer.zero_grad()
            scaler.scale(loss).backward()
            
            # 梯度裁剪
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            
            total_loss += loss.item()
            progress_bar.set_postfix({"loss": f"{loss.item():.4f}"})
        
        avg_loss = total_loss / len(dataloader)
        return avg_loss
    
    def evaluate(self, dataloader: DataLoader) -> Dict[str, float]:
        """评估模型性能"""
        self.model.eval()
        all_predictions = []
        all_ground_truth = []
        
        with torch.no_grad():
            for batch_samples in tqdm(dataloader, desc="Evaluating"):
                batch = self.prepare_batch(batch_samples)
                
                outputs = self.model(
                    input_ids=batch["input_ids"],
                    attention_mask=batch["attention_mask"]
                )
                scores = outputs.logits.squeeze(-1).cpu().numpy()
                
                # 记录预测和真实标签
                for i, sample in enumerate(batch_samples):
                    all_predictions.append((
                        sample["query"],
                        sample["document"],
                        float(scores[i])
                    ))
                    all_ground_truth.append((
                        sample["query"],
                        sample["document"],
                        sample["label"]
                    ))
        
        # 计算评估指标
        metrics = self.evaluator.evaluate(
            all_predictions,
            all_ground_truth,
            k_values=config.K_VALUES
        )
        
        return metrics
    
    def train(self, train_dataset, eval_dataset):
        """完整训练流程"""
        logger.info("Starting training...")
        logger.info(f"  Num examples = {len(train_dataset)}")
        logger.info(f"  Num epochs = {self.num_epochs}")
        logger.info(f"  Batch size = {self.batch_size}")
        logger.info(f"  Learning rate = {self.learning_rate}")
        
        # 使用类定义的 collate_fn
        # 创建 DataLoader
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            collate_fn=self.collate_fn
        )
        eval_loader = DataLoader(
            eval_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            collate_fn=self.collate_fn
        )
        
        # 设置优化器
        optimizer = AdamW(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay
        )
        
        # 设置学习率调度器
        total_steps = len(train_loader) * self.num_epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=self.warmup_steps,
            num_training_steps=total_steps
        )
        
        # 训练循环
        for epoch in range(self.num_epochs):
            logger.info(f"\n{'='*60}")
            logger.info(f"Epoch {epoch + 1}/{self.num_epochs}")
            logger.info(f"{'='*60}")
            
            # 训练
            train_loss = self.train_epoch(train_loader, optimizer, scheduler)
            self.history["train_loss"].append(train_loss)
            logger.info(f"Train loss: {train_loss:.4f}")
            
            # 评估
            eval_metrics = self.evaluate(eval_loader)
            self.history["eval_metrics"].append(eval_metrics)
            self.evaluator.print_results(eval_metrics)
            
            # 保存最佳模型
            current_ndcg = eval_metrics.get("NDCG@5", 0.0)
            if current_ndcg > self.history["best_ndcg"]:
                self.history["best_ndcg"] = current_ndcg
                self.save_model("best_model")
                logger.info(f"✓ New best model saved! NDCG@5: {current_ndcg:.4f}")
        
        # 训练结束，保存最终模型
        self.save_model("final_model")
        self.save_history()
        logger.info("\n✓ Training completed!")
    
    def save_model(self, checkpoint_name: str = "checkpoint"):
        """保存模型"""
        save_dir = config.MODEL_DIR / checkpoint_name
        save_dir.mkdir(parents=True, exist_ok=True)
        
        self.model.save_pretrained(save_dir)
        self.tokenizer.save_pretrained(save_dir)
        logger.info(f"Model saved to {save_dir}")
    
    def save_history(self):
        """保存训练历史"""
        history_file = config.MODEL_DIR / "training_history.json"
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)
        logger.info(f"Training history saved to {history_file}")
    
    def load_model(self, checkpoint_path: Path):
        """加载已训练的模型"""
        self.model = AutoModelForSequenceClassification.from_pretrained(checkpoint_path)
        self.tokenizer = AutoTokenizer.from_pretrained(checkpoint_path)
        self.model.to(self.device)
        logger.info(f"Model loaded from {checkpoint_path}")


def main():
    """主训练流程"""
    logger.info("=" * 80)
    logger.info("Evo-Pentest Utility Scorer Training - Phase 2")
    logger.info("=" * 80)
    
    # 1. 加载数据集 (使用 V2 生成的平衡数据集)
    dataset_path = config.DATA_DIR / "utility_dataset_balanced.jsonl"
    if not dataset_path.exists():
        # 如果找不到平衡版, 尝试原始版
        dataset_path = config.DATA_DIR / "utility_dataset.jsonl"
        
    if not dataset_path.exists():
        logger.error(f"Dataset not found: {dataset_path}")
        logger.error("Please run auto_labeler_v2.py first to generate training data.")
        return
    
    logger.info(f"Using dataset: {dataset_path}")
    
    loader = DatasetLoader(
        dataset_path,
        test_size=config.TEST_SPLIT,
        random_seed=config.RANDOM_SEED
    )
    
    samples = loader.load_from_jsonl()
    loader.analyze_dataset(samples)
    
    train_dataset, test_dataset = loader.split_dataset(samples)
    
    # 2. 创建训练器
    trainer = CrossEncoderTrainer()
    
    # 3. 开始训练
    trainer.train(train_dataset, test_dataset)
    
    # 4. 最终评估
    logger.info("\n" + "=" * 80)
    logger.info("Final Evaluation on Test Set:")
    logger.info("=" * 80)
    
    test_loader = DataLoader(
        test_dataset, 
        batch_size=trainer.batch_size, 
        shuffle=False,
        collate_fn=trainer.collate_fn
    )
    final_metrics = trainer.evaluate(test_loader)
    trainer.evaluator.print_results(final_metrics)


if __name__ == "__main__":
    main()
