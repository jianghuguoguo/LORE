from pathlib import Path
from dataclasses import dataclass, field
from typing import List

@dataclass
class EvoConfig:
    # 路径配置
    BASE_DIR: Path = Path("d:/渗透测试相关/语料库/语料")
    LOGS_DIR: Path = BASE_DIR / "logs"
    DATA_DIR: Path = BASE_DIR / "attack_kb/data"
    MODEL_DIR: Path = BASE_DIR / "attack_kb/models"
    
    # 成功判定的关键词/模式
    SUCCESS_INDICATORS: List[str] = field(default_factory=lambda: [
        r"success\":\s*true",
        r"uid=0",
        r"root",
        r"flag\{",
        r"Welcome to CouchDB",
        r"HTTP/1.1 200 OK",
        r"Exploit successful",
        r"Command executed successfully"
    ])
    
    # RAG 训练相关
    RANKER_MODEL: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    TRAIN_BATCH_SIZE: int = 16
    NUM_EPOCHS: int = 3
    MAX_LENGTH: int = 512
    LEARNING_RATE: float = 2e-5
    WARMUP_STEPS: int = 100
    WEIGHT_DECAY: float = 0.01
    
    # 评估配置
    EVAL_STEPS: int = 50  # 每 N 步评估一次
    SAVE_STEPS: int = 100  # 每 N 步保存检查点
    TEST_SPLIT: float = 0.2  # 测试集比例
    RANDOM_SEED: int = 42
    
    # 设备配置 (支持 cuda, mps, cpu)
    # 优先检测 CUDA (NVIDIA GPU)，如果不可用则检查 MPS (Apple Silicon)，最后退回到 CPU
    DEVICE: str = "cuda" if __import__("torch").cuda.is_available() else \
                 ("mps" if hasattr(__import__("torch").backends, "mps") and __import__("torch").backends.mps.is_available() else "cpu")
    
    # 训练加速配置
    FP16: bool = True if __import__("torch").cuda.is_available() else False

    # 指标配置
    K_VALUES: List[int] = field(default_factory=lambda: [3, 5, 10])

    # RAGFlow 配置
    RAGFLOW_API_KEY: str = "ragflow-QxNzk2NTcyN2ZkMzExZjA4NjA3MDI0Mm"
    RAGFLOW_BASE_URL: str = "http://60.205.197.71"
    RAGFLOW_DATASET_ID: str = "537706727fd211f0a4890242ac120006"#完整漏洞库
    RAGFLOW_EXPR_ID: str = "1144627c05c911f197890242ac140003"#经验库

    
    # LLM 配置
    DEEPSEEK_API_KEY: str = "sk-ad39f0f1864a4f9fa6ce0fdd06c19b48"

    # 路径增强
    UTILITY_MODEL_PATH: Path = MODEL_DIR / "best_model"

# 全局单例
config = EvoConfig()
