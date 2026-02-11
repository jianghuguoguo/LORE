# config.py
# ATT&CK 知识库项目全局配置

import os

# ========== 通用配置 ==========
# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# 工作区根目录 (假设 attack_core 在 crawlers/attack_core)
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(PROJECT_ROOT)))

# 数据根目录
DATA_ROOT = os.path.join(WORKSPACE_ROOT, "raw_data", "attack")

# STIX 数据本地存储目录
STIX_OUTPUT_DIR = os.path.join(DATA_ROOT, "stix")

# 确保数据目录存在
os.makedirs(STIX_OUTPUT_DIR, exist_ok=True)

# ========== STIX 数据源配置 ==========
# MITRE ATT&CK STIX GitHub 仓库原始文件 URL
ENTERPRISE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
MOBILE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/mobile-attack/mobile-attack.json"
)
ICS_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/ics-attack/ics-attack.json"
)

# STIX URLs 字典 (用于遍历)
STIX_URLS = {
    "enterprise": ENTERPRISE_STIX_URL,
    "mobile": MOBILE_STIX_URL,
    "ics": ICS_STIX_URL,
}

# ========== 数据库配置 ==========

# 如果使用 PostgreSQL（可选）
DB_DSN = os.getenv(
    "ATTACK_DB_DSN",
    "postgresql://user:password@localhost:5432/attackkb"
)

# ========== 日志配置 ==========
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
