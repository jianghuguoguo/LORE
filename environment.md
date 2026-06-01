# 部署与环境说明

本文件列出运行 LORE 时需要用户填写或检查的配置文件与环境变量，并给出常见注入方法。

**核心配置文件（必须检查/填写）**
- `configs/config.yaml`：主配置（LLM、RAGflow、datasets 等）。密钥建议用环境变量注入，`api_key_literal` 仅用于本地临时测试。
- `crawlers/config.py`：爬虫相关配置（CSDN cookie、RAGFlow 备选配置、GITHUB_TOKEN 等）。敏感值建议通过环境变量注入。
- `crawlers/wechat_crawler/discovery/community_sync.py`：DeepSeek API Key 读取环境变量 `DEEPSEEK_API_KEY`。
- `src/ragflow/uploader.py`：RAGFlow 运行时配置读取 `configs/config.yaml` 与环境变量（如 `RAGFLOW_API_KEY`）。

**示例/辅助文档（请按需阅读并修改）**
- `docs/03_USAGE_GUIDE.md`：示例配置与运行指令（示例占位为格式化占位）。
- `CONTRIBUTING.md`：开发/贡献时的示例配置说明。

**必需的环境变量（推荐）**
- `LLM_API_KEY`：LLM 服务 API Key（示例：`sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`）。优先于 `configs/config.yaml` 中的 literal。
- `DEEPSEEK_API_KEY`：DeepSeek 专用 Key（示例：`sk-...`）。
- `RAGFLOW_API_KEY`：RAGflow API Key（示例前缀：`ragflow-...`）。
- `RAGFLOW_BASE_URL`：RAGflow 主机地址（示例：`http://localhost:8000` 或 `http://host/api/v1`）。
- `RAGFLOW_DATASET_ID`：默认 dataset ID（若某处代码支持通过环境变量覆盖）。
- `CSDN_COOKIE`：CSDN VIP cookie（若使用 CSDN VIP 抓取）。
- `CSDN_USERNAME` / `CSDN_PASSWORD`：可选，作为 cookie 的替代（不建议提交到仓库）。
- `GITHUB_TOKEN`：GitHub API Token（建议 `ghp_...` 前缀）。

**占位与格式规则（请严格遵循）**
- 保留前缀与长度便于自动替换与检测：
  - LLM Key：`sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`（`sk-` + 32 字符占位）
  - RAGFlow Key：`ragflow-xxxxxxxxxxxxxxxx`（保留 `ragflow-` 前缀）
  - Dataset ID：32 个十六进制字符示例占位：`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
  - GitHub Token：`ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- 注：配置文件中示例占位已按上述格式设置，生产请用真实密钥并通过环境变量注入。

**如何设置环境变量（示例）**
- PowerShell（当前会话）：

```powershell
$env:LLM_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
$env:RAGFLOW_API_KEY = "ragflow-xxxxxxxxxxxxxxxx"
$env:DEEPSEEK_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

- PowerShell（永久）：

```powershell
setx LLM_API_KEY "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
setx RAGFLOW_API_KEY "ragflow-xxxxxxxxxxxxxxxx"
```

- Bash (Linux / macOS)：

```bash
export LLM_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export RAGFLOW_API_KEY="ragflow-xxxxxxxxxxxxxxxx"
```

**验证示例（快速检查）**

```bash
python -c "import os; print('LLM=', bool(os.getenv('LLM_API_KEY')),'RAG=', bool(os.getenv('RAGFLOW_API_KEY')))"
```

**安全建议**
- 永远不要将真实密钥提交到 Git 仓库。把 `configs/config.yaml` 保持为占位或仅包含非敏感设置，并将 `.env` / secrets 存储在安全位置。
- 在生产环境中，使用 CI/CD secret 管理或系统级环境变量注入。