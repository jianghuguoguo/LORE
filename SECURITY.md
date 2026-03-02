# Security Policy

## Supported Versions

| Version | Supported |
|:--------|:---------:|
| 0.3.x (current) | ✅ |
| 0.2.x | ⚠️ critical fixes only |
| < 0.2 | ❌ |

---

## Scope — What RefPenTest Processes

RefPenTest 处理的数据包含**真实渗透测试日志**，其中可能含有：

- 目标系统 IP / 主机名 / 端口
- CVE 漏洞编号与利用细节
- Agent 命令历史（含凭据片段）
- LLM 中间推理文本

**在运行或分享日志文件前，请确认已获得目标系统的合法授权**，并在上传至任何公开服务（包括 RAGFlow 共享实例）前完成脱敏处理。

---

## Reporting a Vulnerability

**请不要在公开 Issue 中披露安全漏洞。**

若发现：

- 代码执行类漏洞（如日志解析路径穿越、反序列化注入）
- 认证绕过（如 RAGFlow token 泄露）
- 敏感数据意外写入日志/输出文件

请通过以下方式私下报告：

1. **Email**：发送至项目维护者邮箱（在 GitHub Profile 页面可查）
2. **GitHub Security Advisories**（推荐）：使用仓库的 "Security" → "Advisories" → "New draft security advisory"

报告中请包含：
- 漏洞描述和影响范围
- 复现步骤（最小可复现代码）
- 建议的修复方案（可选）

我们承诺在 **72 小时** 内确认收到报告，并在 **14 天** 内评估严重程度，给出修复时间表。

---

## Hardcoded Credentials — Known Design Decision

`src/ragflow_uploader.py` 的 `RAGFLOW_CONFIG` 字典中包含一组**演示用默认凭据**（`123456@mail.com` / `123456`），这是为降低学习成本而保留的 placeholder：

```python
RAGFLOW_CONFIG = {
    "base_url": "http://8.140.33.83",
    "email":    "123456@mail.com",       # ← 演示用，请替换
    "password": "123456",                 # ← 演示用，请替换
    "api_key":  "",                        # ← 推荐：填写真实 API key
    ...
}
```

**生产部署时，请务必**：

1. 将 `api_key` 填写为真实 RAGFlow API Key（在 RAGFlow Web UI → 右上角头像 → API Key 生成）
2. 将 `email` / `password` 替换为专用服务账号
3. 或通过环境变量注入（我们计划在 v0.4.0 中添加 `RAGFLOW_API_KEY` 环境变量支持）

**不要将包含真实凭据的 `ragflow_uploader.py` 提交到版本库。**

---

## Safe Usage Guidelines

1. **日志脱敏**：上传至 RAGFlow 前，用 `scripts/sanitize_logs.py`（计划中）对日志中的真实 IP、凭据进行替换
2. **网络隔离**：建议在内网或 VPN 环境中运行 RAGFlow 服务
3. **访问控制**：Dashboard (`localhost:5000`) 默认不启用认证，生产部署时请配置反向代理（Nginx + Basic Auth 或 OAuth）
4. **LLM API Key**：`configs/config.yaml` 已在 `.gitignore` 中，请不要手动取消忽略
5. **日志文件**：`logs/` 目录中包含会话数据，`.gitignore` 中已排除，请勿在 CI/CD 流程中上传

---

## Dependency Security

建议定期运行：

```bash
pip audit    # 检查已知漏洞依赖
```

或使用 GitHub Dependabot（在仓库 Settings → Security → Dependabot alerts 中启用）。

---

*This policy is effective as of 2026-03-01.*
