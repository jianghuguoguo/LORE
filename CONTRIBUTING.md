# Contributing to RefPenTest

感谢你考虑为 RefPenTest 做贡献！本文档说明了参与方式、代码规范和提交流程。

---

## 目录

- [参与方式](#参与方式)
- [开发环境搭建](#开发环境搭建)
- [项目结构速览](#项目结构速览)
- [贡献代码](#贡献代码)
- [添加爬虫适配器](#添加爬虫适配器)
- [添加日志格式适配器](#添加日志格式适配器)
- [代码规范](#代码规范)
- [提交 Pull Request](#提交-pull-request)
- [报告 Bug](#报告-bug)
- [行为准则](#行为准则)

---

## 参与方式

你可以通过以下方式参与贡献：

- **提交 Bug 报告**：在 Issues 中使用 `bug` 标签描述问题
- **提出功能请求**：使用 `enhancement` 标签，附上使用场景描述
- **提交 Pull Request**：修复 Bug、新增功能、完善文档
- **添加适配器**：为新的 Agent 框架或日志格式编写适配器（见下文）
- **完善测试**：扩充 `tests/` 中的测试覆盖率

---

## 开发环境搭建

```bash
# 1. 克隆仓库
git clone https://github.com/your-org/RefPenTest.git
cd RefPenTest

# 2. 创建虚拟环境
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. 安装依赖（含开发依赖）
pip install -r requirements.txt
pip install pytest pytest-cov

# 4. 验证安装
python -c "from src.layer0 import run_layer0; print('OK')"
```

**LLM 配置**（Layer 1/2 需要）：编辑 `configs/config.yaml`，填写你的 API key：

```yaml
llm:
  provider: deepseek
  model: deepseek-chat
  api_key: "sk-..."   # 或设置环境变量 DEEPSEEK_API_KEY
```

---

## 项目结构速览

```
src/
├── layer0/          # 日志解析：原始 JSONL → TurnSequence
│   ├── adapters/    # 格式适配层（CAI / LangChain / OpenAI / Generic）
│   ├── parser.py
│   ├── extractor.py
│   ├── assembler.py
│   └── pipeline.py  ← 唯一对外入口：run_layer0() / run_layer0_batch()
├── layer1/          # 语义标注：规则层 + LLM 层
├── layer2/          # 经验提炼：5 类知识提取
├── layer3/          # XPEC 跨会话融合（Phase 1–5）
├── layer4/          # 缺口感知自适应爬取
├── ragflow/         # RAGFlow 客户端
└── ragflow_uploader.py  # 经验库上传

crawlers/            # 关键词驱动的外部信息源爬虫
dashboard/           # Flask Web UI
configs/             # 配置文件
tests/               # 单元与集成测试
```

---

## 贡献代码

### 分支命名

| 类型 | 分支命名示例 |
|:----|:-----------|
| 功能 | `feat/layer2-cve-enrichment` |
| 修复 | `fix/layer1-timeout-false-positive` |
| 文档 | `docs/update-contributing` |
| 重构 | `refactor/layer3-klm-serialization` |

### 开发流程

```bash
# 创建特性分支
git checkout -b feat/your-feature

# 开发 → 测试
pytest tests/ -v

# 提交（符合 Conventional Commits 规范）
git commit -m "feat(layer2): add CVSS score extraction for FACTUAL entries"

# 推送并创建 PR
git push origin feat/your-feature
```

---

## 添加日志格式适配器

如果你的 Agent 框架不在支持列表（CAI / LangChain / OpenAI Assistants）中，可以通过以下步骤添加适配器：

**1. 在 `src/layer0/adapters/` 下创建新文件 `my_framework.py`**

```python
from pathlib import Path
from typing import Iterator, Tuple
from src.layer0 import AdapterRegistry, LogAdapter
from src.layer0.canonical_types import CanonicalAgentTurn, SessionMeta

@AdapterRegistry.register
class MyFrameworkAdapter(LogAdapter):

    @property
    def adapter_name(self) -> str:
        return "my_framework"

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        """读前几行，判断是否为本格式。"""
        try:
            first = file_path.read_text(encoding="utf-8").splitlines()[0]
            return '"my_framework_marker"' in first
        except Exception:
            return False

    def parse(self, file_path: Path) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        meta = SessionMeta(session_id="...", start_time="...")

        def _iter():
            with open(file_path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    import json
                    row = json.loads(line)
                    yield CanonicalAgentTurn(
                        session_id=meta.session_id,
                        turn_index=i,
                        timestamp=row.get("ts", ""),
                        tool_name=row["action"],   # 按实际字段填写
                        tool_args=row.get("args", {}),
                        stdout=row.get("output", ""),
                        return_code=row.get("rc"),
                    )

        return meta, _iter()
```

**2. 在 `src/layer0/adapters/__init__.py` 中导入**

```python
from .my_framework import MyFrameworkAdapter  # 新增此行
```

**3. 添加测试 `tests/test_my_framework_adapter.py`**

```python
from pathlib import Path
from src.layer0 import AdapterRegistry

def test_can_handle(tmp_path):
    log = tmp_path / "test.jsonl"
    log.write_text('{"my_framework_marker": true, "action": "nmap"}\n')
    adapter = AdapterRegistry.auto_detect(log)
    assert adapter.adapter_name == "my_framework"
```

**4. 更新 `docs/04_Log Adapter  多框架日志接入指南.md`** 中的"支持的框架"表格。

---

## 添加爬虫适配器

新增外部知识源爬虫的步骤：

**1. 继承 `BaseCrawler` 并实现 `crawl()` 方法**

```python
# crawlers/my_source_crawler.py
from .base_crawler import BaseCrawler, CrawlResult

class MySourceCrawler(BaseCrawler):
    SOURCE_NAME = "my_source"

    def crawl(self, keyword: str, max_results: int = 20) -> list[CrawlResult]:
        # 实现爬取逻辑
        ...
```

**2. 在 `crawlers/__init__.py` 中注册**

```python
from .my_source_crawler import MySourceCrawler
CRAWLERS["my_source"] = MySourceCrawler
```

**3. 在 `configs/config.yaml` 的 `crawlers.sources` 中添加配置**

---

## 代码规范

- **Python 版本**：3.10+，使用 `from __future__ import annotations`
- **类型注解**：所有公开函数必须有类型注解
- **文档字符串**：公开函数使用 Google style docstring（见现有代码示例）
- **导入顺序**：stdlib → 第三方 → 本地，各组之间空一行
- **行长度**：不超过 100 字符
- **禁止**：硬编码 API key 提交到版本库（使用 `configs/config.yaml` 或环境变量）

**运行检查：**

```bash
# 类型检查
pyright src/

# 测试
pytest tests/ -v --tb=short

# 查看覆盖率
pytest tests/ --cov=src --cov-report=term-missing
```

---

## 提交 Pull Request

1. 确保所有测试通过：`pytest tests/ -v`
2. PR 标题遵循 Conventional Commits：`feat:` / `fix:` / `docs:` / `refactor:`
3. PR 描述中说明：
   - **做了什么**（What）
   - **为什么这么做**（Why）
   - **如何测试**（How to test）
4. 如涉及 Layer 1/2/3 变更，请附上对示例数据集的测试运行结果

---

## 报告 Bug

请在 Issue 中包含：

- **复现步骤**（最小可复现命令/代码）
- **期望行为** vs **实际行为**
- **环境信息**：Python 版本、OS、关键依赖版本（`pip freeze | grep -E "openai|langchain|requests"`）
- **相关日志**（`logs/` 目录下的文件，注意脱敏敏感信息）

---

## 行为准则

本项目遵循 [Contributor Covenant](https://www.contributor-covenant.org/) 行为准则。

核心原则：保持友善、尊重不同观点、聚焦技术讨论。安全研究背景下，请**不要**在 Issue 或 PR 中提交真实的漏洞利用代码或目标系统凭据。

---

*感谢所有贡献者 ❤*
