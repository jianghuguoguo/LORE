# Log Adapter — 多框架日志接入指南

LORE 支持将 **CAI、LangChain、OpenAI Assistants API** 以及任意自定义 JSONL 格式的 Agent 运行日志直接接入分析流水线，无需修改日志生成代码。

---

## 目录

- [哪种情况需要这份文档？](#哪种情况需要这份文档)
- [快速接入（3 行代码）](#快速接入3-行代码)
- [选择适配器](#选择适配器)
  - [CAI](#cai)
  - [LangChain](#langchain)
  - [OpenAI Assistants API](#openai-assistants-api)
  - [任意 JSONL（Generic）](#任意-jsonl通用兜底)
- [接入效果说明](#接入效果说明)
- [贡献新适配器](#贡献新适配器)
- [常见问题](#常见问题)

---

## 哪种情况需要这份文档？

如果你：

- 使用 **LangChain、CrewAI、AutoGen** 等框架（而非 CAI）运行了渗透测试 Agent
- 有自定义的 Agent 日志（每行一个 JSON 对象的 JSONL 文件）
- 希望分析 **OpenAI Assistants API** 的 Run Steps 日志

那么只需按本文档配置适配器，即可将这些日志接入 LORE 的五层分析流水线（Layer 0 → Layer 1 标注 → Layer 2 经验提炼 → Layer 3 融合 → Layer 4 缺口爬取）。

如果你使用的是 **CAI 框架**，系统默认支持，无需任何额外配置。

---

## 快速接入（3 行代码）

```python
from pathlib import Path
from src.layer0 import AdapterRegistry

adapter = AdapterRegistry.auto_detect(Path("your_agent_run.jsonl"))  # 自动识别格式
meta, turns = adapter.parse(Path("your_agent_run.jsonl"))            # 解析

for turn in turns:
    print(f"[Turn {turn.turn_index}] {turn.tool_name}  exit={turn.return_code}")
```

`auto_detect()` 会按顺序检测格式（CAI → LangChain → OpenAI Assistants → Generic），自动选择最合适的适配器。大多数场景下不需要手动指定。

---

## 选择适配器

### CAI

使用 [CAI 框架](https://github.com/alibabacloud-labs/cai-lab) 生成的日志，系统**自动支持**，无需任何配置。

```python
# 不需要做任何事，直接运行流水线
from src.layer0 import run_layer0
result = run_layer0(Path("logs/cai_session.jsonl"))
```

CAI 适配器能获取最完整的信息，包括工具退出码、超时状态、RAG 检索内容和 Agent 推理文本，Layer 1 分析功能全部可用。

---

### LangChain

支持通过 [`FileCallbackHandler`](https://python.langchain.com/docs/concepts/callbacks/) 保存的日志，兼容 LangChain v0.1.x 和 v0.2+。

**在你的 LangChain 代码中保存日志：**

```python
from langchain.callbacks import FileCallbackHandler
from langchain.agents import AgentExecutor

agent_executor = AgentExecutor(
    agent=...,
    tools=...,
    callbacks=[FileCallbackHandler("agent_run.jsonl")],
)
agent_executor.invoke({"input": "Scan 192.168.1.1"})
```

**接入 LORE：**

```python
from src.layer0 import AdapterRegistry

adapter = AdapterRegistry.auto_detect(Path("agent_run.jsonl"))
meta, turns = adapter.parse(Path("agent_run.jsonl"))
```

**若使用了 RAG 检索工具，声明工具名：**

```python
from src.layer0.adapters import LangChainAdapter

# 默认已识别 retrieval / search / kb_search / rag_query 等常见名称
# 若使用了自定义工具名，通过 rag_tool_names 额外声明
adapter = LangChainAdapter(rag_tool_names={"my_retriever", "knowledge_search"})
meta, turns = adapter.parse(Path("agent_run.jsonl"))
```

> LangChain 日志不包含进程退出码（`return_code`），Layer 1 将自动降级为语义分析模式，通过 stdout/stderr 内容判断工具执行结果，不影响最终分析质量。

---

### OpenAI Assistants API

**导出 Run Steps 日志：**

```python
from openai import OpenAI
import json

client = OpenAI()
steps = client.beta.threads.runs.steps.list(thread_id="thread_xxx", run_id="run_xxx")

with open("run_steps.json", "w") as f:
    json.dump([s.model_dump() for s in steps.data], f, indent=2)
```

**接入 LORE：**

```python
from src.layer0 import AdapterRegistry

adapter = AdapterRegistry.get_by_name("openai_assistant")
meta, turns = adapter.parse(Path("run_steps.json"))
```

支持所有内置工具类型：`function`（自定义函数）、`file_search`（RAG 检索）、`code_interpreter`（代码解释器）。同一步骤内的多个并行工具调用会按顺序编号区分。

---

### 任意 JSONL（通用兜底）

如果你的日志是每行一个 JSON 对象的 JSONL 文件，即使字段名不标准，也可以通过字段映射直接接入。系统在无法识别其他格式时会自动使用此方式。

**直接尝试（无需配置）：**

```python
from src.layer0 import AdapterRegistry

# 如果你的日志有 tool_name / output / timestamp 等接近标准的字段，往往开箱即用
adapter = AdapterRegistry.auto_detect(Path("my_agent.jsonl"))
meta, turns = adapter.parse(Path("my_agent.jsonl"))
```

**自定义字段映射（字段名不标准时）：**

```python
from src.layer0.adapters import GenericJsonlAdapter

# 告诉适配器你的日志用哪些字段名，支持点路径访问嵌套字段
adapter = GenericJsonlAdapter(
    field_map={
        "tool_name":   ["action_type"],       # 你的字段名 → 标准字段
        "tool_args":   ["parameters"],
        "stdout":      ["execution_output"],
        "return_code": ["exit_code"],
        "session_id":  ["run_id"],
        "tool_args":   ["action.inputs"],     # 支持嵌套路径
    },
    rag_tool_names={"my_search_tool"},        # 声明 RAG 工具名
)
meta, turns = adapter.parse(Path("my_agent.jsonl"))
```

**默认可识别的字段名：**

| 需要的字段 | 会自动尝试的候选字段名 |
|:---------|:-------------------|
| `tool_name` | `tool_name`, `tool`, `action.tool`, `function.name`, `name` |
| `tool_args` | `tool_args`, `tool_input`, `action.params`, `function.arguments`, `input` |
| `stdout` | `stdout`, `output`, `observation`, `result`, `response` |
| `return_code` | `return_code`, `exit_code`, `rc`, `status_code` |
| `session_id` | `session_id`, `run_id`, `conversation_id`, `trace_id` |
| `timestamp` | `timestamp`, `created_at`, `time`, `ts` |

---

## 接入效果说明

不同框架因日志结构差异，对 Layer 1 分析功能的支持程度不同：

| 分析功能 | CAI | LangChain | OpenAI Assistants | Generic |
|:--------|:---:|:---------:|:-----------------:|:-------:|
| 精确退出码（失败精准分类） | ✅ | — | ⚠️ 部分 | ⚠️ 取决于日志 |
| 超时检测 | ✅ | — | — | ⚠️ 取决于日志 |
| Agent 推理过程 | ✅ | ✅ | — | ⚠️ 取决于日志 |
| RAG 检索因果分析 | ✅ 自动 | ⚠️ 需声明工具名 | ⚠️ 需声明工具名 | ⚠️ 需声明工具名 |
| 并行工具调用区分 | ✅ | ⚠️ | ✅ | — |
| **Layer 1 整体可用度** | 完整 | 良好 | 良好 | 基础 |

**说明：**
- **—** 表示该框架的日志本身不包含此信息，系统会自动降级（不影响其他功能正常运行）
- **⚠️** 表示通过额外配置可以支持
- 缺少退出码时，Layer 1 会通过 LLM 对 stdout/stderr 内容进行语义分析来完成失败分类，结果仍然可用，只是精度略低于有退出码的情况

---

## 贡献新适配器

如果你使用的框架不在支持列表中（例如 AutoGen、CrewAI、Metasploit 终端日志等），可以通过继承 `LogAdapter` 编写适配器并提交 PR，约需 50～100 行代码。

```python
from pathlib import Path
from typing import Iterator, Tuple
from src.layer0 import AdapterRegistry, LogAdapter
from src.layer0.canonical_types import CanonicalAgentTurn, SessionMeta

@AdapterRegistry.register
class MyFrameworkAdapter(LogAdapter):

    @property
    def adapter_name(self) -> str:
        return "my_framework"   # 适配器唯一标识符

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        \"\"\"通过读取文件前几行，快速判断是否为本适配器支持的格式。\"\"\"
        try:
            with open(file_path, encoding="utf-8") as f:
                first_line = f.readline()
            return '"my_framework_marker"' in first_line
        except Exception:
            return False

    def parse(self, file_path: Path) -> Tuple[SessionMeta, Iterator[CanonicalAgentTurn]]:
        \"\"\"返回 (会话元数据, 工具调用的惰性迭代器)。\"\"\"
        meta = SessionMeta(
            session_id="extracted-from-log",
            start_time="2025-01-01T00:00:00Z",
        )

        def _iter():
            with open(file_path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    # 解析每行，转换为 CanonicalAgentTurn
                    yield CanonicalAgentTurn(
                        session_id=meta.session_id,
                        turn_index=i,
                        timestamp="...",
                        tool_name="...",   # 必填
                        tool_args={},      # 必填
                        stdout="...",
                        return_code=0,
                    )

        return meta, _iter()
```

`parse()` 必须返回**惰性迭代器**，不要将整个文件一次性加载到内存（对大型日志友好）。适配器通过装饰器注册后，`auto_detect()` 会自动包含它。

---

## 常见问题

**Q：运行 `auto_detect()` 后适配器名是 `generic`，这正常吗？**

正常。`generic` 是通用兜底适配器，当日志不符合 CAI、LangChain、OpenAI Assistants 的特征格式时自动启用。只要日志字段名接近标准（如含 `tool_name`、`output`），解析结果通常是正确的。若字段名不同，参考[自定义字段映射](#任意-jsonl通用兜底)。

---

**Q：我的日志没有 `return_code` 字段，Layer 1 还能正常分析吗？**

能。Layer 1 的规则层（依赖精确退出码）会跳过，但 LLM 语义层会根据 `stdout`/`stderr` 的内容自动判断工具执行结果，大多数失败类型（如命令语法错误、目标不可达、认证失败）仍然能被正确识别。

---

**Q：我使用了 RAG 检索工具，但 RAG 因果分析功能没有生效怎么办？**

需要告诉适配器哪个工具名对应 RAG 检索。默认已识别 `retrieval`、`search`、`kb_search`、`rag_query` 等常见名称。若使用了自定义名称，通过 `rag_tool_names` 参数声明：

```python
from src.layer0.adapters import LangChainAdapter   # 或 GenericJsonlAdapter
adapter = LangChainAdapter(rag_tool_names={"your_rag_tool_name"})
```

---

**Q：如何查看当前支持多少种适配器？**

```python
from src.layer0 import AdapterRegistry
print(AdapterRegistry.list_adapters())
# ['cai', 'langchain', 'openai_assistant', 'generic']
```

---

*LORE · Log Adapter · [src/layer0/adapters/](../src/layer0/adapters/)*

