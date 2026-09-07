# Task27：离线真实 Agent Runtime Benchmark 与自动编号报告

## 一、任务背景

前一阶段中，项目已经构建了真实 Agent Runtime 样例库 `security_cases/llm_runtime_cases.json`，覆盖 normal、suspicious、attack 三类场景，包括公开文件读取、内部邮箱发送、数据库只读查询、提示注入、路径穿越、凭证访问、数据外发、破坏性 SQL、危险 Shell 命令等。

但是，样例库本身仍偏向“规格描述”，如果只靠人工阅读 JSON，评审难以快速确认这些样例是否真正经过系统运行时防护链路执行。因此，本阶段将真实 Agent Runtime 样例库进一步升级为可自动执行、可复查、可生成证据报告的离线 Benchmark。

## 二、主要修改文件

本阶段主要新增或修改以下文件：

- backend/agents/offline_runtime_agent.py
- experiments/run_llm_runtime_benchmark.py
- tests/benchmark/test_llm_runtime_offline_benchmark.py
- docs/llm_runtime_offline_benchmark.md
- backend/capability/capability_compiler.py
- backend/capability/capability_enforcer.py
- backend/gateway/semantic_guard.py
- Results/Result_XXX.json
- Results/Result_XXX.html

## 三、主要工作内容

### 1. 新增 OfflineRuntimeAgent

新增 `backend/agents/offline_runtime_agent.py`，用于根据 `llm_runtime_cases.json` 中的样例规格生成确定性的候选工具调用计划。

它不调用真实大模型，因此不依赖 API Key 和网络环境，但仍然复用真实的：

- TaskSession
- Capability Contract
- Runtime Monitor
- Attack Chain Detector
- Sandbox Executor
- input_labels / output_labels 数据流追踪

这样可以保证比赛现场即使无法联网或无法调用大模型，也能稳定展示 Agent Runtime 安全防护效果。

### 2. 新增离线 Benchmark 脚本

新增 `experiments/run_llm_runtime_benchmark.py`，用于一键运行所有真实 Agent Runtime 样例。

运行命令：

```powershell
python experiments\run_llm_runtime_benchmark.py

脚本会自动读取：

security_cases/llm_runtime_cases.json

并生成：

Results/Result_XXX.json
Results/Result_XXX.html

其中 XXX 会根据 Results 目录下已有 Result_数字 文件自动递增，避免固定命名覆盖旧结果。

3. 修复 Capability Contract 对安全工具的授权一致性

前一版本中，样例库已经包含正常的 db.query 和管理员低风险 shell.run 场景，但 Capability Contract 默认把 db.query、shell.run 放入 forbidden_tools，容易造成“样例描述”和“真实执行结果”不一致。

本阶段改进后：

明确的公开 SELECT 查询可以生成 db.query 能力；
DROP / DELETE / UPDATE 等破坏性 SQL 仍然拒绝；
管理员低风险 shell 命令可进入确认；
curl / wget / rm 等危险 shell 行为仍然拒绝；
路径穿越和 secret/private 资源仍然保持禁止。
4. 稳定语义检测模块

本阶段将 semantic_guard.py 改进为“确定性语义检测优先、Embedding 可选增强”的结构。

这样做的意义是：

比赛现场不再完全依赖 sentence-transformers 模型是否下载成功；
即使本地没有 embedding 模型，也能稳定输出 semantic_guard.enabled=True；
对数据外发、凭证访问、策略绕过、提示注入、破坏性操作、网络滥用、提权等风险生成可解释标签；
保留后续接入 embedding 模型进行语义增强的能力。
5. 新增 Benchmark 测试

新增 tests/benchmark/test_llm_runtime_offline_benchmark.py，验证：

离线 Benchmark 能运行全部样例；
样例覆盖 normal / suspicious / attack 三类场景；
Benchmark 能生成 JSON 和 HTML 报告；
离线运行不依赖真实 LLM API。
四、测试结果

本阶段本地已通过以下测试：

python -m pytest tests\benchmark\test_llm_runtime_offline_benchmark.py -q
python experiments\run_llm_runtime_benchmark.py
python -m pytest tests -q

完整测试通过后，项目具备了稳定的一键离线评测能力。

五、任务价值

本阶段的核心价值是把真实 Agent Runtime 从“演示链路”进一步升级为“可复现评测体系”。

答辩时可以这样表达：

本项目不仅能接入真实 LLM Agent 展示工具调用防护，还构建了离线可复现的 Agent Runtime Benchmark。系统可以在不依赖外部大模型 API 的情况下，自动执行覆盖正常、可疑、攻击三类场景的样例库，并生成 JSON/HTML 证据报告。每个样例都会经过 Capability Contract、Runtime Monitor、Attack Chain Detector 和 Sandbox Executor 的完整链路，因此评测结果可复查、可复现、可审计。

六、后续方向

后续可以继续增强：

将 Benchmark 结果接入前端 Dashboard；
为每个样例生成更细粒度的攻击链图谱；
将 Benchmark 结果写入审计日志和哈希链；
增加 MCP、浏览器、代码执行等更复杂工具场景；
增加与真实 LLM Agent 运行结果的对照评测。
