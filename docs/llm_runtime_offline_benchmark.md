# LLM Runtime Offline Benchmark

本模块用于将 `security_cases/llm_runtime_cases.json` 从“样例规格”升级为“可执行评测”。

## 设计目的

真实 LLM Agent Runtime 演示依赖大模型 API Key 和网络环境。比赛现场或 CI 环境中，真实 API 可能不可用，因此项目需要一个稳定的离线评测模式。

Offline Benchmark 的定位不是替代真实 LLM，而是提供一个可复查、可重复、可自动化的安全评测入口：

1. 读取 `security_cases/llm_runtime_cases.json`；
2. 使用 OfflineRuntimeAgent 根据样例期望生成确定性候选工具调用；
3. 复用现有 `TaskSession -> Capability Contract -> Runtime Monitor -> Sandbox Executor` 执行链；
4. 输出 JSON 和 HTML 报告，展示每个样例的决策、步骤、风险分、标签和检查结果。

## 运行方式

```powershell
python experiments\run_llm_runtime_benchmark.py
默认输出：

Results/llm_runtime_benchmark.json
Results/llm_runtime_benchmark.html
评审表达

这部分可以在答辩中表述为：

本项目不仅提供真实 LLM Agent 接入演示，还构建了离线可复现的 Runtime Benchmark。即使没有外部大模型 API，系统仍能基于同一套 Capability Contract、Runtime Monitor、Attack Chain Detector 和 Sandbox Executor 执行安全评测，生成可审计的 JSON/HTML 证据报告。
