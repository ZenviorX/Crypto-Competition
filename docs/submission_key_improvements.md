# 提交前关键改进说明

## 1. 改进目标

本轮改进不再继续堆叠边缘功能，而是围绕线下评审最关注的三个问题进行增强：

1. 项目是否真的能接入真实 AI Agent，而不是只停留在 FakeAgent 演示；
2. AgentGuard 相比 NoGuard、OAuth-only、Keyword-only 是否有清晰优势；
3. 作品报告中是否能形成“威胁模型—安全机制—实验验证”的完整闭环。

## 2. 新增真实 LLM Tool Calling 适配入口

新增模块：

- `backend/real_agent/tool_call_adapter.py`
- `backend/routes/llm_tool_call_routes.py`

新增接口：

```text
POST /real-agent/tool-call/run
该接口支持 OpenAI / DeepSeek / OpenAI-compatible 模型的 tool-calling 输出格式。例如：

{
  "user": "user",
  "original_task": "请读取 public/notice.txt 并总结",
  "execute": true,
  "llm_tool_call": {
    "tool_calls": [
      {
        "type": "function",
        "function": {
          "name": "file.read",
          "arguments": "{\"path\":\"public/notice.txt\"}"
        }
      }
    ]
  }
}

执行链路为：

Real LLM tool_call
  -> OpenAI-compatible adapter
  -> Tool Proxy prepare
  -> Capability Token
  -> execute=true
  -> Hybrid Sandbox
  -> Audit / Evidence

这可以用于回答评委问题：

你们保护的是真实 Agent，还是自己模拟的 Agent？

回答要点：

项目既保留 FakeAgent 作为稳定演示入口，也新增了 OpenAI-compatible tool-call adapter。真实大模型只负责生成工具调用计划，AgentGuard 负责统一授权、Token 绑定、沙箱执行和审计证据。

3. 新增四组对比实验

新增脚本：

scripts/run_submission_key_eval.py

运行方式：

python scripts\run_submission_key_eval.py

输出文件：

docs/evaluation/submission_key_eval_summary.json
docs/evaluation/submission_key_eval_cases.csv
docs/evaluation/submission_key_eval_report.md

对比方法：

方法含义
NoGuard不做任何检查，所有工具调用直接放行
OAuth-only只检查工具调用声明的 scope 是否满足要求
Keyword-only只检查参数中是否包含危险关键词
AgentGuard使用完整网关策略进行综合判断
