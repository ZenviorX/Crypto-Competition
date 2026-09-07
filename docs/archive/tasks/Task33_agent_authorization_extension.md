# Task33：外部 Agent 授权接入、OAuth-style Scope 与 Sandbox Policy 增强

## 1. 本阶段目标

本阶段根据老师提出的“Agent 授权、OAuth 鉴别、外部 Agent 沙箱封装”等建议，对项目进行了系统性增强。

本次改进不是只增加一个演示字段，而是围绕外部 Agent 工具调用安全边界，补充了完整链路：

`	ext
External Agent
    ↓
External Agent Adapter
    ↓
Tool Proxy
    ↓
OAuth-style Scope Check
    ↓
Sandbox Policy
    ↓
Capability Contract
    ↓
Runtime Monitor
    ↓
allow / confirm / deny
2. 核心新增内容
2.1 OAuth-style Agent Authorization

新增或增强：

backend/proxy/oauth_profile.py
backend/proxy/proxy_models.py
backend/proxy/tool_proxy_service.py

实现内容：

根据工具调用自动推导 required_scopes；
从 requested_scopes 和 oauth_token_claims 中提取 declared_scopes；
比较 missing_scopes；
生成 agent_auth_profile；
在 scope 不足时提前 deny；
说明 OAuth 与 AgentGuard 的区别。

本项目并不是简单接入 OAuth，而是借鉴 OAuth 的 scope 思想，用于约束外部 Agent 的工具调用权限。

2.2 External Agent Adapter

新增：

backend/adapters/external_agent_adapter.py
backend/routes/external_agent_routes.py

实现内容：

模拟 OpenClaw / WorkBuddy / Custom Agent 接入；
将不同外部 Agent 请求标准化为 ToolProxyAuthorizeRequest；
提供 /external-agent/simulate 接口；
支持 valid_public_read、insufficient_scope_email、valid_internal_email_confirm、sandbox_block_shell 等场景；
返回 adapter_trace，展示外部 Agent 如何进入安全边界。
2.3 Sandbox Policy

新增：

backend/sandbox/sandbox_policy.py

实现内容：

将 sandbox_profile 从简单字段升级为独立策略模块；
支持 default、local_readonly、local_safe_write、no_shell、strict 等沙箱配置；
对 file.read、email.send、shell.run、file.write 等工具进行策略判断；
返回 sandbox_evaluation；
在 Tool Proxy 层融合沙箱判定结果。
2.4 前端展示增强

修改：

frontend/src/types/domain.ts
frontend/src/services/api.ts
frontend/src/pages/GatewayWorkbench.tsx

前端新增展示内容：

OAuth-style Agent Authorization Profile；
required_scopes / declared_scopes / missing_scopes；
scope_decision；
External Agent Adapter trace；
normalized Tool Proxy request；
Sandbox Policy evaluation；
allowed_tools / denied_tools；
filesystem / network / shell_enabled / side_effects。

这样展示时，老师和评委不需要直接看 Swagger JSON，也能理解完整安全链路。

3. 新增评测脚本

新增：

experiments/run_external_agent_adapter_eval.py
experiments/run_sandbox_policy_eval.py
experiments/run_agent_authorization_extension_eval.py

其中：

run_external_agent_adapter_eval.py：验证 OpenClaw / WorkBuddy / Custom Agent Adapter；
run_sandbox_policy_eval.py：独立验证 Sandbox Policy；
run_agent_authorization_extension_eval.py：统一验收 OAuth、Adapter、Sandbox 三层增强。
4. 测试结果

本阶段所有测试结果均按照项目已有格式保存到：

Results/Result_XXX.json

重点验收结果包括：

OpenClaw 合法读取公开文件 -> allow
WorkBuddy scope 不足外发邮件 -> deny
WorkBuddy 内部邮件发送 -> confirm
Custom Agent shell 命令 -> deny
Sandbox Policy 独立评测 -> 通过
前端构建 -> 通过
总验收脚本 -> 通过
5. 本阶段意义

本阶段改进后，项目从“本地 Agent 工具调用网关”进一步扩展为：

面向外部 Agent 平台的工具调用授权与安全执行边界

它能够回应老师提出的几个关键问题：

项目与 OAuth 的关系是什么；
为什么只靠 OAuth 不够；
OpenClaw / WorkBuddy 这类外部 Agent 如何接入；
外部 Agent 如何被封装到沙箱；
工具调用如何经过多层安全检查；
如何证明这些模块不是临时 demo，而是有评测脚本验证。
6. 展示时可以这样讲

OAuth 主要解决“谁被授权访问资源”的问题，而 AI Agent 工具调用还需要进一步回答“这个 Agent 在当前任务中能不能安全调用这个工具”。

因此，我们将 OAuth-style scope 引入 Tool Proxy，但不止步于 scope。外部 Agent 的请求首先经过 Adapter 标准化，然后进入 Tool Proxy。Tool Proxy 会依次检查 scope、沙箱策略、任务能力边界和运行时数据流，最终输出 allow、confirm 或 deny。

这样一来，OpenClaw、WorkBuddy 或其他外部 Agent 都不能直接接触本地文件、邮件、Shell 等工具，而是必须经过统一授权边界。

7. 后续建议

下一步可以继续做：

README 中加入“外部 Agent 接入与沙箱封装”章节；
把新增评测脚本纳入总 benchmark；
在展示 PPT 中增加一张 External Agent Adapter 架构图；
在报告中单独写“OAuth-style scope 与 AgentGuard 授权机制对比”；
增加更多真实外部 Agent 请求样例。
