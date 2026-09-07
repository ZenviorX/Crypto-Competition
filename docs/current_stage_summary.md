# 当前阶段完成情况

本阶段已完成 AgentGuard 授权主线的后端增强、自动化测试和前端演示接入。

## 一、后端主线

已完成以下能力：

1. OAuth-only 与 AgentGuard 横向对比
2. Task Boundary Guard 任务边界守卫
3. Capability Contract 能力契约
4. Data Provenance Guard 数据来源守卫
5. Authorization Trace 可解释授权链路
6. Task-scoped Capability Token 任务级临时授权凭证
7. prepare -> execute 两阶段授权流程
8. Token 绑定任务、工具、参数、沙箱和契约
9. Token 过期、撤销、消费、防重放
10. Token Ledger 生命周期审计
11. 后端自动化回归测试脚本

## 二、前端展示

已完成以下内容：

1. 修复主要前端中文乱码
2. 新增“两阶段授权”演示页面
3. 接入 prepare、execute、token status 接口
4. 页面展示 Prepare、Execute、Replay 三个阶段结果
5. 页面展示 Authorization Trace 和 Token 生命周期状态

## 三、当前演示效果

浏览器中点击“两阶段授权”页面并运行演示后，正常结果为：

Prepare: allow
Execute: allow
Replay: deny

这说明系统不是直接执行工具，而是先进行授权准备。Prepare 阶段通过后签发一次性 Capability Token，Execute 阶段必须携带该 Token 才能真正执行工具。Token 执行后会被消费，再次复用会被拒绝。

## 四、项目亮点

普通 OAuth scope 只能说明外部 Agent 拥有某类长期权限，而 AgentGuard 进一步判断本次工具调用是否符合当前任务、当前参数、当前沙箱、当前能力契约和当前风险边界。

因此，本项目的核心创新点是：

从“长期权限授权”升级为“任务级、一次性、可审计、可解释的 Agent 工具调用授权”。
