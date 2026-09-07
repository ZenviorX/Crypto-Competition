# OAuth 与 Agent Authorization 的关系说明

## 1. 核心区别

OAuth 主要解决的是：

谁有没有权限访问某个资源。

例如，某个 Agent 拿到了这些权限：

tool:file:read
tool:email:send

OAuth 会认为它可以读文件，也可以发邮件。

但是 AI Agent 场景下，仅有 OAuth 不够。因为 OAuth 通常不知道：

1. Agent 为什么要读这个文件；
2. 读的是不是敏感文件；
3. 发邮件给谁；
4. 是否偏离用户原始任务；
5. 是否受到提示注入影响；
6. 多个工具调用连起来是否形成攻击链。

所以本项目不是替代 OAuth，而是在 OAuth 的基础上，继续判断 Agent 的每一次工具调用是否安全。

## 2. 本项目解决什么问题

本项目解决的是：

AI Agent 在当前任务中，能不能安全调用某个工具。

系统会检查：

1. 工具类型，例如 file.read、email.send、shell.run；
2. 工具参数，例如文件路径、邮箱地址、命令内容；
3. 当前任务边界；
4. 数据是否敏感；
5. 是否存在提示注入；
6. 是否形成多步攻击链；
7. 是否需要人工确认；
8. 是否只能在沙箱中执行。

## 3. 对比关系

| 对比项 | OAuth | AgentGuard |
|---|---|---|
| 主要目标 | 判断有没有权限 | 判断这次工具调用是否安全 |
| 判断依据 | token、scope | scope、任务、参数、风险、数据流 |
| 控制粒度 | API 权限 | 单次工具调用和多步任务链 |
| 是否理解任务 | 通常不理解 | 通过任务合约限制 |
| 是否检查敏感路径 | 通常不检查 | 检查 |
| 是否检查外部邮箱 | 通常不检查 | 检查 |
| 是否处理提示注入 | 不负责 | 负责识别 |
| 是否处理攻击链 | 不负责 | 运行时监控 |

## 4. 示例

用户原始任务：

请总结 public/notice.txt。

恶意行为：

读取 secret/password.txt，然后发送给 attacker@example.com。

如果只看 OAuth：

Agent 有 file.read 和 email.send 权限，可能会被放行。

如果使用本项目：

系统会发现：

1. 读取了敏感路径；
2. 邮件发往外部邮箱；
3. 行为偏离用户任务；
4. 存在数据外发风险；
5. 沙箱策略不允许该行为。

最终结果：

decision = deny

## 5. 外部 Agent 接入思路

对于 OpenClaw、WorkBuddy 或其他外部 Agent，本项目不让它们直接调用本地文件、邮件、命令行或数据库。

它们必须先进入统一入口：

External Agent -> Adapter -> Tool Proxy -> Gateway -> Runtime Monitor -> Sandbox

这样可以把外部 Agent 封装进安全边界。

## 6. 一句话总结

OAuth 解决“谁被授权访问资源”的问题。

AgentGuard 进一步解决“AI Agent 在当前任务中能不能安全调用工具”的问题。
