# EVALUATION

状态：PROPOSED

## 旧评测体系

旧 AgentGuard 已有 NoGuard / OAuth-only / Keyword-only / AgentGuard 对比、Runtime Benchmark、Evidence Pack、风险样例与可视化报告。这些材料可作为历史 baseline，但不能直接代表新密码赛方案的有效性。

## 新评测目标

后续评测应围绕授权一致性和密码学证据建立新的实验体系，至少考虑：

- 正常合法调用通过率；
- 参数越界 / 权限扩张阻断；
- 主体或 Holder 替换阻断；
- VC/VP/token 篡改检测；
- 过期与撤销；
- replay / usage limit；
- 授权与验证延迟；
- token / VC / proof 大小；
- 与 OAuth/RAR 基线、现有 Agent Authorization 方案的协议和工程开销对比。

具体数据集、baseline 和统计方法尚未最终冻结，完成前保持 `PROPOSED`。
