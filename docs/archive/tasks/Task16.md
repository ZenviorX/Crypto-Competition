本阶段主要围绕项目主干能力进行了升级，将原先偏单次工具调用判断的授权网关，进一步扩展为具备任务级运行时监控能力的安全框架。首先新增了 Capability Contract v2，用于根据用户原始任务生成更细粒度的能力合约，明确限定本次任务中允许使用的工具、资源路径、外发对象、风险预算和最大执行步数。随后实现了 Capability Compiler 和 Capability Enforcer，使系统能够自动从任务描述中生成授权边界，并在每一步工具调用前检查是否越权。

在此基础上，进一步加入 Runtime Monitor，开始记录任务执行过程中的步骤状态、已消耗风险、输入输出标签、阻断原因和任务是否被终止。为了应对提示注入场景，还实现了 Flow Label / Taint Analyzer，能够对工具输出内容进行标签分析，将公开文件中隐藏的提示注入内容标记为 prompt_injection 和 tainted，并在后续外发操作中触发确认或拒绝。之后将这些能力封装成 Runtime API，支持启动任务、执行步骤、继承历史步骤标签和查看完整运行时状态。

前端方面新增了 runtime_demo.html 页面，并在首页加入入口按钮，用于演示完整的运行链路：读取 public/injected_notice.txt 时允许执行，但输出被标记为 public、prompt_injection、tainted；当该污染数据发送给 [teacher@example.com](mailto:teacher@example.com) 时进入人工确认；当尝试发送给 [attacker@example.com](mailto:attacker@example.com) 时被系统拒绝。同时修复了任务进入 blocked 状态后仍可重复追加步骤的问题，并补充了对应的后端测试和接口测试。至此，项目已经从简单的规则判断升级为“任务级能力合约 + 运行时状态追踪 + 污染标签传播 + 信息流控制”的主干框架，为后续审计图展示和比赛演示打下了基础。
