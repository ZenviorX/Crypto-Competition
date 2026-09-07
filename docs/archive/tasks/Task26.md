# Task26：真实 Agent Runtime 样例库与评测约束增强

一、任务背景

在前一阶段中，项目已经完成真实 Stepwise LLM Agent 运行时防护链路，能够展示真实大模型 Agent 根据用户任务逐步规划工具调用，并在每一步执行前经过 Capability Contract、Runtime Monitor、Attack Chain Detector 和 Sandbox Executor 的联合检查。

但是，早期真实 Agent Runtime 样例数量较少，更多用于说明功能链路，尚不足以支撑较强的比赛评测表达。为了让该模块从“演示功能”进一步升级为“可复查的评测规格”，本阶段对真实 Agent Runtime 样例库和测试约束进行了系统增强。

二、主要修改文件

本阶段主要修改以下文件：

security_cases/llm_runtime_cases.json
tests/test_llm_runtime_cases.py
docs/real_agent_runtime.md
README.md
Task/Task26.md
三、主要工作内容
1. 扩充真实 Agent Runtime 样例库

将 security_cases/llm_runtime_cases.json 从早期 5 条样例扩展到 18 条样例，覆盖 normal、suspicious、attack 三类真实 Agent Runtime 场景。

当前样例分布如下：

类别数量说明
normal5公开文件读取、公开文档读取、内部邮箱发送、只读数据库查询、安全 Shell 命令
suspicious2外部合作邮箱发送、private 内部资料读取
attack11间接提示注入、secret 读取、.env/token 访问、路径穿越、凭证外发、curl 外联、DROP TABLE、低置信度敏感计划、文件删除
2. 增强正常场景覆盖

新增多个正常样例，用于证明系统不是简单地“一律拒绝”，而是能够在任务边界内支持 Agent 完成合理工作。

代表样例包括：

llm_normal_public_notice_summary
llm_normal_public_guide_summary
llm_normal_public_read_then_internal_email
llm_normal_public_db_select_summary
llm_normal_safe_shell_pwd

这些样例主要用于观察误拒率，并在答辩中说明系统兼顾安全性和可用性。

3. 增强可疑场景覆盖

新增可疑场景，用于展示系统对灰区任务的处理能力。

代表样例包括：

llm_suspicious_public_read_then_external_partner_email
llm_suspicious_private_course_plan_summary

这类任务不一定必须直接拒绝，更适合进入人工确认或受策略约束，可以体现系统的风险分级思想。

4. 增强攻击场景覆盖

扩充多类真实 Agent Runtime 攻击样例，包括：

间接提示注入诱导外发；
提示注入诱导读取 secret；
直接读取 secret/password.txt；
读取 .env 或 token；
路径穿越读取 secret；
敏感内容发送到攻击者邮箱；
提示注入诱导绕过 Gateway；
使用 curl 外发 secret 文件；
执行 DROP TABLE 破坏数据库；
低置信度敏感资源访问；
删除公开文件等破坏性操作。

这些样例覆盖了 Agent 工具调用中常见的敏感资源访问、凭证泄露、数据外发、提示注入、路径穿越、破坏性操作等风险。

5. 强化测试约束

重写并增强 tests/test_llm_runtime_cases.py，使测试不再只是检查字段是否存在，而是进一步检查样例库是否具有足够覆盖能力和安全语义约束。

新增或增强的测试包括：

样例数量不少于 15 条；
normal / suspicious / attack 三类样例均有覆盖；
攻击样例不能只期望 allow；
正常样例不能只期望 deny；
正常样例必须显式禁止攻击者邮箱和 secret 访问；
prompt injection 样例必须体现 tainted 标签或阻断预期；
样例库必须覆盖 file.read、email.send、shell.run、db.query、file.delete 等工具；
secret、token、.env、password 等敏感场景必须要求阻断或确认；
删除、DROP、curl 等破坏性或外发行为必须进入确认或拒绝。
四、测试结果

本地已经通过以下测试：

python -m pytest tests/test_llm_runtime_cases.py -q
python -m pytest tests -q
python tests/dashboard/generate_ci_dashboard.py

当前完整测试结果为：

181 passed

并已生成新的 Dashboard：

Results/Result_025.html
Results/Result_025.json
五、任务价值

本阶段的核心价值在于增强真实 Agent Runtime 模块的评测说服力。

在此之前，真实 Stepwise LLM Agent 模块已经能够展示“真实 Agent 逐步规划 + 运行时检查 + 沙箱执行 + 攻击链阻断”的链路，但样例数量较少，更多偏向功能演示。本阶段通过扩充样例库和强化测试约束，使该模块具备了更强的可复查性和可扩展性。

这一改进可以在答辩中表达为：

本项目不仅能演示真实 LLM Agent 接入后的攻击链防护过程，还构建了覆盖正常、可疑、攻击三类场景的真实 Agent Runtime 样例库，并通过自动化测试约束样例质量，保证系统评测不是单一脚本演示，而是可复查、可扩展的安全评测规格。

六、当前不足与后续方向

后续仍可继续从以下方向增强：

将 llm_runtime_cases.json 从规格样例进一步升级为可自动执行的真实 Agent Runtime benchmark；
将每条真实 Agent Runtime case 的执行结果写入 Dashboard；
增加更多浏览器、MCP 工具、代码执行工具等复杂工具场景；
将 confirm 状态与人工确认队列打通，实现确认后继续执行；
将真实 Agent Runtime 的执行证据写入审计日志和哈希链；
增加离线 Mock LLM 模式，避免真实 API 不稳定影响比赛现场展示。
七、阶段总结

通过本阶段工作，项目从“真实 Agent Runtime 演示链路”进一步升级为“真实 Agent Runtime 评测规格”。这对冲击高等级奖项非常重要，因为它能让评审看到项目不只是做了一个可运行 demo，而是具备系统化样例、自动化测试和可复查文档的完整工程闭环。
