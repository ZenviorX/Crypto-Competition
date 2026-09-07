
Task32：竞赛证据包与防护覆盖矩阵
一、任务背景

前序阶段已经完成 Benchmark、Dashboard、完整性哈希链、数据流安全图谱、SVG 图谱展示和 AgentGuard vs naive baseline 有效性评估。

这些功能已经具备较强展示力，但仍然分散在多个 JSON、HTML、Dashboard 页面和测试文件中。为了更适合信安赛作品提交和答辩展示，本阶段将这些证据整合为统一的“竞赛证据包”。

二、主要修改文件

本阶段主要新增：

backend/evidence/coverage_matrix.py
experiments/generate_competition_evidence_pack.py
scripts/run_competition_evidence.ps1
tests/evidence/test_coverage_matrix.py
tests/benchmark/test_competition_evidence_pack.py
docs/competition_evidence_pack.md
Task/Task32.md
三、主要工作内容
1. 新增防护覆盖矩阵

新增 coverage_matrix.py，用于统计 Benchmark 报告中各防护层的覆盖情况。

覆盖层包括：

Capability Contract；
Runtime Monitor；
Semantic Guard；
Data-flow Security Graph；
SHA-256 Integrity Chain；
Effectiveness Baseline；
Sandbox Executor。

同时统计 file、email、shell、database、network 等攻击面覆盖情况。

2. 新增竞赛证据包生成器

新增 experiments/generate_competition_evidence_pack.py，自动读取最新 Results/Result_XXX.json，生成：

Results/EvidencePack_XXX.json
Results/EvidencePack_XXX.md

证据包包含：

核心指标；
完整性校验；
防护覆盖矩阵；
AgentGuard vs Naive Baseline；
代表性攻击样例；
高风险数据流；
可复现命令；
答辩展示建议。
3. 新增一键演示脚本

新增：

.\scripts\run_competition_evidence.ps1

该脚本会依次执行：

离线 Runtime Benchmark；
竞赛证据包生成；
关键测试；
输出 Dashboard 启动提示。
4. 新增自动化测试

新增测试覆盖：

防护覆盖矩阵计算；
EvidencePack Markdown / JSON 生成；
完整性校验结果写入；
防护覆盖评分写入；
代表性案例写入。
四、任务价值

本阶段将项目从“功能系统”进一步提升为“可提交、可展示、可复查的竞赛作品材料”。

答辩时可以这样表述：

我们不仅实现了 Agent 工具调用的授权控制、运行时监控、语义检测、数据流图谱和完整性校验，还进一步构建了自动化竞赛证据包生成机制。系统能够将每次 Benchmark 结果自动汇总为 Markdown 和 JSON 证据包，包含防护覆盖矩阵、攻击面覆盖、完整性哈希、有效性对比和代表性案例，使作品具备可复现、可审计、可量化的评测材料。
