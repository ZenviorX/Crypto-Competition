# Task18：运行时攻击链防护、系统能力总览与安全对比实验

## 一、任务背景

在 Task17 中，项目已经新增了可解释风险评估、网关安全评测、审计哈希链、多步攻击链检测模块和实验报告展示能力。但当时的攻击链检测主要仍以：

```text
独立模块
演示脚本
离线评测报告
```

为主。

也就是说，系统虽然能够证明“攻击链检测逻辑可行”，但还没有完全进入运行时工具调用链路。为了进一步提升项目的实战性和展示效果，本阶段继续围绕以下问题展开改进：

```text
1. 攻击链检测能否参与真实接口调用的最终决策？
2. 是否可以通过网页动态演示运行时攻击链防护？
3. 是否可以批量评测多步攻击链样例，而不是只做一个 demo？
4. 是否可以对比无防护、单步网关和完整系统的效果差异？
5. 是否可以提供系统能力总览接口，让项目状态更直观？
```

因此，本阶段目标是将项目进一步升级为：

```text
运行时攻击链防护 + 安全能力总览 + 批量攻击链评测 + 对比实验
```

---

## 二、本阶段核心目标

本阶段主要完成以下目标：

```text
1. 将 AttackChainDetector 接入运行时接口。
2. 新增 /attack-chain/check、/attack-chain/session、/attack-chain/reset 接口。
3. 新增运行时攻击链演示页面 /attack-chain-runtime。
4. 新增攻击链样例库与批量评测脚本。
5. 新增系统能力概览接口 /security/overview。
6. 更新安全总览页，使其展示测试数量、样例数量、报告状态和能力启用情况。
7. 新增安全对比实验，对比 Baseline、Gateway-only、Gateway + AttackChain 三种模式。
8. 更新 CI，使自动化流程覆盖更多实验。
```

---

## 三、本阶段主要新增能力

### 3.1 运行时攻击链检测接口

新增路由文件：

```text
backend/routes/attack_chain_routes.py
```

新增接口：

```text
POST /attack-chain/check
GET /attack-chain/session/{session_id}
POST /attack-chain/reset/{session_id}
```

其中 `POST /attack-chain/check` 的核心流程为：

```text
1. 接收带 chain_session_id 的 ToolCallRequest
2. 调用原 Gateway 进行单次工具调用风险判断
3. 将本次调用事件写入对应 session 的 AttackChainDetector
4. 根据 Gateway 决策与攻击链决策合并得到 effective_decision
```

返回结构包括：

```text
session_id
gateway_decision
chain_decision
effective_decision
gateway_result
chain_result
```

其中：

```text
gateway_decision：单次工具调用的网关决策
chain_decision：会话级攻击链检测结果
effective_decision：最终生效决策
```

合并规则：

```text
deny > confirm > allow
```

也就是说，任意一层发现更高风险，最终决策都采用更严格结果。

---

### 3.2 运行时攻击链演示页面

新增页面：

```text
frontend/attack_chain_runtime.html
```

新增访问路由：

```text
/attack-chain-runtime
```

该页面支持按按钮演示完整攻击链：

```text
0. 重置会话
1. 写入提示注入内容
2. 读取 secret/password.txt
3. 向 attacker@example.com 外发敏感信息
4. 查看攻击链会话状态
```

页面展示：

```text
gateway_decision
chain_decision
effective_decision
cumulative_risk
summary
events
```

最终应看到：

```text
effective_decision: deny
```

该页面使攻击链检测从“离线脚本结果”变成“浏览器可交互演示”。

---

### 3.3 攻击链批量评测体系

新增样例库：

```text
security_cases/attack_chain_cases.json
```

当前包含 8 条攻击链样例，覆盖：

```text
正常公开文件读取
正常内部邮件发送
正常课程读取后内部发送
提示注入后访问 secret 文件
完整数据外发攻击链
提示注入诱导高危命令
浏览器外部内容引发提示注入后访问 secret
外部发送但未形成完整攻击链
```

新增脚本：

```text
experiments/run_attack_chain_benchmark.py
```

自动生成：

```text
experiments/attack_chain_benchmark_results.csv
experiments/attack_chain_benchmark_report.md
```

新增报告接口：

```text
GET /reports/attack-chain-benchmark
```

评测指标包括：

```text
Overall accuracy
Normal chain consistency
Attack chain detection consistency
```

---

### 3.4 系统能力概览接口

新增路由文件：

```text
backend/routes/security_overview_routes.py
```

新增接口：

```text
GET /security/overview
```

返回项目当前能力状态，包括：

```text
项目名称
系统简介
单元测试数量
网关安全样例数量
攻击链样例数量
安全样例总数
实验报告是否存在
GitHub Actions 是否配置
核心安全能力是否启用
```

返回示例结构：

```json
{
  "project": "Agent-Authorization",
  "metrics": {
    "unit_test_cases": 43,
    "gateway_security_cases": 30,
    "attack_chain_cases": 8,
    "total_security_cases": 38
  },
  "automation": {
    "github_actions_configured": true
  },
  "features": [
    {
      "key": "explainable_risk",
      "name": "可解释风险评估",
      "enabled": true
    },
    {
      "key": "attack_chain_runtime",
      "name": "运行时攻击链检测",
      "enabled": true
    }
  ]
}
```

---

### 3.5 安全总览页增强

继续增强：

```text
frontend/security_dashboard.html
```

新增“系统能力概览”模块，前端会调用：

```text
/security/overview
```

并展示：

```text
单元测试数量
网关安全样例数量
攻击链样例数量
安全样例总数
GitHub Actions 配置状态
网关评测报告是否已生成
攻击链演示报告是否已生成
攻击链评测报告是否已生成
核心能力启用情况
```

同时增加入口：

```text
运行时攻击链演示
攻击链评测报告
安全对比实验报告
```

---

### 3.6 安全对比实验

新增脚本：

```text
experiments/run_comparison_benchmark.py
```

该脚本基于攻击链样例库，对比三种模式：

```text
1. Baseline：无防护，所有工具调用默认 allow
2. Gateway-only：仅使用单步 Gateway 判断每次工具调用
3. Gateway + AttackChain：使用 Gateway 再叠加会话级攻击链检测
```

自动生成：

```text
experiments/comparison_benchmark_results.csv
experiments/comparison_benchmark_report.md
```

新增报告接口：

```text
GET /reports/comparison-benchmark
```

报告展示指标：

```text
Normal workflow acceptance
Attack workflow protection
Overall safe decision rate
```

这个实验可以用来回答评委常问的问题：

```text
你们的方法相比没有防护、相比普通单步规则网关，到底提升在哪里？
```

---

### 3.7 CI 自动化增强

更新：

```text
.github/workflows/ci.yml
```

CI 从原来的：

```text
单元测试
网关安全评测
攻击链演示
```

扩展为：

```text
单元测试
网关安全评测
攻击链演示
攻击链批量评测
安全对比实验
```

同时上传以下报告：

```text
gateway_benchmark_results.csv
gateway_benchmark_report.md
attack_chain_demo_result.json
attack_chain_demo_report.md
attack_chain_benchmark_results.csv
attack_chain_benchmark_report.md
comparison_benchmark_results.csv
comparison_benchmark_report.md
```

---

## 四、修改文件总览

本阶段主要修改和新增文件如下：

```text
backend/routes/attack_chain_routes.py
backend/routes/security_overview_routes.py
backend/routes/report_routes.py
backend/main.py

frontend/attack_chain_runtime.html
frontend/security_dashboard.html

security_cases/attack_chain_cases.json

experiments/run_attack_chain_benchmark.py
experiments/attack_chain_benchmark_results.csv
experiments/attack_chain_benchmark_report.md
experiments/run_comparison_benchmark.py
experiments/comparison_benchmark_results.csv
experiments/comparison_benchmark_report.md

tests/test_attack_chain_runtime_routes.py
tests/test_attack_chain_runtime_page.py
tests/test_attack_chain_benchmark_cases.py
tests/test_security_overview_route.py
tests/test_comparison_benchmark.py

.github/workflows/ci.yml
```

---

## 五、关键实现说明

### 5.1 运行时攻击链接口请求模型

新增：

```python
class AttackChainGatewayRequest(ToolCallRequest):
    chain_session_id: str = Field(default="default")
```

该模型继承 `ToolCallRequest`，因此兼容原有：

```text
user
tool
params
task_contract
input_labels
current_step
used_risk
agent_confidence
plan_status
plan_warnings
```

并额外增加：

```text
chain_session_id
```

用于区分不同攻击链会话。

---

### 5.2 攻击链会话管理

新增内存态会话表：

```python
_DETECTORS: Dict[str, AttackChainDetector] = {}
```

对应方法：

```python
def get_detector(session_id: str) -> AttackChainDetector:
    ...

def reset_detector(session_id: str) -> AttackChainDetector:
    ...
```

作用：

```text
同一个 chain_session_id 下的连续工具调用会进入同一个 AttackChainDetector，从而实现会话级风险累积。
```

---

### 5.3 决策合并逻辑

新增：

```python
def merge_decision(gateway_decision: str, chain_decision: str) -> str:
    severity = {
        "allow": 0,
        "confirm": 1,
        "deny": 2,
    }
    ...
```

合并原则：

```text
deny 优先级最高
confirm 次之
allow 最低
```

因此：

```text
Gateway allow + Chain deny → effective deny
Gateway confirm + Chain allow → effective confirm
Gateway allow + Chain confirm → effective confirm
Gateway deny + Chain allow → effective deny
```

---

### 5.4 系统能力概览统计

`/security/overview` 通过静态分析和文件检查得到：

```text
测试数量：扫描 tests/test_*.py 中 test_ 开头的方法
网关样例数量：读取 security_cases/gateway_cases.json
攻击链样例数量：读取 security_cases/attack_chain_cases.json
报告状态：检查 experiments 下对应报告是否存在
CI 状态：检查 .github/workflows/ci.yml 是否存在
```

该接口不会替代真实测试执行，但可以作为展示项目完成度的概览入口。

---

### 5.5 安全对比实验逻辑

对比实验中三种模式定义如下：

#### Baseline

```text
所有工具调用默认 allow
```

用于模拟无防护 Agent。

#### Gateway-only

```text
对每一步工具调用独立执行 check_tool_call
多步任务中只要任意一步 confirm / deny，就认为链路被升级或阻断
```

用于模拟单步规则网关。

#### Gateway + AttackChain

```text
每一步先经过 Gateway
再输入 AttackChainDetector
最终使用更严格决策作为 effective_decision
```

用于模拟完整系统。

该实验能更好说明：

```text
完整系统并不是简单关键词过滤，而是单步授权 + 会话级链式风险检测的组合防护。
```

---

## 六、新增测试

本阶段新增测试包括：

```text
1. /attack-chain/check 正常公开读取测试
2. /attack-chain/check 恶意链路升级测试
3. /attack-chain/session/{session_id} 会话查询测试
4. /attack-chain-runtime 页面可访问测试
5. attack_chain_cases.json 样例库存在性测试
6. 攻击链样例期望决策测试
7. /security/overview 接口可访问测试
8. /security/overview features 字段测试
9. comparison benchmark 脚本存在性测试
10. /reports/comparison-benchmark 报告接口测试
```

当前单元测试总数：

```text
43 项
```

覆盖模块包括：

```text
Gateway 授权
PlanGuard
TaskContract
Capability Contract
Runtime Monitor
审计哈希链
多步攻击链检测
运行时攻击链接口
运行时攻击链页面
安全总览页
报告接口
攻击链批量评测
安全对比实验
```

---

## 七、验收命令

本阶段完成后可运行：

```powershell
python experiments\run_gateway_benchmark.py
python experiments\run_attack_chain_demo.py
python experiments\run_attack_chain_benchmark.py
python experiments\run_comparison_benchmark.py
python -m unittest discover -s tests
```

预期结果：

```text
Gateway Benchmark：30 / 30 通过
Attack Chain Demo：Final decision: deny
Attack Chain Benchmark：8 / 8 通过
Comparison Benchmark：正常生成 CSV 与 Markdown 报告
Unit tests：Ran 43 tests OK
```

启动后端：

```powershell
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

可访问：

```text
/security-dashboard
/attack-chain-runtime
/security/overview
/reports/gateway-benchmark
/reports/attack-chain
/reports/attack-chain-benchmark
/reports/comparison-benchmark
```

---

## 八、本阶段价值总结

本阶段将项目从：

```text
离线攻击链检测演示
```

升级为：

```text
运行时攻击链防护平台
```

主要提升包括：

```text
1. 攻击链检测正式接入真实接口调用流程。
2. 每次工具调用都可以在 Gateway 判断后继续进入会话级链式风险检测。
3. effective_decision 能综合单步风险和多步上下文风险。
4. 前端可以动态演示攻击链从形成到拒绝的完整过程。
5. 攻击链评测从单条 demo 扩展到 8 条批量样例。
6. 系统能力概览让项目完成度可以被结构化展示。
7. 对比实验提供了“无防护 vs 单步网关 vs 完整系统”的量化论证。
8. CI 覆盖更多实验脚本，使结果更可复现。
```

一句话总结：

> Task18 的核心改进，是将多步攻击链检测从离线演示能力升级为运行时防护能力，并通过系统总览、批量评测和对比实验，把项目进一步提升为可展示、可复现、可论证的 AI Agent 工具调用安全平台。
