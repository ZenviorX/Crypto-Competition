# Task17：可解释风险评估、可复现安全评测与审计防篡改体系建设

## 一、任务背景

在前面多个 Task 中，项目已经完成了基础授权网关、PlanGuard 计划校验、任务授权合约、Capability Contract、运行时监控和前端演示页面。此时系统已经能够对单次工具调用进行 `allow / confirm / deny` 判断，但仍然存在三个关键不足：

```text
1. 网关能给出决策，但解释性不够强，评委或用户难以直接理解“为什么拒绝/确认”。
2. 系统有功能演示，但缺少可复现的批量安全评测结果支撑。
3. 审计日志虽然能记录行为，但缺少防篡改能力，事后追责可信度不足。
4. 多步攻击链风险已有概念，但还需要形成独立检测模块、演示脚本和实验报告。
```

因此，本阶段的核心目标是把项目从“能做安全判断的原型”进一步升级为：

```text
可解释
可审计
可复现评测
可生成实验报告
可演示多步攻击链风险
```

---

## 二、本阶段核心目标

本阶段主要完成以下目标：

```text
1. 为 Gateway 增加 risk_level 与 explanations，使风险判断可解释。
2. 构建网关安全样例库，形成可复现批量评测。
3. 自动生成 CSV 与 Markdown 实验报告，增强项目展示和答辩支撑。
4. 为审计日志增加哈希链，使日志具备篡改检测能力。
5. 新增独立多步攻击链检测模块，识别跨工具链式风险。
6. 增加报告访问接口，使实验结果可通过浏览器查看。
7. 更新 README 和 CI，使项目更像完整竞赛作品。
```

---

## 三、本阶段主要新增能力

### 3.1 可解释风险评估

改造前，Gateway 主要返回：

```text
decision
risk_score
reason
```

改造后新增：

```text
risk_level
explanations
```

其中：

```text
risk_level：将风险分映射为 low / medium / high / critical
explanations：将原始 reason 归类为结构化风险来源
```

示例：

```json
{
  "decision": "deny",
  "risk_score": 120,
  "risk_level": "critical",
  "reason": [
    "访问路径命中资源风险规则：secret/，风险分 +80",
    "命中 student 角色 deny 策略"
  ],
  "explanations": [
    {
      "factor": "resource_path",
      "reason": "访问路径命中资源风险规则：secret/，风险分 +80"
    },
    {
      "factor": "role_policy",
      "reason": "命中 student 角色 deny 策略"
    }
  ]
}
```

这样系统不只是给出“能不能执行”，还能说明风险来自哪里。

---

### 3.2 网关安全样例库与批量评测

新增安全样例库：

```text
security_cases/gateway_cases.json
```

样例数量扩展至 30 条，覆盖：

```text
正常公开文件读取
课程文件读取
普通文件写入
教师课程文件写入
管理员低风险命令
SELECT 数据库查询
敏感文件读取
private 文件访问
Unix 路径穿越
Windows 路径穿越
Windows 绝对路径
Linux 绝对路径
.env 文件读取
中文提示注入
英文提示注入
绕过授权指令
rm -rf 高危命令
shutdown 命令
curl 数据外传
未知工具调用
外部邮箱敏感内容发送
邮件收件人缺失
secret 内容外发
数据库 DELETE
数据库 DROP TABLE
数据库 UPDATE password
删除公开文件
删除 secret 文件
低置信度 Agent 计划
中等置信度 Agent 计划
```

新增批量评测脚本：

```text
experiments/run_gateway_benchmark.py
```

运行后自动生成：

```text
experiments/gateway_benchmark_results.csv
experiments/gateway_benchmark_report.md
```

评测指标包括：

```text
Overall accuracy
Normal task pass consistency
Attack blocking consistency
```

示例结果：

```text
Total cases: 30
Passed cases: 30
Overall accuracy: 100.00%
Normal task pass consistency: 100.00%
Attack blocking consistency: 100.00%
Failed cases: None
```

---

### 3.3 审计日志哈希链防篡改

改造前，系统可以写入审计日志，但无法判断历史日志是否被修改。  
本阶段为每条日志增加：

```text
prev_hash
record_hash
```

其中：

```text
prev_hash：上一条日志的哈希
record_hash：当前日志内容计算出的哈希
```

多条日志形成链式结构：

```text
log_1.record_hash → log_2.prev_hash
log_2.record_hash → log_3.prev_hash
log_3.record_hash → log_4.prev_hash
```

如果日志被修改、删除、插入或重排，哈希链校验会失败。

新增接口：

```text
GET /audit/verify
```

返回示例：

```json
{
  "valid": true,
  "total_records": 10,
  "checked_records": 10,
  "broken_index": null,
  "reason": "审计日志哈希链校验通过。"
}
```

该能力使系统从“有日志”提升为“日志可验证”。

---

### 3.4 多步攻击链检测模块

新增模块：

```text
backend/attack_chain/
```

核心文件：

```text
backend/attack_chain/attack_chain_detector.py
```

该模块用于检测单次工具调用难以发现的链式攻击行为，例如：

```text
外部内容读取
    ↓
提示注入命中
    ↓
敏感资源访问
    ↓
外部发送或高危命令执行
```

支持识别的阶段包括：

```text
external_content_read
prompt_injection_detected
sensitive_resource_access
external_output
high_risk_command
indirect_prompt_injection_chain
prompt_to_sensitive_access_chain
data_exfiltration_chain
prompt_to_command_execution_chain
```

新增演示脚本：

```text
experiments/run_attack_chain_demo.py
```

运行后自动生成：

```text
experiments/attack_chain_demo_result.json
experiments/attack_chain_demo_report.md
```

示例输出：

```text
========== Attack Chain Demo ==========
Session ID: demo-attack-chain
Cumulative risk: ...
Final decision: deny
```

---

### 3.5 实验报告访问接口

新增报告接口：

```text
GET /reports/gateway-benchmark
GET /reports/attack-chain
```

对应报告：

```text
experiments/gateway_benchmark_report.md
experiments/attack_chain_demo_report.md
```

这样实验报告不再只能在本地文件中查看，而是可以通过浏览器直接访问，方便项目展示和答辩演示。

---

### 3.6 安全总览页

新增页面：

```text
frontend/security_dashboard.html
```

新增访问入口：

```text
/security-dashboard
```

页面集中展示：

```text
后端运行状态
审计哈希链校验状态
网关安全评测报告
多步攻击链报告
核心安全能力说明
```

同时在主页面右上角增加“安全总览”入口，使项目展示链路更清晰。

---

### 3.7 README 与 CI 更新

更新 README，补充：

```text
项目背景
系统定位
核心功能
系统架构
运行方式
主要接口
推荐演示流程
单元测试说明
安全评测说明
多步攻击链演示
创新点
后续规划
```

同时新增 GitHub Actions 自动测试流程，使项目每次推送后自动运行：

```text
单元测试
网关安全评测
攻击链演示
```

并上传实验报告作为 CI artifact。

---

## 四、修改文件总览

本阶段主要修改和新增文件如下：

```text
backend/gateway/gateway.py
backend/schemas.py
backend/routes/gateway_routes.py
backend/audit/audit_logger.py
backend/audit/__init__.py
backend/routes/audit_routes.py
backend/attack_chain/attack_chain_detector.py
backend/attack_chain/__init__.py
backend/routes/report_routes.py
backend/main.py

security_cases/gateway_cases.json

experiments/run_gateway_benchmark.py
experiments/gateway_benchmark_results.csv
experiments/gateway_benchmark_report.md
experiments/run_attack_chain_demo.py
experiments/attack_chain_demo_result.json
experiments/attack_chain_demo_report.md

frontend/security_dashboard.html
frontend/index.html

tests/test_gateway_explanation.py
tests/test_audit_hash_chain.py
tests/test_attack_chain_detector.py
tests/test_report_routes.py
tests/test_security_dashboard_page.py

.github/workflows/ci.yml
README.md
```

---

## 五、关键实现说明

### 5.1 Gateway 返回值统一构造

新增统一构造函数：

```python
def build_gateway_result(
    decision: str,
    risk_score: int,
    reason: list[str],
    user: str,
    role: str,
    tool: str,
    params: dict,
) -> dict:
    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "reason": reason,
        "explanations": build_explanations(reason),
        "user": user,
        "role": role,
        "normalized_tool": tool,
        "normalized_params": params,
    }
```

作用：

```text
保证正常返回、未知工具返回、低置信度返回、任务合约拒绝返回等路径字段一致。
```

---

### 5.2 风险解释结构化

新增：

```python
def build_explanations(reason: list[str]) -> list[dict]:
    ...
```

根据 reason 文本自动归类：

```text
resource_path
role_policy
external_output
prompt_injection
command
database
agent_plan
task_contract
tool
params
general
```

实现效果：

```text
后端返回结构更适合前端展示和审计分析。
```

---

### 5.3 审计哈希链校验

新增：

```python
def verify_audit_chain() -> Dict[str, Any]:
    ...
```

校验逻辑：

```text
1. 读取 audit.log 中所有 JSONL 日志
2. 跳过旧版本无哈希日志
3. 对带哈希字段的日志重新计算 record_hash
4. 检查当前日志 prev_hash 是否等于上一条日志 record_hash
5. 若不一致则返回 valid=False
```

---

### 5.4 攻击链风险累积

`AttackChainDetector` 使用会话级状态记录：

```text
external_content_seen
prompt_injection_seen
sensitive_access_seen
external_output_seen
high_risk_command_seen
cumulative_risk
final_decision
events
summary
```

当多个风险阶段连续出现时，系统进行链式风险升级。

例如：

```text
prompt_injection_seen + sensitive_access_seen
→ prompt_to_sensitive_access_chain

prompt_injection_seen + sensitive_access_seen + external_output_seen
→ data_exfiltration_chain
```

---

## 六、新增测试

本阶段新增测试覆盖：

```text
1. secret 文件访问是否返回 risk_level 和 explanations
2. public 文件读取是否保留解释字段
3. 未知工具是否返回结构化解释
4. 审计日志是否包含 prev_hash 和 record_hash
5. 审计哈希链是否能校验成功
6. 审计日志被篡改后是否能检测失败
7. 多步攻击链是否能识别提示注入到敏感访问
8. 完整数据外发链是否被拒绝
9. 攻击链演示报告接口是否可访问
10. 安全总览页是否可访问
```

---

## 七、验收命令

本阶段完成后可运行：

```powershell
python experiments\run_gateway_benchmark.py
python experiments\run_attack_chain_demo.py
python -m unittest discover -s tests
```

预期结果：

```text
Gateway Benchmark：30 / 30 通过
Attack Chain Demo：Final decision: deny
Unit tests：全部通过
```

---

## 八、本阶段价值总结

本阶段将项目从：

```text
能进行单次工具调用判断的安全网关
```

升级为：

```text
具备可解释决策、可复现评测、审计防篡改和多步攻击链演示能力的 Agent 安全防护原型
```

核心提升包括：

```text
1. 风险判断更加透明，便于人工确认和答辩展示。
2. 实验评测更加可复现，不再只依赖单次演示。
3. 审计日志具备防篡改能力，提高事后追责可信度。
4. 多步攻击链检测为后续运行时防护奠定基础。
5. 前端和 README 展示效果明显增强。
6. CI 自动化提升了工程可信度。
```

一句话总结：

> Task17 的核心改进，是为 Agent 工具调用安全网关补齐“可解释、可审计、可评测、可展示”的基础能力，使项目从功能原型迈向竞赛型安全系统。
