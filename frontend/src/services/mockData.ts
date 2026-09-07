import type { AuditLog, EvaluationMetric, GatewayRequest, Overview, PolicyRule, SystemSetting } from '../types/domain';

export const overview: Overview = {
  totalRequests: 1286,
  blockedRequests: 214,
  confirmRequests: 73,
  averageLatencyMs: 38,
  policyHitRate: 92.7,
  securityScore: 91,
  activePolicies: 18,
  agentsOnline: 6
};

export const requests: GatewayRequest[] = [
  {
    id: 'REQ-2401',
    agent: 'research-agent',
    user: 'student',
    tool: 'file.read',
    target: 'public/notice.txt',
    intent: '读取公开通知文件并总结',
    risk: 'low',
    decision: 'allow',
    status: 'approved',
    createdAt: '2026-06-16 21:42:10',
    reason: '角色权限允许，路径位于 public，工具无破坏性副作用。',
    policy: 'public-read-allow'
  },
  {
    id: 'REQ-2402',
    agent: 'shell-agent',
    user: 'guest',
    tool: 'shell.exec',
    target: 'rm -rf ./logs',
    intent: '清理日志目录',
    risk: 'critical',
    decision: 'deny',
    status: 'blocked',
    createdAt: '2026-06-16 21:43:52',
    reason: '命令具备破坏性副作用，且 guest 无执行 Shell 权限。',
    policy: 'dangerous-command-deny'
  },
  {
    id: 'REQ-2403',
    agent: 'finance-agent',
    user: 'teacher',
    tool: 'purchase.submit',
    target: 'order/food-materials',
    intent: '提交食材采购核算订单',
    risk: 'medium',
    decision: 'confirm',
    status: 'pending',
    createdAt: '2026-06-16 21:45:07',
    reason: '涉及订单提交与预算占用，需要人工确认。',
    policy: 'side-effect-confirm'
  },
  {
    id: 'REQ-2404',
    agent: 'crawler-agent',
    user: 'student',
    tool: 'http.request',
    target: 'internal/admin',
    intent: '访问内部管理接口',
    risk: 'high',
    decision: 'deny',
    status: 'blocked',
    createdAt: '2026-06-16 21:47:23',
    reason: '命中内网管理路径访问限制，用户角色不满足。',
    policy: 'internal-admin-deny'
  },
  {
    id: 'REQ-2405',
    agent: 'planner-agent',
    user: 'admin',
    tool: 'config.update',
    target: 'config/policy.yaml',
    intent: '更新策略优先级',
    risk: 'medium',
    decision: 'review',
    status: 'pending',
    createdAt: '2026-06-16 21:49:40',
    reason: '策略变更会影响全局判定，建议进入审计复核流程。',
    policy: 'policy-change-review'
  }
];

export const policies: PolicyRule[] = [
  {
    id: 'POL-001',
    name: '路径穿越硬拒绝',
    description: '阻止包含 ../、..\\ 或编码绕过形式的路径访问。',
    scope: 'file.*',
    effect: 'deny',
    priority: 100,
    enabled: true,
    updatedAt: '2026-06-15 19:20',
    examples: ['../../secret/password.txt', '..%2f..%2fconfig.yaml']
  },
  {
    id: 'POL-002',
    name: '破坏性操作确认',
    description: '删除、覆盖、转账、下单等有副作用工具默认进入人工确认。',
    scope: 'tool.side_effect',
    effect: 'confirm',
    priority: 80,
    enabled: true,
    updatedAt: '2026-06-15 19:32',
    examples: ['file.delete', 'purchase.submit', 'db.drop']
  },
  {
    id: 'POL-003',
    name: '公开目录读取放行',
    description: '允许低风险角色读取 public 目录下的非敏感文件。',
    scope: 'file.read',
    effect: 'allow',
    priority: 20,
    enabled: true,
    updatedAt: '2026-06-14 22:10',
    examples: ['public/notice.txt', 'public/report.md']
  },
  {
    id: 'POL-004',
    name: 'Shell 执行最小权限',
    description: '仅 admin 可执行白名单 Shell 命令，其余角色直接拒绝。',
    scope: 'shell.exec',
    effect: 'deny',
    priority: 95,
    enabled: true,
    updatedAt: '2026-06-14 18:48',
    examples: ['rm -rf', 'curl internal', 'powershell encodedCommand']
  }
];

export const auditLogs: AuditLog[] = [
  {
    id: 'AUD-9001',
    timestamp: '2026-06-16 21:51:02',
    actor: 'gateway-core',
    action: 'policy.evaluate',
    resource: 'REQ-2405',
    result: 'review',
    detail: '策略变更请求进入复核队列。'
  },
  {
    id: 'AUD-9002',
    timestamp: '2026-06-16 21:47:24',
    actor: 'crawler-agent',
    action: 'request.block',
    resource: 'internal/admin',
    result: 'deny',
    detail: '阻断内部管理接口访问。'
  },
  {
    id: 'AUD-9003',
    timestamp: '2026-06-16 21:43:53',
    actor: 'shell-agent',
    action: 'command.block',
    resource: 'rm -rf ./logs',
    result: 'deny',
    detail: '检测到高危删除命令。'
  },
  {
    id: 'AUD-9004',
    timestamp: '2026-06-16 21:42:11',
    actor: 'research-agent',
    action: 'file.read',
    resource: 'public/notice.txt',
    result: 'allow',
    detail: '公开文件读取成功。'
  }
];

export const evaluations: EvaluationMetric[] = [
  {
    name: '拦截准确率',
    value: 96.4,
    unit: '%',
    trend: 'up',
    description: '攻击样本、越权样本、路径穿越样本的综合阻断准确率。'
  },
  {
    name: '误拦率',
    value: 2.1,
    unit: '%',
    trend: 'down',
    description: '正常请求被错误拒绝或确认的比例。'
  },
  {
    name: '平均判定耗时',
    value: 38,
    unit: 'ms',
    trend: 'flat',
    description: '从请求进入网关到输出 allow/deny/confirm 的平均耗时。'
  },
  {
    name: '策略覆盖率',
    value: 91.8,
    unit: '%',
    trend: 'up',
    description: '测试集中可被明确策略解释的样本比例。'
  }
];

export const settings: SystemSetting[] = [
  {
    key: 'mode',
    name: '运行模式',
    value: '严格模式',
    description: '高风险工具默认拒绝，中风险工具默认确认。'
  },
  {
    key: 'audit_retention',
    name: '审计保留周期',
    value: '90 天',
    description: '审计日志会保留 90 天，便于实验报告复盘。'
  },
  {
    key: 'mock_fallback',
    name: 'Mock 兜底',
    value: '开启',
    description: '后端不可用时自动显示内置样例数据。'
  }
];
