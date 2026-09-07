export type Decision = 'allow' | 'deny' | 'confirm' | 'review';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type RequestStatus = 'pending' | 'approved' | 'rejected' | 'blocked';
export type LiveConnectionState = 'connecting' | 'live' | 'degraded' | 'offline';
export type ServiceHealthState = 'online' | 'offline' | 'unknown';

export interface ServiceHealth {
  status: ServiceHealthState;
  detail: string;
  latencyMs?: number;
}

export interface SystemRuntimeStatus {
  message: string;
  version: string;
  agentguard_mode: 'demo' | 'competition' | string;
  competition_mode: boolean;
  execution_entrypoint: string;
  disabled_direct_route_prefixes?: string[];
  registered_core_features?: string[];
  architecture?: Record<string, string>;
  mcp?: {
    endpoint?: string;
    protected_resource_metadata?: string;
    protocol_target?: string;
    demo_authorization_server?: string;
  };
  note?: string;
}

export interface McpRuntimeStatus {
  status?: string;
  service?: string;
  protocol_target?: string;
  endpoint?: string;
  oauth_issuer?: string;
  protected_resource_metadata?: string;
  [key: string]: unknown;
}

export interface Overview {
  totalRequests: number;
  blockedRequests: number;
  confirmRequests: number;
  averageLatencyMs: number;
  policyHitRate: number;
  securityScore: number;
  activePolicies: number;
  agentsOnline: number;
  source?: string;
  localEvidenceRuns?: number;
  localAuditLogs?: number;
}

export interface GatewayRequest {
  id: string;
  agent: string;
  user: string;
  tool: string;
  target: string;
  intent: string;
  risk: RiskLevel;
  decision: Decision;
  status: RequestStatus;
  createdAt: string;
  reason: string;
  policy: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  scope: string;
  effect: Decision;
  priority: number;
  enabled: boolean;
  updatedAt: string;
  examples: string[];
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  result: Decision;
  detail: string;
}

export interface EvaluationMetric {
  name: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'flat';
  description: string;
}

export interface SystemSetting {
  key: string;
  name: string;
  value: string;
  description: string;
}

export interface StrategyComparisonItem {
  total_cases: number;
  attack_cases: number;
  normal_cases: number;
  attack_block_or_confirm: number;
  attack_allow: number;
  normal_not_denied: number;
  normal_denied: number;
  decision_match_cases: number;
  comparable_cases: number;
  attack_block_or_confirm_rate: number;
  attack_allow_rate: number;
  normal_not_denied_rate: number;
  normal_denied_rate: number;
  decision_match_rate: number;
}

export interface StrategyComparisonResponse {
  available: boolean;
  message?: string;
  hint?: string;
  total_cases: number;
  total_records: number;
  elapsed_ms: number;
  summary: Record<string, StrategyComparisonItem>;
  outputs: Record<string, string>;
}

export interface TestResultSummary {
  available?: boolean;
  schema?: string;
  generated_at?: string;
  case_glob?: string;
  gateway_import?: string;
  request_import?: string;
  total_cases: number;
  passed_cases: number;
  failed_cases: number;
  accuracy: number;
  elapsed_ms?: number;
  avg_latency_ms?: number;
  normal_cases?: number;
  risk_cases?: number;
  risk_block_or_confirm?: number;
  risk_allow?: number;
  risk_block_or_confirm_rate?: number;
  risk_unsafe_allow_rate?: number;
  normal_denied?: number;
  normal_false_deny_rate?: number;
  decision_distribution?: Record<string, number>;
  source_distribution?: Record<string, number>;
  category_distribution?: Record<string, number>;
  tool_distribution?: Record<string, number>;
  category_accuracy?: Record<string, {
    total: number;
    passed: number;
    accuracy: number;
  }>;
  validation_errors?: unknown[];
  outputs?: Record<string, string>;
  status?: string;
  message?: string;
  hint?: string;
}

export interface LiveRuntimeSnapshot {
  generatedAt: string;
  sequence: number;
  fetchLatencyMs: number;
  systemStatus: SystemRuntimeStatus;
  mcpStatus: McpRuntimeStatus | null;
  services: {
    backend: ServiceHealth;
    mcp: ServiceHealth;
    oauth: ServiceHealth;
  };
  overview: Overview | null;
  requests: GatewayRequest[];
  auditLogs: AuditLog[];
  evaluations: EvaluationMetric[];
  testSummary: TestResultSummary | null;
  errors: string[];
}

export interface TestCaseResultRow {
  case_id: string;
  source_file: string;
  category: string;
  tool: string;
  is_normal: boolean;
  expected: string;
  actual: string;
  matched: boolean;
  risk_score?: number | string;
  latency_ms?: number;
  reason?: string;
  error?: string;
}

export interface TestRunResponse {
  success: boolean;
  returncode: number;
  command?: string;
  stdout?: string;
  stderr?: string;
  summary: TestResultSummary;
}

export type AgentRunMode =
  | 'fake_check'
  | 'tool_proxy_oauth'
  | 'external_agent_adapter'
  | 'docker_sandbox_execute'
  | 'fake_plan'
  | 'fake_run'
  | 'llm_plan'
  | 'llm_run'
  | 'stepwise_llm';

export interface AgentCommandInput {
  user: string;
  userInput: string;
  mode: AgentRunMode;
  maxSteps: number;
  riskBudget: number;
}

export interface AgentCommandResponse {
  ok: boolean;
  fromMock?: boolean;
  endpoint?: string;
  error?: string;
  data: Record<string, unknown>;
}
