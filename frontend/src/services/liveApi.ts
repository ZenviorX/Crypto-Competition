import type {
  AuditLog,
  EvaluationMetric,
  GatewayRequest,
  LiveRuntimeSnapshot,
  McpRuntimeStatus,
  Overview,
  ServiceHealth,
  SystemRuntimeStatus,
  TestResultSummary
} from '../types/domain';

const API_BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '');
const REQUEST_TIMEOUT_MS = 12_000;

function buildUrl(endpoint: string) {
  if (!API_BASE) return endpoint;
  return `${API_BASE}${endpoint}`;
}

async function strictGet<T>(endpoint: string, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });

  try {
    const response = await fetch(buildUrl(endpoint), {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: controller.signal
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${endpoint} 返回 HTTP ${response.status}${text ? `：${text}` : ''}`);
    }

    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}

function settledValue<T>(result: PromiseSettledResult<T>, fallback: T): T {
  return result.status === 'fulfilled' ? result.value : fallback;
}

function service(status: ServiceHealth['status'], detail: string, latencyMs?: number): ServiceHealth {
  return { status, detail, latencyMs };
}

async function probeOAuth(url: string, signal?: AbortSignal): Promise<ServiceHealth> {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 3_000);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });

  try {
    await fetch(`${url.replace(/\/$/, '')}/health`, {
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal
    });
    return service('online', 'OAuth Demo Server 可访问', Math.round(performance.now() - started));
  } catch {
    return service('offline', 'OAuth Demo Server 未响应');
  } finally {
    window.clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}

export async function fetchLiveRuntimeSnapshot(signal?: AbortSignal): Promise<LiveRuntimeSnapshot> {
  const started = performance.now();
  const systemStatus = await strictGet<SystemRuntimeStatus>('/api/status', signal);

  const [
    mcpResult,
    overviewResult,
    requestsResult,
    auditResult,
    evaluationResult,
    testResult
  ] = await Promise.allSettled([
    strictGet<McpRuntimeStatus>('/mcp/status', signal),
    strictGet<Overview>('/api/overview', signal),
    strictGet<GatewayRequest[]>('/api/requests?limit=60', signal),
    strictGet<AuditLog[]>('/api/audit-logs?limit=60', signal),
    strictGet<EvaluationMetric[]>('/api/evaluations', signal),
    strictGet<TestResultSummary>('/test-results/latest/summary', signal)
  ]);

  const oauthUrl = systemStatus.mcp?.demo_authorization_server || 'http://127.0.0.1:9000';
  const oauth = await probeOAuth(oauthUrl, signal);
  const errors: string[] = [];

  for (const [name, result] of [
    ['MCP 状态', mcpResult],
    ['运行总览', overviewResult],
    ['请求记录', requestsResult],
    ['审计日志', auditResult],
    ['评估指标', evaluationResult],
    ['测试摘要', testResult]
  ] as const) {
    if (result.status === 'rejected') {
      errors.push(`${name}：${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
    }
  }

  const mcpStatus = settledValue<McpRuntimeStatus | null>(mcpResult, null);

  return {
    generatedAt: new Date().toISOString(),
    sequence: Date.now(),
    fetchLatencyMs: Math.round(performance.now() - started),
    systemStatus,
    mcpStatus,
    services: {
      backend: service('online', `FastAPI ${systemStatus.version || ''}`.trim()),
      mcp: mcpStatus
        ? service('online', `MCP ${mcpStatus.protocol_target || 'online'}`)
        : service('offline', 'MCP 状态接口未响应'),
      oauth
    },
    overview: settledValue<Overview | null>(overviewResult, null),
    requests: settledValue<GatewayRequest[]>(requestsResult, []),
    auditLogs: settledValue<AuditLog[]>(auditResult, []),
    evaluations: settledValue<EvaluationMetric[]>(evaluationResult, []),
    testSummary: settledValue<TestResultSummary | null>(testResult, null),
    errors
  };
}
