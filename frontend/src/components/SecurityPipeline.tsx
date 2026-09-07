import type { AuditLog, GatewayRequest, LiveRuntimeSnapshot } from '../types/domain';

interface Stage {
  key: string;
  title: string;
  caption: string;
  state: 'idle' | 'active' | 'success' | 'warning' | 'danger';
}

function latestRequest(requests: GatewayRequest[]) {
  return requests[0] ?? null;
}

function decisionState(request: GatewayRequest | null): Stage['state'] {
  if (!request) return 'idle';
  if (request.decision === 'deny') return 'danger';
  if (request.decision === 'confirm') return 'warning';
  if (request.decision === 'allow') return 'success';
  return 'active';
}

export function SecurityPipeline({
  snapshot
}: {
  snapshot: LiveRuntimeSnapshot | null;
}) {
  const request = latestRequest(snapshot?.requests ?? []);
  const audits: AuditLog[] = snapshot?.auditLogs ?? [];
  const hasSandboxEvidence = Boolean(
    request && (
      request.intent.includes('sandbox')
      || request.policy.includes('sandbox')
      || request.status === 'approved'
    )
  );

  const stages: Stage[] = [
    {
      key: 'oauth',
      title: 'OAuth 身份',
      caption: snapshot?.services.oauth.status === 'online' ? 'Access Token 服务在线' : '等待 OAuth Server',
      state: snapshot?.services.oauth.status === 'online' ? 'success' : 'idle'
    },
    {
      key: 'mcp',
      title: 'MCP Gateway',
      caption: snapshot?.services.mcp.status === 'online' ? 'JSON-RPC 入口在线' : '等待 MCP Gateway',
      state: snapshot?.services.mcp.status === 'online' ? 'success' : 'idle'
    },
    {
      key: 'task',
      title: '任务边界',
      caption: request ? `${request.tool} · ${request.target}` : '等待工具调用',
      state: request ? 'active' : 'idle'
    },
    {
      key: 'decision',
      title: '授权决策',
      caption: request ? `${request.decision.toUpperCase()} · ${request.risk}` : '尚无决策',
      state: decisionState(request)
    },
    {
      key: 'sandbox',
      title: '隔离执行',
      caption: hasSandboxEvidence ? '已产生沙箱运行记录' : '未进入或等待执行',
      state: hasSandboxEvidence ? 'success' : request?.decision === 'deny' ? 'danger' : 'idle'
    },
    {
      key: 'evidence',
      title: '审计证据',
      caption: audits.length ? `${audits.length} 条最新审计事件` : '等待审计记录',
      state: audits.length ? 'success' : 'idle'
    }
  ];

  return (
    <div className="security-pipeline" aria-label="AgentGuard security pipeline">
      {stages.map((stage, index) => (
        <div className="pipeline-stage-wrap" key={stage.key}>
          <article className={`pipeline-stage pipeline-stage-${stage.state}`}>
            <span className="pipeline-stage-index">{String(index + 1).padStart(2, '0')}</span>
            <div>
              <strong>{stage.title}</strong>
              <small>{stage.caption}</small>
            </div>
          </article>
          {index < stages.length - 1 && <span className="pipeline-connector" aria-hidden="true">→</span>}
        </div>
      ))}
    </div>
  );
}
