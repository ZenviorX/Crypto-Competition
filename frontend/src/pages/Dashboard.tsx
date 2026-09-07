import { Badge } from '../components/Badge';
import { MetricCard } from '../components/MetricCard';
import { RequestTable } from '../components/RequestTable';
import { Section } from '../components/Section';
import type { AuditLog, GatewayRequest, LiveConnectionState, Overview } from '../types/domain';
import { compactNumber, decisionText } from '../utils/format';

interface DashboardProps {
  overview: Overview | null;
  requests: GatewayRequest[];
  auditLogs: AuditLog[];
  connectionState: LiveConnectionState;
  lastUpdated: string | null;
}

function formatTimestamp(value: string | null) {
  if (!value) return '等待首轮数据';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function Dashboard({
  overview,
  requests,
  auditLogs,
  connectionState,
  lastUpdated
}: DashboardProps) {
  const pending = requests.filter((item) => item.status === 'pending');
  const blocked = requests.filter((item) => item.decision === 'deny');
  const evidenceRuns = overview?.localEvidenceRuns ?? requests.filter((item) => item.intent.includes('sandbox')).length;

  return (
    <div className="page-grid evidence-page">
      <section className="evidence-hero">
        <div>
          <div className="evidence-live-line">
            <span className={`live-mini-dot live-mini-${connectionState}`} />
            <strong>{connectionState === 'live' ? '实时同步中' : '连接降级'}</strong>
            <small>最后更新：{formatTimestamp(lastUpdated)}</small>
          </div>
          <h1>运行证据与审计时间线</h1>
          <p>
            汇总授权裁定、隔离执行与审计事件，形成从请求到结果的可追溯证据链。
          </p>
        </div>
        <div className="evidence-trust-card">
          <span>Evidence Chain</span>
          <strong>授权 → 执行 → 留证</strong>
          <small>Authorization · Sandbox · Audit</small>
        </div>
      </section>

      <div className="metric-grid evidence-metrics">
        <MetricCard title="运行记录" value={compactNumber(overview?.totalRequests ?? 0)} hint="授权与执行过程记录" icon="dashboard" />
        <MetricCard title="阻断请求" value={compactNumber(overview?.blockedRequests ?? blocked.length)} hint="高风险请求被安全拒绝" icon="shield" />
        <MetricCard title="待确认请求" value={compactNumber(overview?.confirmRequests ?? pending.length)} hint="副作用操作进入人工确认" icon="spark" />
        <MetricCard title="沙箱证据" value={compactNumber(evidenceRuns)} hint="隔离执行产生的证据记录" icon="check" />
      </div>

      <Section
        eyebrow="Authorization Records"
        title="最近授权与执行记录"
        description="按时间展示工具调用、风险等级、授权裁定与执行状态。"
        actions={<Badge tone={pending.length ? 'yellow' : 'green'}>{pending.length} 个待确认</Badge>}
      >
        <RequestTable
          rows={requests.slice(0, 12)}
          evidenceLayout
        />
      </Section>

      <section className="evidence-grid">
        <Section
          eyebrow="Audit Timeline"
          title="最新审计事件"
          description="授权、阻断与执行结果按时间形成完整审计时间线。"
        >
          <div className="timeline realtime-timeline">
            {auditLogs.slice(0, 12).map((log) => (
              <article className="timeline-item" key={log.id}>
                <span className={`timeline-dot timeline-dot-${log.result}`} />
                <div>
                  <div className="timeline-title">
                    <strong>{log.action}</strong>
                    <Badge>{decisionText[log.result]}</Badge>
                  </div>
                  <p>{log.detail}</p>
                  <small>{log.timestamp} · {log.actor} · {log.resource}</small>
                </div>
              </article>
            ))}
            {!auditLogs.length && (
              <div className="empty-live-state">暂无审计记录。运行一次授权演示后将自动刷新。</div>
            )}
          </div>
        </Section>

        <Section
          eyebrow="Evidence Integrity"
          title="证据链说明"
          description="将授权、能力令牌、隔离执行和证据包串联为可验证链路。"
        >
          <div className="evidence-integrity-list">
            <div><span>01</span><div><strong>授权决策</strong><small>记录用户、工具、参数、风险分和策略解释</small></div></div>
            <div><span>02</span><div><strong>Capability Token</strong><small>执行前原子 claim，阻止并发重放</small></div></div>
            <div><span>03</span><div><strong>隔离执行</strong><small>Native Subprocess 或 Docker Sandbox</small></div></div>
            <div><span>04</span><div><strong>Evidence Bundle</strong><small>运行结果、哈希和审计事件可验证关联</small></div></div>
          </div>
          <div className="evidence-summary-strip">
            <div><span>安全评分</span><strong>{overview?.securityScore ?? 0}/100</strong></div>
            <div><span>平均延迟</span><strong>{overview?.averageLatencyMs ?? 0} ms</strong></div>
            <div><span>策略命中</span><strong>{overview?.policyHitRate ?? 0}%</strong></div>
          </div>
        </Section>
      </section>
    </div>
  );
}
