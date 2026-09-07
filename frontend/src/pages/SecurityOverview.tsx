import { useState } from 'react';
import { DecisionDonut } from '../components/DecisionDonut';
import { SecurityPipeline } from '../components/SecurityPipeline';
import type { LiveConnectionState, LiveRuntimeSnapshot } from '../types/domain';

const DEMO_CLEAR_KEY = 'agentguard:security-overview-cleared-at';

function formatPercent(value: number) {
  return `${value.toFixed(1)}%`;
}

function serviceText(status?: string) {
  if (status === 'online') return '在线';
  if (status === 'offline') return '离线';
  return '未知';
}

function relativeTime(value?: string) {
  if (!value) return '暂无记录';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return date.toLocaleString();
}

function runtimeTimestamp(value?: string) {
  if (!value) return 0;
  const normalized = value.includes('T') ? value : value.replace(' ', 'T');
  const timestamp = new Date(normalized).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

export function SecurityOverview({
  snapshot,
  connectionState,
  onNavigate
}: {
  snapshot: LiveRuntimeSnapshot | null;
  connectionState: LiveConnectionState;
  onNavigate: (page: 'workbench' | 'evidence' | 'test') => void;
}) {
  const [demoClearedAt, setDemoClearedAt] = useState(() => {
    const saved = window.localStorage.getItem(DEMO_CLEAR_KEY);
    const parsed = Number(saved || 0);
    return Number.isFinite(parsed) ? parsed : 0;
  });

  const overview = snapshot?.overview;
  const requests = (snapshot?.requests ?? []).filter(
    (item) => runtimeTimestamp(item.createdAt) > demoClearedAt
  );
  const audits = (snapshot?.auditLogs ?? []).filter(
    (item) => runtimeTimestamp(item.timestamp) > demoClearedAt
  );
  const latest = requests[0];
  const denied = requests.filter((item) => item.decision === 'deny').length;
  const confirmed = requests.filter((item) => item.decision === 'confirm').length;
  const highRisk = requests.filter((item) => item.risk === 'high' || item.risk === 'critical').length;
  const controlled = requests.length ? ((denied + confirmed) / requests.length) * 100 : 0;
  const mode = snapshot?.systemStatus.agentguard_mode || 'unknown';

  const visibleSnapshot: LiveRuntimeSnapshot | null = snapshot
    ? {
        ...snapshot,
        requests,
        auditLogs: audits,
        overview: snapshot.overview
          ? {
              ...snapshot.overview,
              totalRequests: requests.length,
              blockedRequests: denied,
              confirmRequests: confirmed,
              localAuditLogs: audits.length
            }
          : snapshot.overview
      }
    : null;

  function clearDemoRecords() {
    const clearedAt = Date.now();
    window.localStorage.setItem(DEMO_CLEAR_KEY, String(clearedAt));
    setDemoClearedAt(clearedAt);
  }

  return (
    <div className="overview-page">
      <section className="overview-hero">
        <div className="overview-hero-copy">
          <div className="overview-hero-heading">
            <span className="overview-hero-eyebrow">AgentGuard Security Operations</span>
            <div className="overview-hero-page-line">
              <h2>安全总览</h2>
              <span>实时状态与安全链路</span>
            </div>
          </div>

          <div className="overview-kicker-row">
            <span className={`mode-badge mode-${mode}`}>{mode.toUpperCase()} MODE</span>
            <span className={`connection-caption connection-${connectionState}`}>
              {connectionState === 'live' ? '数据每 2 秒自动更新' : '正在恢复实时连接'}
            </span>
          </div>
          <h1>Agent 工具调用安全控制台</h1>
          <p>
            将 OAuth 身份、任务边界、Capability Token、运行时监控、隔离沙箱与审计证据整合为一条可观测安全链路。
          </p>
        </div>
        <div className="overview-health-panel">
          <div className="overview-health-title">
            <div>
              <span>System Health</span>
              <strong>核心服务状态</strong>
            </div>
            <small>{snapshot ? `${snapshot.fetchLatencyMs} ms` : '--'}</small>
          </div>
          {(['oauth', 'backend', 'mcp'] as const).map((key) => {
            const item = snapshot?.services[key];
            return (
              <div className="service-health-row" key={key}>
                <span className={`service-health-dot service-${item?.status ?? 'unknown'}`} />
                <div>
                  <strong>{key === 'oauth' ? 'OAuth Server' : key === 'mcp' ? 'MCP Gateway' : 'FastAPI Backend'}</strong>
                  <small>{item?.detail || '等待首轮状态同步'}</small>
                </div>
                <b>{serviceText(item?.status)}</b>
              </div>
            );
          })}
        </div>
      </section>

      <section className="overview-metrics">
        <article>
          <span>可信运行记录</span>
          <strong>{requests.length}</strong>
          <small>审计与沙箱证据聚合</small>
        </article>
        <article>
          <span>风险控制率</span>
          <strong>{formatPercent(controlled)}</strong>
          <small>deny + confirm / 最新记录</small>
        </article>
        <article>
          <span>高风险请求</span>
          <strong>{highRisk}</strong>
          <small>high / critical</small>
        </article>
        <article>
          <span>安全评分</span>
          <strong>{overview?.securityScore ?? 0}<small>/100</small></strong>
          <small>基于最新测试摘要</small>
        </article>
        <article>
          <span>平均授权延迟</span>
          <strong>{overview?.averageLatencyMs ?? 0}<small>ms</small></strong>
          <small>最新 Gateway 测试</small>
        </article>
        <article>
          <span>最近安全事件</span>
          <strong className="metric-text">{latest ? latest.decision.toUpperCase() : 'WAITING'}</strong>
          <small>{relativeTime(latest?.createdAt)}</small>
        </article>
      </section>

      <section className="overview-section pipeline-section">
        <div className="overview-section-head">
          <div>
            <span className="eyebrow">Live Security Path</span>
            <h2>当前安全链路</h2>
            <p>每次轮询会根据最新工具调用、决策和审计记录同步节点状态。</p>
          </div>
          <button className="secondary-btn small" onClick={() => onNavigate('workbench')}>发起新调用</button>
        </div>
        <SecurityPipeline snapshot={visibleSnapshot} />
      </section>

      <section className="overview-insight-grid">
        <article className="overview-section decision-panel">
          <div className="overview-section-head compact-head">
            <div>
              <span className="eyebrow">Decision Analytics</span>
              <h2>决策分布</h2>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <small>{requests.length} 条实时记录</small>
              <button
                className="link-button"
                type="button"
                onClick={clearDemoRecords}
                disabled={!requests.length && !audits.length}
                title="仅清空当前演示视图，底层审计证据仍然保留"
                style={{ fontSize: 11, padding: '3px 7px', minHeight: 0 }}
              >
                清空
              </button>
            </div>
          </div>
          <DecisionDonut requests={requests} />
        </article>

        <article className="overview-section live-events-panel">
          <div className="overview-section-head compact-head">
            <div>
              <span className="eyebrow">Live Events</span>
              <h2>最新审计事件</h2>
            </div>
            <button className="link-button" onClick={() => onNavigate('evidence')}>查看全部</button>
          </div>
          <div className="live-event-list">
            {audits.slice(0, 6).map((item) => (
              <div className="live-event-item" key={item.id}>
                <span className={`event-result event-${item.result}`} />
                <div>
                  <strong>{item.action}</strong>
                  <p>{item.detail}</p>
                  <small>{item.actor} · {relativeTime(item.timestamp)}</small>
                </div>
              </div>
            ))}
            {!audits.length && <div className="empty-live-state">运行一次授权演示后，这里会自动出现审计事件。</div>}
          </div>
        </article>
      </section>

      <section className="overview-section latest-request-panel">
        <div className="overview-section-head compact-head">
          <div>
            <span className="eyebrow">Latest Request</span>
            <h2>最新工具调用摘要</h2>
          </div>
          <button className="link-button" onClick={() => onNavigate('test')}>查看评测</button>
        </div>
        {latest ? (
          <div className="latest-request-grid">
            <div><span>Agent / 用户</span><strong>{latest.agent}</strong><small>{latest.user}</small></div>
            <div><span>工具 / 目标</span><strong>{latest.tool}</strong><small>{latest.target}</small></div>
            <div><span>风险 / 决策</span><strong>{latest.risk.toUpperCase()}</strong><small>{latest.decision.toUpperCase()}</small></div>
            <div className="latest-request-reason"><span>安全解释</span><strong>{latest.reason}</strong><small>{latest.policy}</small></div>
          </div>
        ) : (
          <div className="empty-live-state">暂无真实运行记录。进入“实时演示”发起一次工具调用。</div>
        )}
      </section>
    </div>
  );
}
