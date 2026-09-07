import { useEffect, useState } from 'react';
import { useLiveRuntime } from './hooks/useLiveRuntime';
import { AuthenticationPage } from './pages/AuthenticationPage';
import { Dashboard } from './pages/Dashboard';
import { EvaluationPage } from './pages/EvaluationPage';
import { GatewayWorkbench } from './pages/GatewayWorkbench';
import { ResearchComparisonPage } from './pages/ResearchComparisonPage';
import { SecurityOverview } from './pages/SecurityOverview';
import { api } from './services/api';
import type { StrategyComparisonResponse } from './types/domain';
import './styles/global.css';
import './styles/layout.css';
import './styles/realtime-console.css';
import './styles/overview-hero-header.css';
import './styles/sidebar-authentication.css';
import './styles/page-status-banner.css';

type PageKey = 'auth' | 'overview' | 'workbench' | 'evidence' | 'test' | 'research';
type StatusTone = 'blue' | 'purple' | 'green' | 'yellow' | 'red' | 'gray';

type PageStatusItem = {
  label: string;
  value: string;
  tone: StatusTone;
};

type PageStatusConfig = {
  eyebrow: string;
  title: string;
  description: string;
  items: PageStatusItem[];
};

const navItems: Array<{
  key: PageKey;
  label: string;
  subtitle: string;
}> = [
  { key: 'auth', label: 'MCP / OAuth 认证', subtitle: '认证服务与协议状态' },
  { key: 'overview', label: '安全总览', subtitle: '实时状态与安全链路' },
  { key: 'workbench', label: '实时演示', subtitle: '发起任务并观察决策' },
  { key: 'evidence', label: '审计证据', subtitle: '运行记录与事件时间线' },
  { key: 'test', label: '评测对比', subtitle: '测试指标与策略图表' },
  { key: 'research', label: '研究说明', subtitle: '方法定位与实验逻辑' }
];

function serviceLabel(status?: string) {
  if (status === 'online') return '在线';
  if (status === 'offline') return '离线';
  return '等待状态';
}

function serviceTone(status?: string): StatusTone {
  if (status === 'online') return 'green';
  if (status === 'offline') return 'red';
  return 'yellow';
}

function decisionTone(decision?: string): StatusTone {
  if (decision === 'allow') return 'green';
  if (decision === 'confirm' || decision === 'review') return 'yellow';
  if (decision === 'deny') return 'red';
  return 'gray';
}

function formatAccuracy(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '等待结果';
  return `${(value * 100).toFixed(2)}%`;
}

function formatEventTime(value?: string) {
  if (!value) return '暂无事件';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function App() {
  const [page, setPage] = useState<PageKey>('auth');
  const [strategyComparison, setStrategyComparison] = useState<StrategyComparisonResponse | null>(null);
  const [testRunning, setTestRunning] = useState(false);
  const [testRunMessage, setTestRunMessage] = useState<string | null>(null);
  const { snapshot, connectionState, error, refresh } = useLiveRuntime();

  useEffect(() => {
    let active = true;
    api.getStrategyComparison().then((result) => {
      if (active) setStrategyComparison(result);
    });
    return () => { active = false; };
  }, []);

  async function handleRunIndependentTests() {
    setTestRunning(true);
    setTestRunMessage('正在运行独立 Gateway 测试，请稍候…');
    try {
      const result = await api.runIndependentTests();
      setTestRunMessage(
        result.success
          ? `测试完成：${result.summary.passed_cases}/${result.summary.total_cases} 通过。`
          : `测试执行失败：退出码 ${result.returncode}。`
      );
      window.dispatchEvent(new Event('agentguard:runtime-changed'));
      await refresh();
    } catch (reason) {
      setTestRunMessage(reason instanceof Error ? reason.message : '测试执行失败。');
    } finally {
      setTestRunning(false);
    }
  }

  const latestRequest = snapshot?.requests[0];
  const latestAudit = snapshot?.auditLogs[0];
  const testSummary = snapshot?.testSummary;
  const registeredFeatures = snapshot?.systemStatus.registered_core_features ?? [];
  const sandboxRegistered = registeredFeatures.some((item) => item.toLowerCase().includes('sandbox'));

  const pageStatus: PageStatusConfig = (() => {
    switch (page) {
      case 'auth':
        return {
          eyebrow: 'Authentication Status',
          title: '认证链路状态',
          description: 'OAuth Authorization Server、MCP Protected Resource 与 AgentGuard Backend。',
          items: [
            {
              label: 'OAuth Server',
              value: serviceLabel(snapshot?.services.oauth.status),
              tone: serviceTone(snapshot?.services.oauth.status)
            },
            {
              label: 'MCP Gateway',
              value: serviceLabel(snapshot?.services.mcp.status),
              tone: serviceTone(snapshot?.services.mcp.status)
            },
            {
              label: 'Backend',
              value: serviceLabel(snapshot?.services.backend.status),
              tone: serviceTone(snapshot?.services.backend.status)
            }
          ]
        };
      case 'overview':
        return {
          eyebrow: 'Overview Status',
          title: '全局运行摘要',
          description: '当前运行模式、最近决策和审计记录。',
          items: [
            {
              label: '运行模式',
              value: snapshot?.systemStatus.agentguard_mode?.toUpperCase() ?? '等待状态',
              tone: 'blue'
            },
            {
              label: '最新决策',
              value: latestRequest?.decision.toUpperCase() ?? 'WAITING',
              tone: decisionTone(latestRequest?.decision)
            },
            {
              label: '审计记录',
              value: `${snapshot?.auditLogs.length ?? 0} 条`,
              tone: snapshot?.auditLogs.length ? 'green' : 'gray'
            }
          ]
        };
      case 'workbench':
        return {
          eyebrow: 'Workbench Status',
          title: '演示执行环境',
          description: 'Gateway、运行模式和沙箱能力。',
          items: [
            {
              label: 'Gateway',
              value: serviceLabel(snapshot?.services.backend.status),
              tone: serviceTone(snapshot?.services.backend.status)
            },
            {
              label: '授权模式',
              value: snapshot?.systemStatus.agentguard_mode?.toUpperCase() ?? '等待状态',
              tone: 'blue'
            },
            {
              label: '沙箱能力',
              value: sandboxRegistered ? '已注册' : '等待状态',
              tone: sandboxRegistered ? 'purple' : 'yellow'
            }
          ]
        };
      case 'evidence':
        return {
          eyebrow: 'Evidence Status',
          title: '审计与证据摘要',
          description: '运行记录、最新事件和沙箱证据。',
          items: [
            {
              label: '运行记录',
              value: `${snapshot?.overview?.totalRequests ?? snapshot?.requests.length ?? 0} 条`,
              tone: 'blue'
            },
            {
              label: '最新事件',
              value: formatEventTime(latestAudit?.timestamp),
              tone: latestAudit ? 'purple' : 'gray'
            },
            {
              label: '沙箱证据',
              value: `${snapshot?.overview?.localEvidenceRuns ?? 0} 份`,
              tone: (snapshot?.overview?.localEvidenceRuns ?? 0) > 0 ? 'green' : 'gray'
            }
          ]
        };
      case 'test':
        return {
          eyebrow: 'Evaluation Status',
          title: '测试运行摘要',
          description: '最新准确率、样例规模和测试执行状态。',
          items: [
            {
              label: '准确率',
              value: formatAccuracy(testSummary?.accuracy),
              tone: testSummary?.available ? 'blue' : 'gray'
            },
            {
              label: '测试样例',
              value: `${testSummary?.total_cases ?? 0} 条`,
              tone: 'purple'
            },
            {
              label: '测试状态',
              value: testRunning ? '运行中' : testSummary?.available ? '已生成' : '等待运行',
              tone: testRunning ? 'yellow' : testSummary?.available ? 'green' : 'gray'
            }
          ]
        };
      case 'research':
        return {
          eyebrow: 'Research Status',
          title: '策略对比摘要',
          description: '对比策略数量、样例规模和结果状态。',
          items: [
            {
              label: '对比策略',
              value: `${Object.keys(strategyComparison?.summary ?? {}).length} 种`,
              tone: 'blue'
            },
            {
              label: '对比样例',
              value: `${strategyComparison?.total_cases ?? 0} 条`,
              tone: 'purple'
            },
            {
              label: '结果状态',
              value: strategyComparison?.available ? '可用' : '等待生成',
              tone: strategyComparison?.available ? 'green' : 'gray'
            }
          ]
        };
    }
  })();

  const content: Record<PageKey, JSX.Element> = {
    auth: (
      <AuthenticationPage
        snapshot={snapshot}
        connectionState={connectionState}
      />
    ),
    overview: (
      <SecurityOverview
        snapshot={snapshot}
        connectionState={connectionState}
        onNavigate={(target) => setPage(target)}
      />
    ),
    workbench: <GatewayWorkbench />,
    evidence: (
      <Dashboard
        overview={snapshot?.overview ?? null}
        requests={snapshot?.requests ?? []}
        auditLogs={snapshot?.auditLogs ?? []}
        connectionState={connectionState}
        lastUpdated={snapshot?.generatedAt ?? null}
      />
    ),
    test: (
      <EvaluationPage
        metrics={snapshot?.evaluations ?? []}
        strategyComparison={strategyComparison}
        testSummary={testSummary ?? null}
        testRunning={testRunning}
        testRunMessage={testRunMessage}
        onRunTests={() => void handleRunIndependentTests()}
        onRefreshTestSummary={() => void refresh()}
      />
    ),
    research: <ResearchComparisonPage />
  };

  return (
    <div className="app-shell clean-shell realtime-shell">
      <aside className="sidebar clean-sidebar realtime-sidebar">
        <div className="brand clean-brand realtime-brand">
          <strong>AgentGuard</strong>
          <span>MCP Agent Security Console</span>
        </div>

        <nav className="nav-list clean-nav realtime-nav" aria-label="AgentGuard frontend navigation">
          {navItems.map((item) => (
            <button
              key={item.key}
              className={page === item.key ? 'active' : ''}
              onClick={() => setPage(item.key)}
            >
              <span className="nav-copy">
                <strong>{item.label}</strong>
                <small>{item.subtitle}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />

        <section
          className={`sidebar-security-status status-${connectionState}`}
          aria-label="系统状态与安全主线"
        >
          <div className="sidebar-status-row">
            <div className="sidebar-status-name">
              <span className="sidebar-status-dot" />
              <span>系统状态</span>
            </div>
            <strong className="sidebar-status-value">{connectionState.toUpperCase()}</strong>
          </div>
          <small className="sidebar-status-detail">
            {snapshot?.systemStatus.execution_entrypoint ?? '等待后端状态'}
          </small>

          <div className="sidebar-status-divider" />

          <span className="sidebar-security-label">安全主线</span>
          <div className="sidebar-security-flow">
            OAuth → MCP → Task Boundary → Token → Sandbox → Evidence
          </div>
          <p className="sidebar-security-note">
            页面每 2 秒读取本机后端状态；窗口重新聚焦时立即刷新。
          </p>
        </section>
      </aside>

      <main className="main-panel clean-main realtime-main">
        <section className="page-status-banner" aria-label={`${pageStatus.title}状态`}>
          <div className="page-status-copy">
            <span className="eyebrow">{pageStatus.eyebrow}</span>
            <h2>{pageStatus.title}</h2>
            <p>{pageStatus.description}</p>
          </div>

          <div className="page-status-actions">
            <button className="page-status-refresh" onClick={() => void refresh()}>立即刷新</button>
            {pageStatus.items.map((item) => (
              <div className={`page-status-pill tone-${item.tone}`} key={item.label}>
                <span className="page-status-pill-dot" />
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </section>

        {error && connectionState !== 'offline' && (
          <div className="runtime-warning">
            <strong>部分数据源暂不可用</strong>
            <span>{error.split('\n')[0]}</span>
          </div>
        )}

        {connectionState === 'offline' && !snapshot ? (
          <div className="offline-screen">
            <div className="offline-icon">!</div>
            <h2>无法连接 AgentGuard 后端</h2>
            <p>请确认 FastAPI 已运行在 127.0.0.1:8000。页面会继续自动重试，也可以点击“立即刷新”。</p>
            <button className="primary-btn" onClick={() => void refresh()}>重新连接</button>
          </div>
        ) : content[page]}
      </main>
    </div>
  );
}
