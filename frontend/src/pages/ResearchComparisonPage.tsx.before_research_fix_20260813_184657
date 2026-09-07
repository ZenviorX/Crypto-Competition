import { useState } from 'react';
import { Badge } from '../components/Badge';
import { Section } from '../components/Section';

type ResearchCase = {
  id: string;
  scenario: string;
  is_risky: boolean;
  noguard: string;
  oauth_only: string;
  agentguard: string;
  research_value: string;
  summary: string;
};

type ResearchReport = {
  name: string;
  total_cases: number;
  risky_cases: number;
  metrics: {
    noguard_unsafe_allow_rate: number;
    oauth_only_unsafe_allow_rate: number;
    agentguard_unsafe_allow_rate: number;
  };
  cases: ResearchCase[];
};

function percent(value: number) {
  return `${(value * 100).toFixed(0)}%`;
}

export function ResearchComparisonPage() {
  const [report, setReport] = useState<ResearchReport | null>(null);
  const [loading, setLoading] = useState(false);

  async function runComparison() {
    setLoading(true);
    try {
      const res = await fetch('/research/strategy-comparison/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      setReport(data as ResearchReport);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-grid">
      <section className="workbench-hero">
        <div>
          <span className="eyebrow">Project Explanation</span>
          <h1>项目说明与对比逻辑</h1>
          <p>
            本页用于答辩时解释“为什么普通 OAuth 不够”。NoGuard 代表没有防护，OAuth-only 只检查 scope，AgentGuard 则在 scope 之外继续检查任务边界、运行时风险、Capability Token、策略沙箱和执行证据。
          </p>
        </div>
        <div className="flow-strip">
          <span>NoGuard</span>
          <b>vs</b>
          <span>OAuth-only</span>
          <b>vs</b>
          <span>AgentGuard</span>
        </div>
      </section>

      <Section
        eyebrow="Core Difference"
        title="三种方案的差异"
        description="这部分是说明性内容，用于把项目从普通权限系统中区分出来。"
        actions={<button className="primary-btn small" onClick={runComparison} disabled={loading}>{loading ? '运行中...' : '运行对比实验'}</button>}
      >
        <div className="matrix-grid">
          <div>
            <strong>NoGuard</strong>
            <span>Agent 提出工具调用后直接执行，没有任务边界、参数风险和审计证据。</span>
          </div>
          <div>
            <strong>OAuth-only</strong>
            <span>只判断 Agent 是否声明了某类 scope，无法判断本次调用是否符合当前任务。</span>
          </div>
          <div>
            <strong>AgentGuard</strong>
            <span>将 scope、任务、参数、运行时、沙箱和审计绑定到每一次工具调用。</span>
          </div>
        </div>
      </Section>

      {report && (
        <>
          <div className="verdict-grid">
            <div>
              <span>NoGuard 误放行率</span>
              <strong>{percent(report.metrics.noguard_unsafe_allow_rate)}</strong>
            </div>
            <div>
              <span>OAuth-only 误放行率</span>
              <strong>{percent(report.metrics.oauth_only_unsafe_allow_rate)}</strong>
            </div>
            <div>
              <span>AgentGuard 误放行率</span>
              <strong>{percent(report.metrics.agentguard_unsafe_allow_rate)}</strong>
            </div>
          </div>

          <Section
            eyebrow="Research Cases"
            title="横向对比样例"
            description={`总样例 ${report.total_cases} 条，其中风险样例 ${report.risky_cases} 条。`}
          >
            <div className="pipeline-card">
              <table>
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Scenario</th>
                    <th>NoGuard</th>
                    <th>OAuth-only</th>
                    <th>AgentGuard</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {report.cases.map((item) => (
                    <tr key={item.id}>
                      <td>{item.id}</td>
                      <td>{item.scenario}</td>
                      <td><Badge tone={item.noguard === 'allow' ? 'red' : 'green'}>{item.noguard}</Badge></td>
                      <td><Badge tone={item.oauth_only === 'allow' && item.is_risky ? 'red' : 'green'}>{item.oauth_only}</Badge></td>
                      <td><Badge tone={item.agentguard === 'deny' ? 'green' : 'yellow'}>{item.agentguard}</Badge></td>
                      <td>{item.research_value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        </>
      )}
    </div>
  );
}
