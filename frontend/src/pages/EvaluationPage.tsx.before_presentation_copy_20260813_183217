import { EvaluationCharts } from '../components/EvaluationCharts';
import { MetricCard } from '../components/MetricCard';
import { Section } from '../components/Section';
import type { EvaluationMetric, StrategyComparisonResponse, TestResultSummary } from '../types/domain';

function formatRate(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '0.00%';
  return `${(value * 100).toFixed(2)}%`;
}

function formatPercentNumber(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '0.00';
  return (value * 100).toFixed(2);
}

function formatMs(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value)) return '0.00 ms';
  return `${value.toFixed(2)} ms`;
}

const strategyNames: Record<string, string> = {
  allow_all: 'Allow All',
  keyword_only: 'Keyword Only',
  gateway: 'AgentGuard Gateway'
};

const strategyDescriptions: Record<string, string> = {
  allow_all: '无授权边界，全部放行，仅作为风险对照',
  keyword_only: '只按关键词拦截，容易漏掉上下文和任务边界风险',
  gateway: '结合 OAuth、任务边界、Capability Token、运行时监控和沙箱证据'
};

export function EvaluationPage({
  metrics,
  strategyComparison,
  testSummary,
  testRunning,
  testRunMessage,
  onRunTests,
  onRefreshTestSummary
}: {
  metrics: EvaluationMetric[];
  strategyComparison: StrategyComparisonResponse | null;
  testSummary: TestResultSummary | null;
  testRunning: boolean;
  testRunMessage: string | null;
  onRunTests: () => void;
  onRefreshTestSummary: () => void;
}) {
  const summary = strategyComparison?.summary ?? {};
  const strategies = ['allow_all', 'keyword_only', 'gateway'].filter((name) => summary[name]);
  const latestTestAvailable = Boolean(testSummary?.available);

  return (
    <div className="page-grid evaluation-page">
      <section className="evaluation-hero">
        <div>
          <span className="eyebrow">Security Evaluation</span>
          <h1>用实时数据证明 AgentGuard 的安全收益</h1>
          <p>
            测试模块会把样例直接输入 Gateway，输出准确率、风险阻断率、误放行率、误拒率和延迟；页面会在测试完成后自动同步最新摘要。
          </p>
        </div>
        <div className="evaluation-score-card">
          <span>Latest Accuracy</span>
          <strong>{formatPercentNumber(testSummary?.accuracy)}%</strong>
          <small>{testSummary?.generated_at ?? '尚未生成最新测试结果'}</small>
        </div>
      </section>

      <Section
        eyebrow="Independent Test Module"
        title="独立 Gateway 测试"
        description="提交时以该模块生成的 latest_summary.json 为准；页面不使用浏览器 Mock 伪造测试结果。"
        actions={(
          <div className="row-actions">
            <button className="secondary-btn small" onClick={onRefreshTestSummary} disabled={testRunning}>刷新结果</button>
            <button className="primary-btn small" onClick={onRunTests} disabled={testRunning}>
              {testRunning ? '测试运行中…' : '一键运行测试'}
            </button>
          </div>
        )}
      >
        <div className="metric-grid compact">
          <MetricCard title="测试样例" value={testSummary?.total_cases ?? 0} suffix=" cases" hint="本轮输入 Gateway 的样例数量" icon="lab" />
          <MetricCard title="通过样例" value={testSummary?.passed_cases ?? 0} suffix=" cases" hint="实际 decision 与预期匹配" icon="check" />
          <MetricCard title="风险阻断/确认率" value={formatPercentNumber(testSummary?.risk_block_or_confirm_rate)} suffix="%" hint="风险样例被 confirm 或 deny" icon="shield" />
          <MetricCard title="平均延迟" value={testSummary?.avg_latency_ms ?? 0} suffix=" ms" hint="Gateway 判定平均耗时" icon="spark" />
        </div>

        <div className="metric-grid compact">
          <MetricCard title="风险误放行率" value={formatPercentNumber(testSummary?.risk_unsafe_allow_rate)} suffix="%" hint="风险样例被错误 allow，越低越好" icon="arrow" />
          <MetricCard title="正常误拒率" value={formatPercentNumber(testSummary?.normal_false_deny_rate)} suffix="%" hint="正常样例被 deny，越低越好" icon="dashboard" />
          <MetricCard title="失败样例" value={testSummary?.failed_cases ?? 0} suffix=" cases" hint="决策与预期不一致" icon="shield" />
          <MetricCard title="测试耗时" value={Number((testSummary?.elapsed_ms ?? 0).toFixed(2))} suffix=" ms" hint="完整测试轮次耗时" icon="spark" />
        </div>

        <EvaluationCharts testSummary={testSummary} strategyComparison={strategyComparison} />

        <div className={`test-run-state ${testRunning ? 'test-run-active' : latestTestAvailable ? 'test-run-success' : ''}`}>
          <div>
            <strong>{testRunning ? '测试正在执行' : latestTestAvailable ? '最新测试结果已生成' : '暂无测试结果'}</strong>
            <span>{testRunMessage ?? testSummary?.message ?? '点击“一键运行测试”生成真实结果。'}</span>
          </div>
          <code>{testSummary?.generated_at ?? testSummary?.hint ?? 'test/results/latest_summary.json'}</code>
        </div>
      </Section>

      <section className="evaluation-detail-grid">
        <Section
          eyebrow="Auxiliary Metrics"
          title="本地运行辅助指标"
          description="由运行证据、审计日志和测试摘要实时聚合。"
        >
          <div className="evaluation-metric-list">
            {metrics.map((metric) => (
              <div key={metric.name}>
                <span>{metric.name}</span>
                <strong>{metric.value}{metric.unit}</strong>
                <small>{metric.description}</small>
              </div>
            ))}
            {!metrics.length && <div className="empty-live-state">等待运行数据。</div>}
          </div>
        </Section>

        <Section
          eyebrow="Result Files"
          title="测试产物"
          description={`生成 JSON、CSV、Markdown 和 HTML 看板。测试耗时 ${formatMs(testSummary?.elapsed_ms)}。`}
        >
          <div className="result-file-list">
            <div><span>摘要 JSON</span><code>{testSummary?.outputs?.latest_summary ?? 'test/results/latest_summary.json'}</code></div>
            <div><span>样例明细</span><code>{testSummary?.outputs?.latest_cases ?? 'test/results/latest_cases.json'}</code></div>
            <div><span>CSV 明细</span><code>{testSummary?.outputs?.latest_detail_csv ?? 'test/results/latest_detail.csv'}</code></div>
            <div><span>HTML 看板</span><code>{testSummary?.outputs?.latest_dashboard_html ?? 'test/results/latest_dashboard.html'}</code></div>
          </div>
        </Section>
      </section>

      <Section
        eyebrow="Baseline Comparison"
        title="历史策略对照明细"
        description="图表突出主要结论；下方保留完整数值，便于答辩时解释。"
      >
        {strategyComparison?.available ? (
          <div className="strategy-detail-grid">
            {strategies.map((name) => {
              const item = summary[name];
              return (
                <article key={name}>
                  <span>{strategyNames[name] ?? name}</span>
                  <h3>{strategyDescriptions[name] ?? '暂无策略说明'}</h3>
                  <div><small>攻击拦截/确认率</small><strong>{formatRate(item.attack_block_or_confirm_rate)}</strong></div>
                  <div><small>攻击误放行率</small><strong>{formatRate(item.attack_allow_rate)}</strong></div>
                  <div><small>正常样例通过率</small><strong>{formatRate(item.normal_not_denied_rate)}</strong></div>
                  <div><small>决策匹配率</small><strong>{formatRate(item.decision_match_rate)}</strong></div>
                </article>
              );
            })}
          </div>
        ) : (
          <div className="empty-state">
            <strong>历史策略对照结果未生成</strong>
            <p>{strategyComparison?.hint ?? '当前推荐先运行上方独立测试模块。'}</p>
          </div>
        )}
      </Section>
    </div>
  );
}
