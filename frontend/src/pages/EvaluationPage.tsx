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
          <h1>严格授权回归评测与策略对比</h1>
          <p>
            通过统一用例集验证正常放行、人工确认与风险拒绝，并统计决策匹配率、风险阻断率、误放行率、误拒率和授权判定耗时。
          </p>
        </div>
        <div className="evaluation-score-card">
          <span>本轮决策匹配率</span>
          <strong>{formatPercentNumber(testSummary?.accuracy)}%</strong>
          <small>{testSummary?.generated_at ?? '尚未生成最新测试结果'}</small>
        </div>
      </section>

      <Section
        eyebrow="Strict Authorization Evaluation"
        title="131 条严格授权回归评测"
        description="每条用例仅设置一个预期裁定，统一检验正常放行、人工确认与风险拒绝。"
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
          <MetricCard title="测试样例" value={testSummary?.total_cases ?? 0} suffix=" cases" hint="覆盖正常操作与多类风险场景" icon="lab" />
          <MetricCard title="通过样例" value={testSummary?.passed_cases ?? 0} suffix=" cases" hint="裁定结果与唯一预期决策一致" icon="check" />
          <MetricCard title="风险阻断/确认率" value={formatPercentNumber(testSummary?.risk_block_or_confirm_rate)} suffix="%" hint="风险请求进入确认或拒绝的比例" icon="shield" />
          <MetricCard title="平均授权延迟" value={testSummary?.avg_latency_ms ?? 0} suffix=" ms" hint="本机进程内授权判定平均耗时" icon="spark" />
        </div>

        <div className="metric-grid compact">
          <MetricCard title="风险误放行率" value={formatPercentNumber(testSummary?.risk_unsafe_allow_rate)} suffix="%" hint="风险请求被错误放行的比例" icon="arrow" />
          <MetricCard title="正常误拒率" value={formatPercentNumber(testSummary?.normal_false_deny_rate)} suffix="%" hint="正常请求被错误拒绝的比例" icon="dashboard" />
          <MetricCard title="失败样例" value={testSummary?.failed_cases ?? 0} suffix=" cases" hint="裁定结果与预期决策不一致" icon="shield" />
          <MetricCard title="测试耗时" value={Number((testSummary?.elapsed_ms ?? 0).toFixed(2))} suffix=" ms" hint="完整测试轮次耗时" icon="spark" />
        </div>

        <EvaluationCharts testSummary={testSummary} strategyComparison={strategyComparison} />

        <div className={`test-run-state ${testRunning ? 'test-run-active' : latestTestAvailable ? 'test-run-success' : ''}`}>
          <div>
            <strong>{testRunning ? '测试正在执行' : latestTestAvailable ? '最新测试结果已生成' : '暂无测试结果'}</strong>
            <span>{testRunMessage ?? testSummary?.message ?? '点击“一键运行测试”开始本轮评测。'}</span>
          </div>
          <code>{testSummary?.generated_at ? `评测完成：${testSummary.generated_at}` : '等待评测结果'}</code>
        </div>
      </Section>

      <section className="evaluation-detail-grid">
        <Section
          eyebrow="Evaluation Metrics"
          title="运行与评测指标"
          description="综合展示授权判定、风险控制与执行证据相关指标。"
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
          eyebrow="Evaluation Protocol"
          title="评测口径"
          description={`采用唯一预期决策进行严格匹配；本轮完整评测耗时 ${formatMs(testSummary?.elapsed_ms)}。`}
        >
          <div className="result-file-list">
            <div>
              <span>唯一预期决策</span>
              <code>每条用例仅设置一个正确裁定</code>
            </div>
            <div>
              <span>风险样例</span>
              <code>{testSummary?.risk_cases ?? 0} 条</code>
            </div>
            <div>
              <span>正常样例</span>
              <code>{testSummary?.normal_cases ?? 0} 条</code>
            </div>
            <div>
              <span>结果边界</span>
              <code>当前结果仅代表本轮自建严格回归用例集</code>
            </div>
          </div>
        </Section>
      </section>

      <Section
        eyebrow="Baseline Comparison"
        title="策略对照明细"
        description="比较不同授权策略在风险控制、正常放行和决策匹配方面的表现。"
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
            <strong>策略对照结果尚未生成</strong>
            <p>{strategyComparison?.hint ?? '运行评测后可查看不同策略的对照结果。'}</p>
          </div>
        )}
      </Section>
    </div>
  );
}
