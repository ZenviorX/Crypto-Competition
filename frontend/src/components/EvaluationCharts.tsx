import type { StrategyComparisonResponse, TestResultSummary } from '../types/domain';

function entries(data?: Record<string, number>) {
  return Object.entries(data ?? {}).sort((a, b) => b[1] - a[1]);
}

function maxValue(items: Array<[string, number]>) {
  return Math.max(1, ...items.map(([, value]) => value));
}

export function EvaluationCharts({
  testSummary,
  strategyComparison
}: {
  testSummary: TestResultSummary | null;
  strategyComparison: StrategyComparisonResponse | null;
}) {
  const decisions = entries(testSummary?.decision_distribution);
  const categories = entries(testSummary?.category_distribution).slice(0, 8);
  const decisionMax = maxValue(decisions);
  const categoryMax = maxValue(categories);
  const strategies = strategyComparison?.available
    ? Object.entries(strategyComparison.summary)
    : [];

  return (
    <div className="evaluation-chart-grid">
      <article className="chart-card">
        <div className="chart-card-head">
          <div>
            <span>Decision Distribution</span>
            <strong>决策分布</strong>
          </div>
          <small>{testSummary?.total_cases ?? 0} cases</small>
        </div>
        <div className="horizontal-bars">
          {decisions.length ? decisions.map(([name, value]) => (
            <div className="horizontal-bar-row" key={name}>
              <span>{name}</span>
              <div><i style={{ width: `${(value / decisionMax) * 100}%` }} /></div>
              <strong>{value}</strong>
            </div>
          )) : <p className="chart-empty">运行测试后显示决策分布。</p>}
        </div>
      </article>

      <article className="chart-card">
        <div className="chart-card-head">
          <div>
            <span>Category Coverage</span>
            <strong>测试类别覆盖</strong>
          </div>
          <small>Top {categories.length}</small>
        </div>
        <div className="horizontal-bars category-bars">
          {categories.length ? categories.map(([name, value]) => (
            <div className="horizontal-bar-row" key={name}>
              <span title={name}>{name}</span>
              <div><i style={{ width: `${(value / categoryMax) * 100}%` }} /></div>
              <strong>{value}</strong>
            </div>
          )) : <p className="chart-empty">暂无类别统计。</p>}
        </div>
      </article>

      <article className="chart-card chart-card-wide">
        <div className="chart-card-head">
          <div>
            <span>Security Baseline</span>
            <strong>策略安全效果对比</strong>
          </div>
          <small>攻击误放行率越低越好</small>
        </div>
        <div className="strategy-bars">
          {strategies.length ? strategies.map(([name, value]) => {
            const blocked = Math.max(0, Math.min(100, value.attack_block_or_confirm_rate * 100));
            const unsafe = Math.max(0, Math.min(100, value.attack_allow_rate * 100));
            return (
              <div className="strategy-row" key={name}>
                <strong>{name === 'gateway' ? 'AgentGuard' : name}</strong>
                <div className="strategy-track">
                  <span className="strategy-safe" style={{ width: `${blocked}%` }} title={`阻断/确认 ${blocked.toFixed(1)}%`} />
                  <span className="strategy-unsafe" style={{ width: `${unsafe}%` }} title={`误放行 ${unsafe.toFixed(1)}%`} />
                </div>
                <small>阻断 {blocked.toFixed(1)}% · 误放行 {unsafe.toFixed(1)}%</small>
              </div>
            );
          }) : <p className="chart-empty">尚未生成策略对照结果。</p>}
        </div>
      </article>
    </div>
  );
}
