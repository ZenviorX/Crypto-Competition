import type { GatewayRequest } from '../types/domain';

const colors = {
  allow: '#16a34a',
  confirm: '#d97706',
  deny: '#dc2626',
  review: '#7c3aed'
};

const labels = {
  allow: '放行',
  confirm: '待确认',
  deny: '阻断',
  review: '复核'
};

export function DecisionDonut({ requests }: { requests: GatewayRequest[] }) {
  const counts = requests.reduce(
    (result, item) => {
      result[item.decision] += 1;
      return result;
    },
    { allow: 0, confirm: 0, deny: 0, review: 0 }
  );
  const total = Math.max(1, requests.length);
  const entries = (Object.keys(counts) as Array<keyof typeof counts>).map((key) => ({
    key,
    value: counts[key],
    percent: (counts[key] / total) * 100
  }));

  let cursor = 0;
  const gradient = entries
    .map((item) => {
      const start = cursor;
      cursor += item.percent;
      return `${colors[item.key]} ${start}% ${cursor}%`;
    })
    .join(', ');

  return (
    <div className="decision-visual">
      <div className="decision-donut" style={{ background: requests.length ? `conic-gradient(${gradient})` : '#e5e7eb' }}>
        <div className="decision-donut-core">
          <strong>{requests.length}</strong>
          <span>最新记录</span>
        </div>
      </div>
      <div className="decision-legend">
        {entries.map((item) => (
          <div key={item.key}>
            <span className="legend-color" style={{ background: colors[item.key] }} />
            <span>{labels[item.key]}</span>
            <strong>{item.value}</strong>
            <small>{requests.length ? item.percent.toFixed(1) : '0.0'}%</small>
          </div>
        ))}
      </div>
    </div>
  );
}
