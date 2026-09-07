import { Icon } from './Icon';

interface MetricCardProps {
  title: string;
  value: string | number;
  suffix?: string;
  hint: string;
  icon?: string;
}

export function MetricCard({ title, value, suffix, hint, icon = 'spark' }: MetricCardProps) {
  return (
    <article className="metric-card">
      <div className="metric-topline">
        <span>{title}</span>
        <span className="metric-icon"><Icon name={icon} /></span>
      </div>
      <div className="metric-value">
        {value}<small>{suffix}</small>
      </div>
      <p>{hint}</p>
    </article>
  );
}
