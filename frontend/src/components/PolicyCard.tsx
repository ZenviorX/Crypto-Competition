import type { PolicyRule } from '../types/domain';
import { decisionText } from '../utils/format';
import { Badge } from './Badge';

const tone = {
  allow: 'green',
  deny: 'red',
  confirm: 'yellow',
  review: 'purple'
} as const;

export function PolicyCard({ policy }: { policy: PolicyRule }) {
  return (
    <article className="policy-card">
      <div className="policy-card-head">
        <div>
          <span className="policy-id">{policy.id}</span>
          <h3>{policy.name}</h3>
        </div>
        <Badge tone={policy.enabled ? 'green' : 'gray'}>{policy.enabled ? '启用' : '停用'}</Badge>
      </div>
      <p>{policy.description}</p>
      <div className="policy-meta">
        <span>作用域：<strong>{policy.scope}</strong></span>
        <span>优先级：<strong>{policy.priority}</strong></span>
        <span>效果：<Badge tone={tone[policy.effect]}>{decisionText[policy.effect]}</Badge></span>
      </div>
      <div className="example-list">
        {policy.examples.map((item) => <code key={item}>{item}</code>)}
      </div>
      <small>最后更新：{policy.updatedAt}</small>
    </article>
  );
}
