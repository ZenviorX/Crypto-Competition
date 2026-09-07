import type { PolicyRule } from '../types/domain';
import { PolicyCard } from '../components/PolicyCard';
import { Section } from '../components/Section';

export function PoliciesPage({ policies }: { policies: PolicyRule[] }) {
  return (
    <Section
      eyebrow="Policy Engine"
      title="策略中心"
      description="把策略独立出来后，前端重点展示：作用域、优先级、效果、示例、是否启用。"
      actions={<button className="secondary-btn small">导入 YAML</button>}
    >
      <div className="policy-grid">
        {policies.map((policy) => <PolicyCard key={policy.id} policy={policy} />)}
      </div>
    </Section>
  );
}
