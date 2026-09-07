import type { AuditLog } from '../types/domain';
import { decisionText } from '../utils/format';
import { Badge } from '../components/Badge';
import { Section } from '../components/Section';

export function AuditPage({ logs }: { logs: AuditLog[] }) {
  return (
    <Section
      eyebrow="Audit Logs"
      title="审计日志"
      description="每次策略判定、工具阻断、人工确认都留下可追溯证据。"
      actions={<button className="secondary-btn small">导出报告</button>}
    >
      <div className="audit-list">
        {logs.map((log) => (
          <article className="audit-card" key={log.id}>
            <div>
              <span className="policy-id">{log.id}</span>
              <h3>{log.action}</h3>
              <p>{log.detail}</p>
            </div>
            <div className="audit-meta">
              <Badge>{decisionText[log.result]}</Badge>
              <span>{log.timestamp}</span>
              <span>{log.actor}</span>
              <code>{log.resource}</code>
            </div>
          </article>
        ))}
      </div>
    </Section>
  );
}
