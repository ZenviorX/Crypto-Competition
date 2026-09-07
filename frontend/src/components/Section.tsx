import type { ReactNode } from 'react';

interface SectionProps {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}

export function Section({ eyebrow, title, description, actions, children }: SectionProps) {
  return (
    <section className="section">
      <div className="section-head">
        <div>
          {eyebrow && <span className="eyebrow">{eyebrow}</span>}
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {actions && <div className="section-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}
