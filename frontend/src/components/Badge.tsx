import type { ReactNode } from 'react';

interface BadgeProps {
  children: ReactNode;
  tone?: 'green' | 'red' | 'yellow' | 'blue' | 'purple' | 'gray';
}

export function Badge({ children, tone = 'gray' }: BadgeProps) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
