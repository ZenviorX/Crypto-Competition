interface IconProps {
  name: string;
  className?: string;
}

const iconMap: Record<string, string> = {
  dashboard: '✦',
  requests: '◇',
  policies: '⌁',
  audit: '☷',
  lab: '△',
  settings: '⚙',
  shield: '⬡',
  spark: '✦',
  arrow: '→',
  check: '✓',
  block: '×'
};

export function Icon({ name, className }: IconProps) {
  return <span className={className ?? 'icon'}>{iconMap[name] ?? '•'}</span>;
}
