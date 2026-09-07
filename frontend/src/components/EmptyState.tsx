export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="empty-state">
      <div className="empty-orb">◇</div>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}
