import type { LiveConnectionState, LiveRuntimeSnapshot } from '../types/domain';

const stateText: Record<LiveConnectionState, string> = {
  connecting: '正在连接',
  live: '实时更新',
  degraded: '部分数据降级',
  offline: '后端离线'
};

function formatTime(value: string | null) {
  if (!value) return '--:--:--';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '--:--:--' : date.toLocaleTimeString();
}

export function LiveStatus({
  state,
  snapshot,
  error
}: {
  state: LiveConnectionState;
  snapshot: LiveRuntimeSnapshot | null;
  error?: string | null;
}) {
  return (
    <div className={`live-status live-status-${state}`} title={error || undefined}>
      <span className="live-status-dot" />
      <div>
        <strong>{stateText[state]}</strong>
        <small>
          {snapshot
            ? `${formatTime(snapshot.generatedAt)} · ${snapshot.fetchLatencyMs} ms`
            : '等待首轮状态同步'}
        </small>
      </div>
    </div>
  );
}
