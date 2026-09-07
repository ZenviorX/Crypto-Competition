import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchLiveRuntimeSnapshot } from '../services/liveApi';
import type { LiveConnectionState, LiveRuntimeSnapshot } from '../types/domain';

const ACTIVE_INTERVAL_MS = 2_000;
const DEGRADED_INTERVAL_MS = 5_000;

export function useLiveRuntime() {
  const [snapshot, setSnapshot] = useState<LiveRuntimeSnapshot | null>(null);
  const [connectionState, setConnectionState] = useState<LiveConnectionState>('connecting');
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const controller = useRef<AbortController | null>(null);
  const failureCount = useRef(0);
  const timer = useRef<number | null>(null);
  const mounted = useRef(true);

  const schedule = useCallback((delay: number, runner: () => void) => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(runner, delay);
  }, []);

  const refresh = useCallback(async () => {
    if (!mounted.current || inFlight.current || document.hidden) return;

    inFlight.current = true;
    controller.current?.abort();
    controller.current = new AbortController();

    try {
      const next = await fetchLiveRuntimeSnapshot(controller.current.signal);
      if (!mounted.current) return;
      setSnapshot(next);
      setError(next.errors.length ? next.errors.join('\n') : null);
      failureCount.current = 0;
      setConnectionState(next.errors.length ? 'degraded' : 'live');
      schedule(ACTIVE_INTERVAL_MS, () => void refresh());
    } catch (reason) {
      if (!mounted.current || controller.current?.signal.aborted) return;
      failureCount.current += 1;
      const message = reason instanceof Error ? reason.message : String(reason);
      setError(message);
      setConnectionState(failureCount.current >= 3 ? 'offline' : 'degraded');
      schedule(DEGRADED_INTERVAL_MS, () => void refresh());
    } finally {
      inFlight.current = false;
    }
  }, [schedule]);

  useEffect(() => {
    mounted.current = true;
    void refresh();

    const handleVisibility = () => {
      if (!document.hidden) void refresh();
    };
    const handleFocus = () => void refresh();
    const handleRuntimeChanged = () => void refresh();

    document.addEventListener('visibilitychange', handleVisibility);
    window.addEventListener('focus', handleFocus);
    window.addEventListener('agentguard:runtime-changed', handleRuntimeChanged);

    return () => {
      mounted.current = false;
      controller.current?.abort();
      if (timer.current !== null) window.clearTimeout(timer.current);
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('agentguard:runtime-changed', handleRuntimeChanged);
    };
  }, [refresh]);

  return {
    snapshot,
    connectionState,
    error,
    lastUpdated: snapshot?.generatedAt ?? null,
    refresh
  };
}
