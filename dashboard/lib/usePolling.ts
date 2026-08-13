"use client";

import { useEffect, useRef, useState } from "react";

export interface Polled<T> {
  data: T | null;
  error: Error | null;
  /// True only until the first result arrives. Subsequent polls refresh in place rather than
  /// flashing the view back to a loading state every interval.
  loading: boolean;
}

/// Polls `fetcher` every `intervalMs`. Polling, not websockets — MVP simplicity (Task 9.1).
///
/// The fetcher is held in a ref so an inline arrow function does not restart the interval on
/// every render. That means `intervalMs` is the only thing that reschedules; pass anything else
/// the fetcher depends on through `deps`, which is what a view does when its capability hash or
/// selected provider changes.
///
/// In-flight results are dropped after unmount and a slow poll cannot overwrite a newer one,
/// which matters at the 1s interval the delegation tree uses.
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
): Polled<T> {
  const [state, setState] = useState<Polled<T>>({
    data: null,
    error: null,
    loading: true,
  });

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let cancelled = false;
    // Monotonic per effect run, so a response that arrives out of order is discarded.
    let latest = 0;

    const tick = async () => {
      const sequence = ++latest;
      try {
        const data = await fetcherRef.current();
        if (cancelled || sequence !== latest) return;
        setState({ data, error: null, loading: false });
      } catch (error) {
        if (cancelled || sequence !== latest) return;
        setState((previous) => ({
          // Keep the last good data on screen. A gateway restart mid-demo should not blank the
          // delegation tree, it should show stale numbers and an error.
          data: previous.data,
          error: error instanceof Error ? error : new Error(String(error)),
          loading: false,
        }));
      }
    };

    void tick();
    const handle = setInterval(() => void tick(), intervalMs);

    return () => {
      cancelled = true;
      clearInterval(handle);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);

  return state;
}
