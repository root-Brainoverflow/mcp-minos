// hooks.js — small data-fetching hook shared by the screens.
//
// `useApi(fetcher)` calls the (stable) fetcher on mount and exposes
// { data, loading, error, reload }. On failure it AUTO-RETRIES a couple of
// times with a short delay — this self-heals the common "page loaded a beat
// before the backend was ready" race. After the retries are exhausted it sets
// `error` so the screen can show a clear "backend unreachable — retry" state
// (never silent sample data).
import { useState, useEffect, useCallback } from "react";

export function useApi(fetcher, { retries = 3, retryDelay = 1000 } = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const reload = useCallback(() => {
    let cancelled = false;
    let attempt = 0;
    setLoading(true);
    setError(false);

    const run = () => {
      if (cancelled) return;
      Promise.resolve()
        .then(fetcher)
        .then((d) => {
          if (cancelled) return;
          setData(d);
          setLoading(false);
          setError(false);
        })
        .catch(() => {
          if (cancelled) return;
          if (attempt < retries) {
            attempt += 1;
            setTimeout(run, retryDelay);
          } else {
            setLoading(false);
            setError(true);
          }
        });
    };

    run();
    return () => { cancelled = true; };
  }, [fetcher]);

  useEffect(() => reload(), [reload]);

  return { data, loading, error, reload };
}
