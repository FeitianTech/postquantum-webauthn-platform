import { startTransition, useCallback, useEffect, useState } from 'react';

// Parts of the page that load as chunks of their own (`import()`): a section
// the URL does not name, a dialog not yet opened. Each loads once and is kept;
// a failed load is forgotten, so asking again loads it again.

export type LazyModule<T> = {
  /** The module, loading it the first time it is asked for. */
  load: () => Promise<T>;
};

export function lazyModule<T>(loader: () => Promise<T>): LazyModule<T> {
  let pending: Promise<T> | null = null;
  return {
    load() {
      pending ??= loader().catch((error: unknown) => {
        pending = null;
        throw error;
      });
      return pending;
    },
  };
}

type LazyState<T> = {
  /** The module once it has arrived. */
  module: T | null;
  /** Its chunk could not be loaded. */
  failed: boolean;
  /** Asks for it again after a failure. */
  retry: () => void;
};

/**
 * A lazy module, loaded ahead once `prefetch` and at once when `needed`:
 * nothing on the first render (the server's and the browser's alike, so the
 * exported HTML hydrates as it is), then the module when it has arrived. It
 * arrives as a transition, so rendering what it brings gives way to the
 * person's input. A load that failed is tried again each time the module
 * becomes needed (the section shown, the dialog asked for), as well as on
 * `retry`.
 */
export function useLazyModule<T>(lazy: LazyModule<T>, prefetch: boolean, needed: boolean): LazyState<T> {
  // The module is held inside an object: a module that is a function would
  // otherwise be taken for a state updater.
  const [arrived, setArrived] = useState<{ module: T } | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [neededBefore, setNeededBefore] = useState(needed);
  const wanted = prefetch || needed;

  if (needed !== neededBefore) {
    setNeededBefore(needed);
    if (needed && failed) {
      setFailed(false);
      setAttempt((value) => value + 1);
    }
  }

  useEffect(() => {
    if (!wanted || arrived) return undefined;
    let current = true;
    lazy.load().then(
      (module) => {
        if (current) startTransition(() => setArrived({ module }));
      },
      () => {
        if (current) setFailed(true);
      },
    );
    return () => {
      current = false;
    };
  }, [lazy, wanted, arrived, attempt]);

  const retry = useCallback(() => {
    setFailed(false);
    setAttempt((value) => value + 1);
  }, []);

  return { module: arrived ? arrived.module : null, failed, retry };
}

/**
 * Runs `callback` once the page has drawn its first view and the browser is
 * idle (at most two seconds later), or shortly after where the browser cannot
 * say when it is idle. Gives what cancels it.
 */
export function whenInteractive(callback: () => void): () => void {
  if (typeof window.requestIdleCallback === 'function') {
    const handle = window.requestIdleCallback(callback, { timeout: 2000 });
    return () => window.cancelIdleCallback(handle);
  }
  const handle = window.setTimeout(callback, 200);
  return () => window.clearTimeout(handle);
}
