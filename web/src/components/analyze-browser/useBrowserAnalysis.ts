import type { Analysis } from '@/logic/browser/report.js';
import { useCallback, useRef, useState } from 'react';

import { lazyModule } from '@/lib/lazyModule';

// The questions load as a chunk of their own, with the panel (AppShell).
const BROWSER_REPORT = lazyModule(() => import(/* webpackChunkName: "analyze-browser" */ '@/logic/browser/report.js'));

// The Analyze Browser's findings, asked once per page on the first request and
// reused after (as today). While the questions run the trigger is disabled and
// further requests are ignored; if they fail (or their chunk cannot be loaded)
// the panel does not open, and the next request asks again.
export function useBrowserAnalysis() {
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [running, setRunning] = useState(false);
  const [open, setOpen] = useState(false);
  const cached = useRef<Analysis | null>(null);
  const busy = useRef(false);
  const openedFrom = useRef<HTMLElement | null>(null);

  const request = useCallback(async (from: HTMLElement | null) => {
    if (busy.current) return;
    openedFrom.current = from;
    if (!cached.current) {
      busy.current = true;
      setRunning(true);
      try {
        cached.current = await (await BROWSER_REPORT.load()).gatherAnalysis();
        setAnalysis(cached.current);
      } catch {
        // gatherAnalysis answers each question itself, so this is a bug: nothing
        // opens, and the next click asks again.
        return;
      } finally {
        busy.current = false;
        setRunning(false);
      }
    }
    setOpen(true);
  }, []);

  const close = useCallback(() => setOpen(false), []);
  const returnFocusTo = useCallback(() => openedFrom.current, []);

  return { analysis, running, open, request, close, returnFocusTo };
}
