import { gatherAnalysis } from '@legacy/shared/browser/report.js';
import { useCallback, useRef, useState } from 'react';

import type { Analysis } from './types';

// The Analyze Browser's findings, asked once per page on the first request and
// reused after (as today). While the questions run the trigger is disabled and
// further requests are ignored; if they fail the panel does not open, and the
// next request asks again.
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
        cached.current = await gatherAnalysis();
        setAnalysis(cached.current);
      } catch (error) {
        console.error('Analyze Browser could not gather its findings.', error);
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
