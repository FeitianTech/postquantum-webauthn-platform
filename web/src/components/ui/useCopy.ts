import { writeToClipboard } from '@legacy/shared/browser/report.js';
import { useCallback, useEffect, useState } from 'react';

const COPIED_MS = 2000;

export type CopyOutcome = { state: 'idle' | 'copied' | 'failed'; reason?: string };

// Copies text and remembers how it went: "copied" for two seconds, or "failed"
// with the browser's reason until the next copy. `copy` resolves to whether the
// text reached the clipboard.
export function useCopy() {
  const [outcome, setOutcome] = useState<CopyOutcome>({ state: 'idle' });

  useEffect(() => {
    if (outcome.state !== 'copied') return undefined;
    const timer = setTimeout(() => setOutcome({ state: 'idle' }), COPIED_MS);
    return () => clearTimeout(timer);
  }, [outcome]);

  const copy = useCallback(async (text: string) => {
    const failure = await writeToClipboard(text);
    setOutcome(failure === null ? { state: 'copied' } : { state: 'failed', reason: failure });
    return failure === null;
  }, []);

  return { outcome, copy };
}

// What the status line under a copied value says.
export function copyStatusText(label: string, outcome: CopyOutcome) {
  if (outcome.state === 'copied') return `${label} copied.`;
  if (outcome.state === 'failed') {
    const reason = outcome.reason ?? '';
    return `Could not copy: ${reason}${/[.!?]$/.test(reason) ? '' : '.'} It is shown in full and selected, to copy by hand.`;
  }
  return '';
}

// Select an element's text, so a value the clipboard refused can be copied by hand.
export function selectContents(element: HTMLElement | null) {
  const selection = window.getSelection();
  if (!element || !selection) return;
  const range = document.createRange();
  range.selectNodeContents(element);
  selection.removeAllRanges();
  selection.addRange(range);
}
