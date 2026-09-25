import { writeToClipboard } from '@legacy/shared/browser/report.js';
import { useEffect, useRef, useState } from 'react';

import { cx } from '@/lib/cx';

import { IconButton } from './Button';
import { CheckIcon, CopyIcon } from './icons';

const COPIED_MS = 2000;

type MonoValueProps = {
  value: string;
  /** What the value is, for the copy button: "Copy AAGUID". */
  label: string;
  className?: string;
};

// An identifier, hex, base64 or PEM value in Geist Mono. It is never cut off
// silently: a long value is truncated with "Show all", and it can always be
// copied. When copying fails the value is shown in full and selected, to copy by hand.
export function MonoValue({ value, label, className }: MonoValueProps) {
  const codeRef = useRef<HTMLElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const [copy, setCopy] = useState<{ state: 'idle' | 'copied' | 'failed'; reason?: string }>({ state: 'idle' });

  useEffect(() => {
    const code = codeRef.current;
    if (!code) return undefined;
    const measure = () => setOverflowing(code.scrollWidth > code.clientWidth);
    measure();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(code);
    return () => observer.disconnect();
  }, [value]);

  useEffect(() => {
    if (copy.state !== 'copied') return undefined;
    const timer = setTimeout(() => setCopy({ state: 'idle' }), COPIED_MS);
    return () => clearTimeout(timer);
  }, [copy]);

  const onCopy = async () => {
    const failure = await writeToClipboard(value);
    if (failure === null) {
      setCopy({ state: 'copied' });
      return;
    }
    setCopy({ state: 'failed', reason: failure });
    setExpanded(true);
    const code = codeRef.current;
    const selection = window.getSelection();
    if (code && selection) {
      const range = document.createRange();
      range.selectNodeContents(code);
      selection.removeAllRanges();
      selection.addRange(range);
    }
  };

  return (
    <span className={cx('flex min-w-0 flex-col gap-1', className)}>
      <span className="flex min-w-0 items-center gap-1">
        <code
          ref={codeRef}
          title={expanded ? undefined : value}
          className={cx(
            'min-w-0 font-mono text-label text-ink',
            expanded ? 'break-all whitespace-pre-wrap' : 'truncate whitespace-nowrap',
          )}
        >
          {value}
        </code>
        {overflowing || expanded ? (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="shrink-0 rounded-xs px-1 text-caption font-medium text-accent-ink hover-or-demo:underline"
          >
            {expanded ? 'Show less' : 'Show all'}
          </button>
        ) : null}
        <IconButton
          size="sm"
          label={`Copy ${label}`}
          icon={copy.state === 'copied' ? <CheckIcon className="text-success" /> : <CopyIcon />}
          onClick={onCopy}
        />
      </span>
      <span role="status" className={cx('text-caption', copy.state === 'failed' ? 'text-danger' : 'sr-only')}>
        {copy.state === 'copied'
          ? `${label} copied.`
          : copy.state === 'failed'
            ? `Could not copy: ${copy.reason}${/[.!?]$/.test(copy.reason ?? '') ? '' : '.'} It is shown in full and selected, to copy by hand.`
            : ''}
      </span>
    </span>
  );
}
