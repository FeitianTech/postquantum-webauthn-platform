import { useEffect, useRef, useState } from 'react';

import { cx } from '@/lib/cx';

import { IconButton } from './Button';
import { CheckIcon, CopyIcon } from './icons';
import { copyStatusText, selectContents, useCopy } from './useCopy';

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
  const { outcome, copy } = useCopy();

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

  const onCopy = async () => {
    if (await copy(value)) return;
    setExpanded(true);
    selectContents(codeRef.current);
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
          icon={outcome.state === 'copied' ? <CheckIcon className="text-success" /> : <CopyIcon />}
          onClick={onCopy}
        />
      </span>
      <span role="status" className={cx('text-caption', outcome.state === 'failed' ? 'text-danger' : 'sr-only')}>
        {copyStatusText(label, outcome)}
      </span>
    </span>
  );
}
