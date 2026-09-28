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
  /**
   * On a phone, the whole value on the lines it needs (an AAGUID on one) and the
   * copy button at the top right of the nearest positioned box, beside the
   * value's label: a phone's width is too little to cut the value to.
   */
  wrapOnPhone?: boolean;
};

// An identifier, hex, base64 or PEM value in Geist Mono. It is never cut off
// silently: a long value is truncated with "Show all", and it can always be
// copied. When copying fails the value is shown in full and selected, to copy by hand.
// The flex gap between the value and the buttons after it (gap-1).
const GAP = 4;

export function MonoValue({ value, label, className, wrapOnPhone = false }: MonoValueProps) {
  const codeRef = useRef<HTMLElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const { outcome, copy } = useCopy();

  useEffect(() => {
    const code = codeRef.current;
    if (!code) return undefined;
    // Measured as if "Show all" were not there: the room it takes would keep
    // the value cut once it had shown. Measured again when the row resizes and
    // when the fonts arrive (the value's width changes, its box's may not).
    const measure = () => {
      const showAll = code.parentElement?.querySelector<HTMLElement>('[data-role="show-all"]');
      const room = code.clientWidth + (showAll ? showAll.offsetWidth + GAP : 0);
      setOverflowing(code.scrollWidth > room);
    };
    measure();
    const fonts = document.fonts;
    fonts?.addEventListener?.('loadingdone', measure);
    void fonts?.ready?.then(measure);
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure);
    observer?.observe(code.parentElement ?? code);
    return () => {
      fonts?.removeEventListener?.('loadingdone', measure);
      observer?.disconnect();
    };
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
            wrapOnPhone && 'max-sm:overflow-visible max-sm:break-all max-sm:whitespace-pre-wrap',
          )}
        >
          {value}
        </code>
        {overflowing || expanded ? (
          <button
            type="button"
            data-role="show-all"
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
          className={wrapOnPhone ? 'max-sm:absolute max-sm:top-0 max-sm:right-0' : undefined}
        />
      </span>
      <span role="status" className={cx('text-caption', outcome.state === 'failed' ? 'text-danger' : 'sr-only')}>
        {copyStatusText(label, outcome)}
      </span>
    </span>
  );
}
