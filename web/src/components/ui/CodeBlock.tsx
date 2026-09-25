import { useEffect, useRef, useState } from 'react';

import { cx } from '@/lib/cx';

import { IconButton } from './Button';
import { CheckIcon, CopyIcon } from './icons';
import { copyStatusText, selectContents, useCopy } from './useCopy';

type CodeBlockProps = {
  value: string;
  /** What the text is, for the copy button and its status: "Copy EDN (exact bytes)". */
  label: string;
  /** Start at a height with "Show all" when the text is longer (the default); false shows it whole. */
  collapsible?: boolean;
  className?: string;
};

// Text that is data, in Geist Mono on white with a hairline: EDN, JSON, PEM, hex.
// Nothing is cut off: the whole text is always in the page (the collapsed height
// is only a height), lines wrap instead of scrolling the page sideways, a long
// block starts collapsed with "Show all", and it can always be copied. When
// copying fails the block opens and its text is selected, to copy by hand.
export function CodeBlock({ value, label, collapsible = true, className }: CodeBlockProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const { outcome, copy } = useCopy();
  const collapsed = collapsible && !expanded;

  useEffect(() => {
    const pre = preRef.current;
    if (!pre || !collapsible) return undefined;
    const measure = () => setOverflowing(pre.scrollHeight > pre.clientHeight + 1);
    measure();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(measure);
    observer.observe(pre);
    return () => observer.disconnect();
  }, [value, collapsible]);

  const onCopy = async () => {
    if (await copy(value)) return;
    setExpanded(true);
    selectContents(preRef.current);
  };

  return (
    <div className={cx('min-w-0', className)} data-code-block>
      <div className="relative min-w-0 rounded-sm border border-line bg-surface">
        <pre
          ref={preRef}
          className={cx(
            'm-0 overflow-hidden py-3 pr-12 pl-3.5 font-mono text-[0.78125rem] leading-[1.65] whitespace-pre-wrap text-ink wrap-anywhere',
            collapsed && 'max-h-64',
          )}
        >
          {value}
        </pre>
        {collapsed && overflowing ? (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-px bottom-px h-10 rounded-b-sm bg-linear-to-t from-white to-transparent"
          />
        ) : null}
        <IconButton
          size="sm"
          label={`Copy ${label}`}
          className="absolute top-1.5 right-1.5"
          icon={outcome.state === 'copied' ? <CheckIcon className="text-success" /> : <CopyIcon />}
          onClick={onCopy}
        />
      </div>
      {collapsible && (overflowing || expanded) ? (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
          className="mt-1.5 rounded-xs px-1 text-caption font-medium text-accent-ink hover-or-demo:underline"
        >
          {expanded ? 'Show less' : 'Show all'}
        </button>
      ) : null}
      <span role="status" className={cx('mt-1 block text-caption', outcome.state === 'failed' ? 'text-danger' : 'sr-only')}>
        {copyStatusText(label, outcome)}
      </span>
    </div>
  );
}
