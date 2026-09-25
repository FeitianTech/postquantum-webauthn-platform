import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useLayoutEffect, useRef } from 'react';

import { cx } from '@/lib/cx';

// useLayoutEffect in the browser (the highlight is placed before paint), and no
// warning when the page is rendered for the static export.
const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

export type SegmentOption<T extends string> = { value: T; label: ReactNode };

type SegmentedControlProps<T extends string> = {
  /** The accessible name of the tab list. */
  label: string;
  options: readonly SegmentOption<T>[];
  value: T;
  onChange: (value: T) => void;
  /** Tab ids are `${idBase}-tab-${value}`; each tab controls `${idBase}-panel-${value}`. */
  idBase: string;
  size?: 'sm' | 'md';
  className?: string;
};

export function segmentIds(idBase: string, value: string) {
  return { tab: `${idBase}-tab-${value}`, panel: `${idBase}-panel-${value}` };
}

const NEXT_KEYS = new Set(['ArrowRight', 'ArrowDown']);
const PREVIOUS_KEYS = new Set(['ArrowLeft', 'ArrowUp']);

// Tabs on a white track with one white highlight that slides to the chosen tab.
// The highlight is placed through the CSSOM (element.style), which the CSP
// allows, never through a style attribute. It jumps rather than slides on its
// first placement, on a resize and when the value changes from outside (the URL
// hash), and never slides under prefers-reduced-motion.
export function SegmentedControl<T extends string>({
  label,
  options,
  value,
  onChange,
  idBase,
  size = 'md',
  className,
}: SegmentedControlProps<T>) {
  const listRef = useRef<HTMLDivElement>(null);
  const highlightRef = useRef<HTMLSpanElement>(null);
  const tabs = useRef(new Map<string, HTMLButtonElement>());
  const chosenHere = useRef(false);

  const place = useCallback(
    (slide: boolean) => {
      const list = listRef.current;
      const highlight = highlightRef.current;
      const tab = tabs.current.get(value);
      if (!list || !highlight || !tab) return;
      if (!slide) highlight.dataset.instant = '';
      highlight.style.width = `${tab.offsetWidth}px`;
      highlight.style.transform = `translateX(${tab.offsetLeft}px)`;
      if (!slide) {
        // Apply the position with transitions off, then turn them back on.
        void highlight.offsetWidth;
        delete highlight.dataset.instant;
      }
      highlight.dataset.ready = '';
      list.dataset.ready = '';
    },
    [value],
  );

  useIsomorphicLayoutEffect(() => {
    place(chosenHere.current);
    chosenHere.current = false;
  }, [place]);

  useEffect(() => {
    const list = listRef.current;
    if (!list || typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(() => place(false));
    observer.observe(list);
    return () => observer.disconnect();
  }, [place]);

  const choose = (next: T) => {
    if (next !== value) {
      chosenHere.current = true;
      onChange(next);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = options.findIndex((option) => option.value === value);
    let target = -1;
    if (NEXT_KEYS.has(event.key)) target = (index + 1) % options.length;
    else if (PREVIOUS_KEYS.has(event.key)) target = (index - 1 + options.length) % options.length;
    else if (event.key === 'Home') target = 0;
    else if (event.key === 'End') target = options.length - 1;
    if (target < 0) return;
    event.preventDefault();
    const next = options[target].value;
    tabs.current.get(next)?.focus();
    choose(next);
  };

  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={label}
      data-segmented=""
      onKeyDown={onKeyDown}
      className={cx(
        'relative inline-flex max-w-full items-center gap-0.5 rounded-full border border-line bg-surface p-[3px]',
        className,
      )}
    >
      <span
        ref={highlightRef}
        aria-hidden="true"
        data-segment-highlight=""
        className={cx(
          'pointer-events-none absolute top-[3px] bottom-[3px] left-0 rounded-full bg-surface opacity-0 shadow-segment',
          'transition-[transform,width] duration-(--duration-base) ease-standard',
          'data-instant:transition-none data-ready:opacity-100 motion-reduce:transition-none',
        )}
      />
      {options.map((option) => {
        const selected = option.value === value;
        const ids = segmentIds(idBase, option.value);
        return (
          <button
            key={option.value}
            ref={(element) => {
              if (element) tabs.current.set(option.value, element);
              else tabs.current.delete(option.value);
            }}
            type="button"
            role="tab"
            id={ids.tab}
            aria-selected={selected}
            aria-controls={ids.panel}
            tabIndex={selected ? 0 : -1}
            onClick={() => choose(option.value)}
            className={cx(
              'relative inline-flex shrink-0 items-center justify-center rounded-full font-medium whitespace-nowrap',
              'text-ink-muted transition-colors duration-(--duration-fast) hover-or-demo:text-ink',
              'aria-selected:font-semibold aria-selected:text-ink',
              size === 'sm' ? 'h-7 px-3 text-label' : 'h-8 px-4 text-label',
            )}
          >
            {/* The bold copy keeps each tab as wide as its selected state, so
                choosing a tab never moves the others. */}
            <span className="grid">
              <span aria-hidden="true" className="invisible col-start-1 row-start-1 font-semibold">
                {option.label}
              </span>
              <span className="col-start-1 row-start-1">{option.label}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
