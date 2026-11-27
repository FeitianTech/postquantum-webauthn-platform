import type { ExplorerSort } from '@/logic/mds/explorer/filter-sort.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { type ReactNode, type RefObject, useEffect, useRef, useState } from 'react';

import { ChevronDownIcon } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { ExplorerRow } from './ExplorerRow';
import { ROW_GRID } from './grid';
import { EXPLORER_COLUMNS, type ExplorerColumn } from './columns';

const ROWS_BEFORE_BACK_TO_TOP = 5;

// A quiet sign that the table goes on to the right: a white fade over the
// frame's right edge while it can scroll further that way (never a grey fill or a
// shadow), inside the frame's border and beside its vertical scrollbar.
function EdgeFade({
  frameRef,
  tableRef,
}: {
  frameRef: RefObject<HTMLDivElement | null>;
  tableRef: RefObject<HTMLTableElement | null>;
}) {
  const fadeRef = useRef<HTMLDivElement>(null);
  const [more, setMore] = useState(false);

  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) return undefined;
    const measure = () => {
      setMore(frame.scrollLeft + frame.clientWidth < frame.scrollWidth - 1);
      const fade = fadeRef.current;
      if (!fade) return;
      // The frame's border is 1 px; what else it gives up is its scrollbars.
      fade.style.right = `${Math.max(1, frame.offsetWidth - frame.clientWidth - 1)}px`;
      fade.style.bottom = `${Math.max(1, frame.offsetHeight - frame.clientHeight - 1)}px`;
    };
    measure();
    frame.addEventListener('scroll', measure, { passive: true });
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure);
    observer?.observe(frame);
    if (tableRef.current) observer?.observe(tableRef.current);
    return () => {
      frame.removeEventListener('scroll', measure);
      observer?.disconnect();
    };
  }, [frameRef, tableRef]);

  return (
    <div
      ref={fadeRef}
      aria-hidden="true"
      data-mds-fade=""
      hidden={!more}
      className="pointer-events-none absolute top-px z-[15] w-10 rounded-r-[13px] bg-linear-to-l from-white to-transparent"
    />
  );
}

function HeaderCell({
  column,
  sort,
  onSort,
  filtered,
}: {
  column: ExplorerColumn;
  sort: ExplorerSort;
  onSort: (key: string) => void;
  filtered: boolean;
}) {
  const direction = sort.key === column.key ? sort.direction : 'none';
  const ariaSort = direction === 'asc' ? 'ascending' : direction === 'desc' ? 'descending' : 'none';
  return (
    <th
      scope="col"
      role="columnheader"
      aria-sort={ariaSort}
      className="flex h-10 items-center border-b border-line bg-surface px-3 text-caption font-medium whitespace-nowrap text-ink-muted"
    >
      <button
        type="button"
        onClick={() => onSort(column.key)}
        className={cx(
          '-mx-1 inline-flex max-w-full items-center gap-1 rounded-xs px-1 hover:text-ink',
          direction !== 'none' && 'text-ink',
        )}
      >
        {/* On a phone the Icon column is only as wide as an icon: its name is read, not shown. */}
        <span className={cx('truncate', column.key === 'icon' && 'max-sm:sr-only')}>{column.header}</span>
        {filtered ? (
          <>
            <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-accent" />
            <span className="sr-only">(filtered)</span>
          </>
        ) : null}
        {direction !== 'none' ? (
          <ChevronDownIcon size={12} className={cx('shrink-0 text-accent', direction === 'asc' && 'rotate-180')} />
        ) : null}
      </button>
    </th>
  );
}

// Floats over the list's lower right once five rows have gone by; takes the list
// back to its first row.
function BackToTop({ frameRef }: { frameRef: RefObject<HTMLDivElement | null> }) {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) return undefined;
    const onScroll = () => {
      const header = frame.querySelector('thead')?.getBoundingClientRect().bottom ?? 0;
      const rows = [...frame.querySelectorAll<HTMLTableRowElement>('tbody tr:not([hidden])')];
      const fifth = rows[ROWS_BEFORE_BACK_TO_TOP - 1];
      setShown(rows.length > ROWS_BEFORE_BACK_TO_TOP && Boolean(fifth) && fifth.getBoundingClientRect().top < header);
    };
    frame.addEventListener('scroll', onScroll, { passive: true });
    return () => frame.removeEventListener('scroll', onScroll);
  }, [frameRef]);

  if (!shown) return null;
  const toTop = () => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    frameRef.current?.scrollTo({ top: 0, behavior: reduced ? 'auto' : 'smooth' });
  };
  return (
    <button
      type="button"
      aria-label="Back to top of the authenticator list"
      title="Back to top"
      onClick={toTop}
      className={cx(
        'absolute right-4 bottom-4 z-20 inline-flex size-11 items-center justify-center rounded-full border border-line',
        'bg-surface text-title text-ink shadow-float-sm transition-colors hover:border-line-hover',
      )}
    >
      ↑
    </button>
  );
}

type ExplorerTableProps = {
  rows: MdsEntry[];
  /** The entries the filters let through; the others stay in the table, hidden. */
  shown: Set<string>;
  sort: ExplorerSort;
  onSort: (key: string) => void;
  filteredColumns: Set<string>;
  expanded: Set<string>;
  onToggle: (entryId: string) => void;
  onOpen?: (entryId: string) => void;
  /** A row that stands for the whole list: loading, nothing to show, nothing matches. */
  state: ReactNode;
  frameRef: RefObject<HTMLDivElement | null>;
};

// The 14 columns in a frame that scrolls both ways by itself: the header stays in
// view as the list scrolls, the sideways scrollbar is always within reach, and
// the page never scrolls sideways. Every row is in the page (find-in-page finds
// it), but each row is a grid on the one column template, not a table row, so
// the browser can skip laying out and painting the rows out of view
// (content-visibility, which table rows do not take): a filter that brings back
// all 517 rows lays out only those in view. The table roles are written out,
// since the display is not a table's.
export function ExplorerTable({
  rows,
  shown,
  sort,
  onSort,
  filteredColumns,
  expanded,
  onToggle,
  onOpen,
  state,
  frameRef,
}: ExplorerTableProps) {
  const tableRef = useRef<HTMLTableElement>(null);

  return (
    <div className="relative">
      <div
        ref={frameRef}
        data-mds-frame=""
        // Positioned, so what is absolutely placed inside (a cell's screen-reader
        // status) is clipped by the frame instead of widening the page.
        className="relative max-h-[calc(100dvh-var(--header-height)-2rem)] min-h-80 overflow-auto overscroll-x-contain rounded-md border border-line"
      >
        <table ref={tableRef} role="table" aria-label="FIDO MDS authenticators" className="block w-max text-left text-body">
          <thead role="rowgroup" className="sticky top-0 z-10 block bg-surface">
            <tr role="row" className={ROW_GRID}>
              {EXPLORER_COLUMNS.map((column) => (
                <HeaderCell
                  key={column.key}
                  column={column}
                  sort={sort}
                  onSort={onSort}
                  filtered={filteredColumns.has(column.key)}
                />
              ))}
            </tr>
          </thead>
          <tbody role="rowgroup" className="block">
            {state ? (
              <tr role="row" className="block">
                <td role="cell" colSpan={EXPLORER_COLUMNS.length} className="block p-0">
                  {state}
                </td>
              </tr>
            ) : null}
            {rows.map((entry) => (
              <ExplorerRow
                key={entry.entryId}
                entry={entry}
                hidden={!shown.has(entry.entryId)}
                expanded={expanded.has(entry.entryId)}
                onToggle={onToggle}
                onOpen={onOpen}
              />
            ))}
          </tbody>
        </table>
      </div>
      <EdgeFade frameRef={frameRef} tableRef={tableRef} />
      <BackToTop frameRef={frameRef} />
    </div>
  );
}
