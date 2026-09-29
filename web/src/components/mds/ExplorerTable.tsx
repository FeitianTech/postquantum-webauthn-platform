import { MDS_MIN_COLUMN_WIDTH, normaliseExplorerColumnWidths } from '@/logic/advanced/mds/explorer/columns.js';
import {
  type KeyboardEvent,
  type PointerEvent,
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';

import { ChevronDownIcon } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { ExplorerRow } from './ExplorerRow';
import { ROW_GRID } from './grid';
import { EXPLORER_COLUMNS, type ExplorerColumn, type ExplorerSort, type MdsEntry } from './model';

const normaliseWidths = normaliseExplorerColumnWidths as (widths: number[], minWidth?: number) => number[];
const KEY_STEP = 16;
// The columns' widths, set on the table and read by every row's grid.
const COLUMNS_PROPERTY = '--mds-columns';
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

// Below the `sm` breakpoint.
const PHONE = '(max-width: 639px)';

function minimumWidth(column: ExplorerColumn) {
  return 'min' in column ? column.min : MDS_MIN_COLUMN_WIDTH;
}

// The handle on a header's right edge: drag it, or focus it and use the arrow
// keys. Widths last while the page is open, as in the current UI.
function ColumnResizer({
  column,
  width,
  onResize,
}: {
  column: ExplorerColumn;
  width: number;
  onResize: (width: number) => void;
}) {
  const drag = useRef<{ x: number; width: number } | null>(null);
  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.preventDefault();
    event.stopPropagation();
    drag.current = { x: event.clientX, width };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return;
    onResize(drag.current.width + event.clientX - drag.current.x);
  };
  const onPointerEnd = (event: PointerEvent<HTMLDivElement>) => {
    drag.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    event.preventDefault();
    onResize(width + (event.key === 'ArrowRight' ? KEY_STEP : -KEY_STEP));
  };
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={`Resize ${column.header} column`}
      aria-valuenow={width}
      aria-valuemin={minimumWidth(column)}
      tabIndex={0}
      title="Drag to resize column"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerEnd}
      onPointerCancel={onPointerEnd}
      onKeyDown={onKeyDown}
      onClick={(event) => event.stopPropagation()}
      className={cx(
        'absolute inset-y-0 -right-1 z-10 w-2 cursor-col-resize touch-none rounded-xs',
        'after:absolute after:inset-y-2 after:left-1/2 after:w-px after:-translate-x-1/2 after:bg-line-strong',
        'hover-or-demo:after:bg-accent',
      )}
    />
  );
}

function HeaderCell({
  column,
  sort,
  onSort,
  filtered,
  width,
  onResize,
  last,
}: {
  column: ExplorerColumn;
  sort: ExplorerSort;
  onSort: (key: string) => void;
  filtered: boolean;
  width: number;
  onResize: (width: number) => void;
  last: boolean;
}) {
  const direction = sort.key === column.key ? sort.direction : 'none';
  const ariaSort = direction === 'asc' ? 'ascending' : direction === 'desc' ? 'descending' : 'none';
  return (
    <th
      scope="col"
      role="columnheader"
      aria-sort={ariaSort}
      className="relative flex h-10 items-center border-b border-line bg-surface px-3 text-caption font-medium whitespace-nowrap text-ink-muted"
    >
      <button
        type="button"
        onClick={() => onSort(column.key)}
        className={cx(
          '-mx-1 inline-flex max-w-full items-center gap-1 rounded-xs px-1 hover-or-demo:text-ink',
          direction !== 'none' && 'text-ink',
        )}
      >
        {/* On a phone the Icon column is only as wide as an icon: its name is read, not shown. */}
        <span className={cx('truncate', 'phoneWidth' in column && 'max-sm:sr-only')}>{column.header}</span>
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
      {last ? null : <ColumnResizer column={column} width={width} onResize={onResize} />}
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
        'bg-surface text-title text-ink shadow-float-sm transition-colors hover-or-demo:border-line-hover',
      )}
    >
      ↑
    </button>
  );
}

export type ExplorerTableProps = {
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

// The 13 columns in a frame that scrolls both ways by itself: the header stays in
// view as the list scrolls, the sideways scrollbar is always within reach, and
// the page never scrolls sideways. Every row is in the page (find-in-page finds
// it), but each row is a grid on the one column template, not a table row, so
// the browser can skip laying out and painting the rows out of view
// (content-visibility, which table rows do not take): a filter that brings back
// all 517 rows lays out only those in view. The table roles are written out,
// since the display is not a table's. Widths are set through the CSSOM (the CSP
// refuses style attributes).
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
  const [widths, setWidths] = useState<number[]>(() => EXPLORER_COLUMNS.map((column) => column.width));
  const tableRef = useRef<HTMLTableElement>(null);

  useLayoutEffect(() => {
    const table = tableRef.current;
    if (!table) return;
    table.style.setProperty(COLUMNS_PROPERTY, widths.map((width) => `${width}px`).join(' '));
    table.style.width = `${widths.reduce((sum, width) => sum + width, 0)}px`;
  }, [widths]);

  // A phone has the narrower columns, and the table follows the window as it
  // narrows to a phone's width or widens from one (after hydration: the exported
  // page has the wide columns, and a width is in its markup). A width a person
  // set is kept.
  useLayoutEffect(() => {
    const phone = window.matchMedia(PHONE);
    const follow = (narrow: boolean) =>
      setWidths((current) =>
        current.map((width, index) => {
          const column = EXPLORER_COLUMNS[index];
          if (!('phoneWidth' in column)) return width;
          if (narrow && width === column.width) return column.phoneWidth;
          if (!narrow && width === column.phoneWidth) return column.width;
          return width;
        }),
      );
    if (phone.matches) follow(true);
    const onChange = (event: MediaQueryListEvent) => follow(event.matches);
    phone.addEventListener('change', onChange);
    return () => phone.removeEventListener('change', onChange);
  }, []);

  const resize = useCallback((index: number, width: number) => {
    setWidths((current) => {
      const next = [...current];
      [next[index]] = normaliseWidths([width], minimumWidth(EXPLORER_COLUMNS[index]));
      return next;
    });
  }, []);

  return (
    <div className="relative">
      <div
        ref={frameRef}
        data-mds-frame=""
        // Positioned, so what is absolutely placed inside (a cell's screen-reader
        // status) is clipped by the frame instead of widening the page.
        className="relative max-h-[calc(100dvh-var(--header-height)-2rem)] min-h-80 overflow-auto overscroll-x-contain rounded-md border border-line"
      >
        <table ref={tableRef} role="table" aria-label="FIDO MDS authenticators" className="block text-left text-body">
          <thead role="rowgroup" className="sticky top-0 z-10 block bg-surface">
            <tr role="row" className={ROW_GRID}>
              {EXPLORER_COLUMNS.map((column, index) => (
                <HeaderCell
                  key={column.key}
                  column={column}
                  sort={sort}
                  onSort={onSort}
                  filtered={filteredColumns.has(column.key)}
                  width={widths[index]}
                  onResize={(width) => resize(index, width)}
                  last={index === EXPLORER_COLUMNS.length - 1}
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
