import type { ExplorerSort } from '@/logic/mds/explorer/filter-sort.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { type ReactNode, type RefObject, useEffect, useRef, useState } from 'react';

import { ChevronDownIcon } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { ExplorerRow } from './ExplorerRow';
import { ROW_GRID } from './grid';
import { EXPLORER_COLUMNS, type ExplorerColumn } from './columns';

// A header: a line of the row's two, over its cells.
const HEAD = 'min-w-0 px-3 text-caption leading-5 font-medium whitespace-nowrap text-ink-muted max-md:*:invisible';

// About five rows.
const BACK_TO_TOP_AFTER = 320;

// A header no width shows takes none of a header's padding.
const hiddenAlways = (column: ExplorerColumn) => column.head.startsWith('sr-only');

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
      // Its name, read where the header is hidden with its button.
      aria-label={filtered ? `${column.header} (filtered)` : column.header}
      className={hiddenAlways(column) ? column.head : cx(HEAD, column.head)}
    >
      <button
        type="button"
        onClick={() => onSort(column.key)}
        className={cx(
          '-mx-1 inline-flex max-w-full items-center gap-1 rounded-xs px-1 hover:text-ink',
          direction !== 'none' && 'text-ink',
        )}
      >
        <span className="truncate">{column.header}</span>
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

// Floats over the list's lower right once the window has scrolled this far into
// it; takes the page back to its top. Held at the window's bottom by a sticky
// line after the table (an entering section is a transform, which a fixed
// position would be measured from).
function BackToTop({ tableRef }: { tableRef: RefObject<HTMLTableElement | null> }) {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    // The table of a list that is not shown has no place: its top reads 0.
    const onScroll = () => setShown(tableRef.current!.getBoundingClientRect().top < -BACK_TO_TOP_AFTER);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, [tableRef]);

  if (!shown) return null;
  const toTop = () => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: 0, behavior: reduced ? 'auto' : 'smooth' });
  };
  return (
    <div className="sticky bottom-4 z-20 h-0">
      <button
        type="button"
        aria-label="Back to top of the authenticator list"
        title="Back to top"
        onClick={toTop}
        className={cx(
          'absolute right-2 bottom-0 inline-flex size-11 items-center justify-center rounded-full border border-line',
          'bg-surface text-title text-ink shadow-float-sm transition-colors hover:border-line-hover',
        )}
      >
        ↑
      </button>
    </div>
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
};

// The list, scrolled by the page: every row fits the page's width in two lines
// (grid.ts), under a header row that mirrors them and stays under the site's
// header as the page scrolls. All 14 columns are in every row and in the header,
// in order, for a screen reader; the ones the window has no room for are hidden
// until their row is expanded. Every row is in the page (find-in-page finds it),
// but each is a grid, not a table row, so the browser can skip laying out and
// painting the rows out of view (content-visibility, which table rows do not
// take). The table roles are written out, since the display is not a table's.
export function ExplorerTable({ rows, shown, sort, onSort, filteredColumns, expanded, onToggle, onOpen, state }: ExplorerTableProps) {
  const tableRef = useRef<HTMLTableElement>(null);

  return (
    <div data-mds-table="">
      <table ref={tableRef} role="table" aria-label="FIDO MDS authenticators" className="block text-left text-body">
        <thead role="rowgroup" className="sticky top-(--header-height) z-10 block border-b border-line bg-surface max-md:sr-only">
          <tr role="row" className={cx(ROW_GRID, 'py-1.5')}>
            {EXPLORER_COLUMNS.map((column) => (
              <HeaderCell key={column.key} column={column} sort={sort} onSort={onSort} filtered={filteredColumns.has(column.key)} />
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
      <BackToTop tableRef={tableRef} />
    </div>
  );
}
