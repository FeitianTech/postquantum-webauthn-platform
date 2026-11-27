import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { MISSING_CELL_TEXT, NO_ICON_TEXT, certificationParts, iconAltText, identifierLabel, statusParts } from '@/logic/mds/explorer/rows.js';
import { type MouseEvent, type ReactNode, memo, useEffect, useRef } from 'react';

import { Badge } from '@/components/ui/Badge';
import { CheckIcon, ChevronDownIcon, CopyIcon } from '@/components/ui/icons';
import { useToast } from '@/components/ui/Toast';
import { copyStatusText, selectContents, useCopy } from '@/components/ui/useCopy';
import { cx } from '@/lib/cx';
import { entryHashPath } from '@/lib/sections';

import { ROW_GRID } from './grid';
import { EXPLORER_COLUMNS, type ExplorerColumn, HIDDEN } from './columns';

const [ICON, NAME, PROTOCOL, CERTIFICATION, STATUS, ID] = EXPLORER_COLUMNS;
const LISTS = EXPLORER_COLUMNS.filter((column) => 'list' in column);
const DATE = EXPLORER_COLUMNS[EXPLORER_COLUMNS.length - 1];

// A line of an expanded row, under its two: the column's name beside its value
// (above it on a phone), in line with the name.
const LINE = 'col-[2/-1] flex gap-3 py-0.5 max-md:col-span-full max-md:flex-col max-md:gap-0 md:pl-10';
const CELL = 'min-w-0 px-3 leading-6';

// A cell. Collapsed: where its column puts it in the row's two lines, one line
// that ends in an ellipsis, or hidden where the window gives it no column.
// Expanded: every word, and a labelled line of its own if its column is a detail.
function Cell({
  column,
  expanded,
  title,
  className,
  children,
}: {
  column: ExplorerColumn;
  expanded: boolean;
  title?: string;
  className?: string;
  children: ReactNode;
}) {
  const line = expanded && column.detail;
  const shape = line ? cx(CELL, LINE) : column.cell === HIDDEN ? HIDDEN : cx('block', CELL, column.cell);
  return (
    <td
      role="cell"
      title={expanded ? undefined : title}
      className={cx(shape, expanded ? 'break-words whitespace-normal' : 'truncate whitespace-nowrap', className)}
    >
      {line ? (
        // Its header, for the eye: a screen reader has the column's own.
        <span aria-hidden="true" className="w-32 shrink-0 text-caption leading-6 text-ink-muted">
          {column.header}
        </span>
      ) : null}
      {children}
    </td>
  );
}

function SmallControl({ label, onClick, children, ...props }: { label: string; onClick: () => void; children: ReactNode; 'aria-expanded'?: boolean }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="inline-flex size-6 shrink-0 items-center justify-center rounded-full text-ink-muted transition-colors duration-(--duration-fast) hover:bg-accent-tint hover:text-accent-ink"
      {...props}
    >
      {children}
    </button>
  );
}

function IdCell({ entry, expanded }: { entry: MdsEntry; expanded: boolean }) {
  const toast = useToast();
  const { outcome, copy } = useCopy();
  const valueRef = useRef<HTMLElement>(null);
  const label = identifierLabel(entry);
  const onCopy = async () => {
    const copied = await copy(entry.id);
    if (!copied) selectContents(valueRef.current);
  };
  const shown = outcome.state === 'idle' ? null : copyStatusText(label, outcome);
  // The clipboard refused: say so where it is seen, and leave the value selected.
  useEffect(() => {
    if (outcome.state === 'failed') toast({ tone: 'danger', message: copyStatusText(label, outcome) });
  }, [outcome, label, toast]);
  return (
    <Cell column={ID} expanded={expanded}>
      {entry.id ? (
        <span className="flex items-center gap-1">
          {/* A whole AAGUID on one line; a longer identifier breaks only in an expanded row. */}
          <code ref={valueRef} className={expanded ? 'min-w-0 break-all' : 'min-w-0 truncate'}>
            {entry.id}
          </code>
          <SmallControl label={`Copy ${label}`} onClick={() => void onCopy()}>
            {outcome.state === 'copied' ? <CheckIcon size={13} className="text-success" /> : <CopyIcon size={13} />}
          </SmallControl>
          <span role="status" className="sr-only">
            {shown}
          </span>
        </span>
      ) : (
        MISSING_CELL_TEXT
      )}
    </Cell>
  );
}

// A list of values: comma-separated (on two lines where its column has them), or
// pills when the row is expanded.
function ListCell({ column, values, expanded }: { column: ExplorerColumn; values: string[]; expanded: boolean }) {
  if (!values.length) {
    return (
      <Cell column={column} expanded={expanded}>
        {MISSING_CELL_TEXT}
      </Cell>
    );
  }
  const joined = values.join(', ');
  return (
    <Cell column={column} expanded={expanded} title={joined}>
      {expanded ? (
        <span className="flex min-w-0 flex-1 flex-wrap gap-1 py-0.5">
          {/* A pill that wraps: a long value is never cut at the cell's edge. */}
          {values.map((value) => (
            <span
              key={value}
              className="max-w-full rounded-xs border border-line-strong px-2 py-px text-caption leading-5 font-medium break-words text-ink-muted"
            >
              {value}
            </span>
          ))}
        </span>
      ) : column.clamp ? (
        <span className="line-clamp-2 whitespace-normal">{joined}</span>
      ) : (
        joined
      )}
    </Cell>
  );
}

function CertificationCell({ entry, expanded }: { entry: MdsEntry; expanded: boolean }) {
  const { level, detail, tone } = certificationParts(entry);
  if (!entry.certification) {
    return (
      <Cell column={CERTIFICATION} expanded={expanded}>
        {MISSING_CELL_TEXT}
      </Cell>
    );
  }
  return (
    <Cell column={CERTIFICATION} expanded={expanded} title={entry.certification}>
      <span className={cx('flex min-w-0 flex-1 gap-2', expanded ? 'flex-wrap items-start' : 'items-center')}>
        <Badge tone={tone} className="mt-px">
          {level}
        </Badge>
        {detail ? <span className={cx('min-w-0 text-ink-muted', expanded ? null : 'truncate')}>{detail}</span> : null}
      </span>
    </Cell>
  );
}

function StatusCell({ entry, expanded }: { entry: MdsEntry; expanded: boolean }) {
  const { status, tone } = statusParts(entry);
  if (!entry.latestStatus) {
    return (
      <Cell column={STATUS} expanded={expanded}>
        {MISSING_CELL_TEXT}
      </Cell>
    );
  }
  return (
    <Cell column={STATUS} expanded={expanded} title={entry.latestStatus}>
      {/* At the top of its line, a pixel down: a badge set on the text's middle makes the line taller. */}
      <Badge tone={tone} className="mt-px align-top">
        {status}
      </Badge>
    </Cell>
  );
}

type RowProps = {
  entry: MdsEntry;
  hidden: boolean;
  expanded: boolean;
  onToggle: (entryId: string) => void;
  onOpen?: (entryId: string) => void;
};

// One authenticator, in two lines that fit the page: its name over its ID, and
// what the window has columns for. Expanded, every word, and a labelled line for
// each thing the two lines do not hold. A click anywhere in the row that is not on
// one of its controls or a text selection expands it, or collapses it; the name
// opens the entry (a link, so Enter works), and so does "Open entry", which an
// expanded row has whether or not it has a name.
export const ExplorerRow = memo(function ExplorerRow({ entry, hidden, expanded, onToggle, onOpen }: RowProps) {
  const name = entry.name?.trim() ? entry.name : '';
  const called = name || entry.id || entry.entryId;
  const href = `#${entryHashPath(entry.entryId)}`;
  const onRowClick = (event: MouseEvent<HTMLTableRowElement>) => {
    if ((event.target as HTMLElement).closest('a, button')) return;
    if (window.getSelection()?.toString()) return;
    onToggle(entry.entryId);
  };
  const onLinkClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (!onOpen) return;
    event.preventDefault();
    onOpen(entry.entryId);
  };

  return (
    <tr
      role="row"
      hidden={hidden}
      data-entry-id={entry.entryId}
      aria-expanded={expanded}
      onClick={onRowClick}
      className={cx(
        ROW_GRID,
        'border-b border-line py-1.5 text-ink',
        // Out of view, a row is neither laid out nor painted: it keeps the size it last had,
        // and until it has one, its two lines' (three on a phone).
        '[contain-intrinsic-size:auto_3rem] [content-visibility:auto] max-md:[contain-intrinsic-size:auto_4.75rem]',
        'cursor-pointer transition-colors duration-(--duration-fast) hover:bg-accent-tint',
      )}
    >
      <Cell column={ICON} expanded={expanded}>
        {entry.icon ? (
          <img src={entry.icon} alt={iconAltText(entry)} loading="lazy" decoding="async" className="size-7 object-contain" />
        ) : (
          <span className="text-caption text-ink-faint">{NO_ICON_TEXT}</span>
        )}
      </Cell>
      <Cell column={NAME} expanded={expanded} title={name || undefined}>
        <span className="flex items-start gap-1">
          <SmallControl
            label={`${expanded ? 'Show less of' : 'Show all of'} ${called}`}
            aria-expanded={expanded}
            onClick={() => onToggle(entry.entryId)}
          >
            <ChevronDownIcon size={13} className={cx('transition-transform duration-(--duration-fast)', !expanded && '-rotate-90')} />
          </SmallControl>
          {name ? (
            <a
              href={href}
              data-entry-link={entry.entryId}
              onClick={onLinkClick}
              className={cx('min-w-0 text-ink no-underline hover:underline', expanded ? null : 'truncate')}
            >
              {name}
            </a>
          ) : (
            <span>{MISSING_CELL_TEXT}</span>
          )}
          {expanded ? (
            <a
              href={href}
              aria-label={`Open entry: ${called}`}
              onClick={onLinkClick}
              className="ml-auto shrink-0 pl-3 text-label font-medium whitespace-nowrap text-accent-ink no-underline hover:underline"
            >
              Open entry
            </a>
          ) : null}
        </span>
      </Cell>
      <Cell column={PROTOCOL} expanded={expanded}>
        {entry.protocol || MISSING_CELL_TEXT}
      </Cell>
      <CertificationCell entry={entry} expanded={expanded} />
      <StatusCell entry={entry} expanded={expanded} />
      <IdCell entry={entry} expanded={expanded} />
      {LISTS.map((column) => (
        <ListCell key={column.key} column={column} values={(entry[column.list] as string[] | undefined) ?? []} expanded={expanded} />
      ))}
      <Cell column={DATE} expanded={expanded} title={entry.dateTooltip}>
        {entry.dateUpdated ? <time dateTime={entry.dateTooltip}>{entry.dateUpdated}</time> : MISSING_CELL_TEXT}
      </Cell>
    </tr>
  );
});
