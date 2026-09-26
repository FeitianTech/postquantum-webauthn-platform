import { MISSING_CELL_TEXT, NO_ICON_TEXT, iconAltText } from '@legacy/advanced/mds/explorer/rows.js';
import { type MouseEvent, type ReactNode, memo, useEffect, useRef } from 'react';

import { Badge } from '@/components/ui/Badge';
import { CheckIcon, ChevronDownIcon, CopyIcon } from '@/components/ui/icons';
import { useToast } from '@/components/ui/Toast';
import { copyStatusText, selectContents, useCopy } from '@/components/ui/useCopy';
import { cx } from '@/lib/cx';
import { entryHashPath } from '@/lib/sections';

import { ROW_GRID } from './grid';
import { EXPLORER_COLUMNS, type MdsEntry, certificationBadge, identifierName } from './model';

const iconAlt = iconAltText as (entry: MdsEntry) => string;

// A cell: one line that ends in an ellipsis, or, with its row expanded, every word.
function Cell({ expanded, title, className, children }: { expanded: boolean; title?: string; className?: string; children: ReactNode }) {
  return (
    <td
      role="cell"
      title={expanded ? undefined : title}
      className={cx(
        'block min-w-0 border-b border-line px-3 py-1.5 text-ink',
        expanded ? 'break-words whitespace-normal' : 'truncate whitespace-nowrap',
        className,
      )}
    >
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
      className="inline-flex size-6 shrink-0 items-center justify-center rounded-full text-ink-muted transition-colors duration-(--duration-fast) hover-or-demo:bg-accent-tint hover-or-demo:text-accent-ink"
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
  const label = identifierName(entry);
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
    <Cell expanded={expanded} className="font-mono text-label">
      {entry.id ? (
        <span className="flex items-center gap-1">
          {/* A whole AAGUID on one line: never broken mid-UUID. */}
          <code ref={valueRef} className="min-w-0 truncate whitespace-nowrap">
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

// A list of values: comma-separated on one line, or pills when the row is expanded.
function ListCell({ values, expanded }: { values: string[]; expanded: boolean }) {
  if (!values.length) return <Cell expanded={expanded}>{MISSING_CELL_TEXT}</Cell>;
  const joined = values.join(', ');
  return (
    <Cell expanded={expanded} title={joined}>
      {expanded ? (
        <span className="flex flex-wrap gap-1 py-0.5">
          {/* A pill that wraps: a long value is never cut at the cell's edge. */}
          {values.map((value) => (
            <span
              key={value}
              className="max-w-full rounded-xs border border-line-strong px-2 py-px text-caption font-medium break-words text-ink-muted"
            >
              {value}
            </span>
          ))}
        </span>
      ) : (
        joined
      )}
    </Cell>
  );
}

function CertificationCell({ entry, expanded }: { entry: MdsEntry; expanded: boolean }) {
  const { level, detail, tone } = certificationBadge(entry);
  if (!entry.certification) return <Cell expanded={expanded}>{MISSING_CELL_TEXT}</Cell>;
  return (
    <Cell expanded={expanded} title={entry.certification}>
      <span className={cx('flex gap-2', expanded ? 'flex-wrap items-start' : 'items-center')}>
        <Badge tone={tone}>{level}</Badge>
        {detail ? <span className={cx('min-w-0 text-ink-muted', expanded ? null : 'truncate')}>{detail}</span> : null}
      </span>
    </Cell>
  );
}

export type RowProps = {
  entry: MdsEntry;
  hidden: boolean;
  expanded: boolean;
  onToggle: (entryId: string) => void;
  onOpen?: (entryId: string) => void;
};

// One authenticator: compact, left-aligned, one line until expanded. The name
// opens the entry (a link, so Enter works), and so does a click anywhere else in
// the row that is not on one of its controls or a text selection.
export const ExplorerRow = memo(function ExplorerRow({ entry, hidden, expanded, onToggle, onOpen }: RowProps) {
  const name = entry.name?.trim() ? entry.name : '';
  const open = onOpen ? () => onOpen(entry.entryId) : undefined;
  const onRowClick = (event: MouseEvent<HTMLTableRowElement>) => {
    if (!open || (event.target as HTMLElement).closest('a, button')) return;
    if (window.getSelection()?.toString()) return;
    open();
  };
  const lists = EXPLORER_COLUMNS.filter((column) => 'list' in column);

  return (
    <tr
      role="row"
      hidden={hidden}
      data-entry-id={entry.entryId}
      aria-expanded={expanded}
      onClick={onRowClick}
      className={cx(
        ROW_GRID,
        // Out of view, a row is neither laid out nor painted; it keeps the size it last had.
        '[contain-intrinsic-size:auto_2.5625rem] [content-visibility:auto]',
        'transition-colors duration-(--duration-fast)',
        open && 'cursor-pointer hover-or-demo:bg-accent-tint',
      )}
    >
      <Cell expanded={expanded} className="py-1 max-sm:px-2">
        {entry.icon ? (
          <img src={entry.icon} alt={iconAlt(entry)} loading="lazy" decoding="async" className="size-7 object-contain" />
        ) : (
          <span className="text-caption text-ink-faint">{NO_ICON_TEXT}</span>
        )}
      </Cell>
      <Cell expanded={expanded} title={name || undefined}>
        <span className="flex items-start gap-1">
          <SmallControl
            label={`${expanded ? 'Show less of' : 'Show all of'} ${name || entry.id || entry.entryId}`}
            aria-expanded={expanded}
            onClick={() => onToggle(entry.entryId)}
          >
            <ChevronDownIcon size={13} className={cx('transition-transform duration-(--duration-fast)', !expanded && '-rotate-90')} />
          </SmallControl>
          {name ? (
            <a
              href={`#${entryHashPath(entry.entryId)}`}
              data-entry-link={entry.entryId}
              onClick={(event) => {
                if (!open) return;
                event.preventDefault();
                open();
              }}
              className={cx('min-w-0 pt-0.5 font-medium text-ink no-underline hover-or-demo:underline', expanded ? null : 'truncate')}
            >
              {name}
            </a>
          ) : (
            <span className="pt-0.5">{MISSING_CELL_TEXT}</span>
          )}
        </span>
      </Cell>
      <Cell expanded={expanded}>{entry.protocol || MISSING_CELL_TEXT}</Cell>
      <CertificationCell entry={entry} expanded={expanded} />
      <IdCell entry={entry} expanded={expanded} />
      {lists.map((column) => (
        <ListCell key={column.key} values={(entry[column.list] as string[] | undefined) ?? []} expanded={expanded} />
      ))}
      <Cell expanded={expanded} title={entry.dateTooltip}>
        {entry.dateUpdated ? <time dateTime={entry.dateTooltip}>{entry.dateUpdated}</time> : MISSING_CELL_TEXT}
      </Cell>
    </tr>
  );
});
