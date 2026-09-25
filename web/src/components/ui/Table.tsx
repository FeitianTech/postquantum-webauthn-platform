import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react';

import { cx } from '@/lib/cx';

import { ChevronDownIcon } from './icons';

type Strip<T> = Omit<T, 'style'>;

// A table that scrolls sideways inside its own frame, so the page never does.
// White header, hairlines between rows, compact left-aligned cells.
export function Table({ caption, className, children }: { caption?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <div className={cx('w-full min-w-0 overflow-x-auto rounded-md border border-line', className)}>
      <table className="w-full border-collapse text-left text-body">
        {caption ? <caption className="sr-only">{caption}</caption> : null}
        {children}
      </table>
    </div>
  );
}

export function THead({ sticky = false, children }: { sticky?: boolean; children: ReactNode }) {
  return <thead className={cx('bg-surface', sticky && 'sticky top-0 z-10')}>{children}</thead>;
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

export function Tr({ className, children, ...props }: Strip<HTMLAttributes<HTMLTableRowElement>>) {
  return (
    <tr className={cx('border-b border-line last:border-b-0 [tbody>&]:hover-or-demo:bg-accent-tint', className)} {...props}>
      {children}
    </tr>
  );
}

type Sort = 'ascending' | 'descending' | 'none';

type ThProps = Strip<ThHTMLAttributes<HTMLTableCellElement>> & {
  /** Makes the header a sort button; aria-sort says the current order. */
  sort?: Sort;
  onSort?: () => void;
};

export function Th({ sort, onSort, className, children, ...props }: ThProps) {
  const label = (
    <span className="inline-flex items-center gap-1">
      {children}
      {sort && sort !== 'none' ? (
        <ChevronDownIcon size={12} className={cx('text-accent', sort === 'ascending' && 'rotate-180')} />
      ) : null}
    </span>
  );
  return (
    <th
      scope="col"
      aria-sort={sort}
      className={cx('h-9 border-b border-line px-3 text-caption font-medium whitespace-nowrap text-ink-muted', className)}
      {...props}
    >
      {onSort ? (
        <button type="button" onClick={onSort} className="-mx-1 rounded-xs px-1 hover-or-demo:text-ink">
          {label}
        </button>
      ) : (
        label
      )}
    </th>
  );
}

type TdProps = Strip<TdHTMLAttributes<HTMLTableCellElement>> & { mono?: boolean; truncate?: boolean };

export function Td({ mono = false, truncate = false, className, children, ...props }: TdProps) {
  return (
    <td
      className={cx(
        'px-3 py-2 align-middle text-ink',
        mono && 'font-mono text-label',
        truncate && 'max-w-64 truncate',
        className,
      )}
      {...props}
    >
      {children}
    </td>
  );
}
