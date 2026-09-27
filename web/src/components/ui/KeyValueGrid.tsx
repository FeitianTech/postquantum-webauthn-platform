import type { ReactNode } from 'react';

import { cx } from '@/lib/cx';

export type KeyValueItem = {
  /** Stable key, also written to data-item for tests and styling. */
  key: string;
  label: ReactNode;
  value: ReactNode;
  /** A line under the value, such as where it came from. */
  hint?: ReactNode;
  mono?: boolean;
  /** Running text rather than a figure: regular weight. */
  plain?: boolean;
  /** Takes the whole row: long text wraps across the grid's width. */
  wide?: boolean;
  /**
   * An identifier (an AAGUID, a key identifier) that must fit on its line: the
   * whole row below 1024 px, two columns below 1280 px, one from there, where a
   * column holds a whole AAGUID and its copy button.
   */
  identifier?: boolean;
};

const COLUMNS = {
  2: 'lg:grid-cols-2',
  3: 'lg:grid-cols-3',
  4: 'lg:grid-cols-4',
} as const;

// Labels and values as a description list: one column on a phone, two on a
// tablet, up to four on a wide screen. Separated by space, not tiles or lines.
export function KeyValueGrid({ items, columns = 3 }: { items: KeyValueItem[]; columns?: keyof typeof COLUMNS }) {
  return (
    <dl className={cx('grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2', COLUMNS[columns])}>
      {items.map((item) => (
        <div
          key={item.key}
          data-item={item.key}
          className={cx('min-w-0', item.wide ? 'col-span-full' : item.identifier && 'sm:col-span-2 wide:col-span-1')}
        >
          <dt className="text-caption text-ink-muted">{item.label}</dt>
          <dd className="mt-1 min-w-0">
            <span
              data-role="value"
              className={cx(
                'block break-words text-ink',
                item.mono ? 'font-mono text-label' : item.plain ? 'text-body-lg' : 'text-body-lg font-semibold',
              )}
            >
              {item.value}
            </span>
            {item.hint ? (
              <span data-role="hint" className="mt-0.5 block text-caption text-ink-muted">
                {item.hint}
              </span>
            ) : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}
