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
};

const COLUMNS = {
  2: 'lg:grid-cols-2',
  3: 'lg:grid-cols-3',
  4: 'lg:grid-cols-4',
} as const;

// Labels and values as a description list: one column on a phone, two on a
// tablet, up to four on a wide screen. Separated by hairlines, not tiles.
export function KeyValueGrid({ items, columns = 3 }: { items: KeyValueItem[]; columns?: keyof typeof COLUMNS }) {
  return (
    <dl className={cx('grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2', COLUMNS[columns])}>
      {items.map((item) => (
        <div key={item.key} data-item={item.key} className="min-w-0 border-t border-line pt-3">
          <dt className="text-caption text-ink-muted">{item.label}</dt>
          <dd className="mt-1 min-w-0">
            <span
              data-role="value"
              className={cx(
                'block break-words text-ink',
                item.mono ? 'font-mono text-label' : 'text-body-lg font-semibold',
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
