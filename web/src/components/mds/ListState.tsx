import type { ReactNode } from 'react';

import { Spinner } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

// What the table shows in place of rows: the list loading, no snapshot, a
// failure, or no row matching the filters.
export function ListState({
  tone = 'muted',
  busy = false,
  children,
  action,
}: {
  tone?: 'muted' | 'danger';
  busy?: boolean;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      data-mds-state=""
      className="flex max-w-prose flex-col items-start gap-3 px-3 py-10"
    >
      <p className={cx('flex items-start gap-2 text-body-lg', tone === 'danger' ? 'text-danger' : 'text-ink-muted')}>
        {busy ? (
          <span className="mt-1 shrink-0">
            <Spinner />
          </span>
        ) : null}
        <span>{children}</span>
      </p>
      {action}
    </div>
  );
}
