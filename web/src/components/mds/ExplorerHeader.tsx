import { formatEntryCount } from '@/logic/mds/explorer/status.js';

import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import type { ExplorerStatus } from './model';

const countText = formatEntryCount as (filtered: number, total: number) => { count: string; total: string };

const DOTS = {
  info: 'bg-accent',
  success: 'bg-success',
  error: 'bg-danger',
} as const;

// The count, as status.js words it: "Entries: 12 of 517 total".
export function EntryCount({ shown, total }: { shown: number; total: number }) {
  const text = countText(shown, total);
  return (
    <p className="text-body text-ink-muted tabular-nums" aria-live="polite" data-mds-count="">
      Entries: <span className="font-semibold text-ink">{text.count}</span>
      {text.total ? ` ${text.total}` : null}
    </p>
  );
}

// The line that says what the explorer is doing and what it loaded, with the
// snapshot's legal header as its tooltip, and Retry after a failure.
export function StatusLine({
  status,
  loading,
  failed,
  onRetry,
}: {
  status: ExplorerStatus;
  loading: boolean;
  failed: boolean;
  onRetry: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <p
        role="status"
        title={status.title || undefined}
        data-variant={status.variant}
        className={cx('flex min-w-0 items-start gap-2 text-body', status.variant === 'error' ? 'text-danger' : 'text-ink-muted')}
      >
        {loading ? (
          <span className="mt-0.5 shrink-0">
            <Spinner />
          </span>
        ) : (
          <span aria-hidden="true" className={cx('mt-[0.4375rem] size-2 shrink-0 rounded-full', DOTS[status.variant])} />
        )}
        <span className="min-w-0">{status.text}</span>
      </p>
      {failed ? (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
