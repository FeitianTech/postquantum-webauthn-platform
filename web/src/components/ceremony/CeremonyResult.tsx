import { Fragment } from 'react';

import { AlertIcon } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { type CeremonyResultInput, describeResultPanel } from './model';

// What the server made of the last ceremony, under the tab's buttons: the
// signature counter and its verdict (and in the Advanced tab where the challenge
// came from). It stays until the next ceremony starts, unlike a toast, so a
// warning that an authenticator may have been cloned does not leave by itself.
// A warning is amber with a mark; otherwise white with a hairline. The live
// region is always in the page, so a screen reader hears it fill.
export function CeremonyResult({ result }: { result: CeremonyResultInput | null }) {
  const view = result ? describeResultPanel(result) : null;
  return (
    <div
      role="status"
      aria-live="polite"
      hidden={!view}
      data-ceremony-result=""
      data-verdict={view?.warning ? 'warning' : undefined}
      className={cx(
        'rounded-sm border px-4 py-3',
        view?.warning ? 'border-warning-line bg-warning-tint' : 'border-line bg-surface',
      )}
    >
      {view ? (
        <>
          <p className={cx('flex items-center gap-1.5 text-label font-semibold', view.warning ? 'text-warning' : 'text-ink')}>
            {view.warning ? <AlertIcon size={14} aria-hidden="true" /> : null}
            {view.title}
          </p>
          <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[max-content_minmax(0,1fr)]">
            {view.rows.map((row) => (
              <Fragment key={row.label}>
                <dt className="text-caption text-ink-muted sm:pt-px">{row.label}</dt>
                <dd className="text-body text-ink" data-row={row.label}>
                  {row.value !== null ? (
                    <>
                      <code className="font-mono text-label font-semibold">{row.value}</code>{' '}
                    </>
                  ) : null}
                  {row.text}
                  {row.after ? ` ${row.after}` : null}
                </dd>
              </Fragment>
            ))}
          </dl>
        </>
      ) : null}
    </div>
  );
}
