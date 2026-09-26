import { useEffect, useRef } from 'react';

import { Button, buttonClassName } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/icons';
import { MonoValue } from '@/components/ui/MonoValue';

import { type MdsEntry, identifierName } from './model';

// An authenticator opened from the list (#mds/<entryId>). In Phase 27A it holds
// the entry's name and identifier; the full page (the metadata statement, status
// reports, certificates and raw data) comes to the new interface next, and until
// then the current interface has it.
export function EntryView({
  entryId,
  entry,
  loading,
  onBack,
}: {
  entryId: string;
  entry: MdsEntry | null;
  loading: boolean;
  onBack: () => void;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const found = Boolean(entry);

  // The heading takes the focus once there is one: at once, or when the list has loaded.
  useEffect(() => {
    headingRef.current?.focus({ preventScroll: true });
  }, [entryId, found, loading]);

  let body;
  if (entry) {
    const label = identifierName(entry);
    body = (
      <>
        <h3 ref={headingRef} tabIndex={-1} className="text-heading font-semibold break-words text-ink outline-none">
          {entry.name?.trim() || 'Authenticator'}
        </h3>
        <dl className="mt-4 grid max-w-3xl grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-[max-content_minmax(0,1fr)] sm:items-center">
          <dt className="text-label font-medium text-ink-muted">{label === 'key identifier' ? 'Key identifier' : label}</dt>
          <dd className="min-w-0">
            <MonoValue value={entry.id} label={label} />
          </dd>
        </dl>
        <div className="mt-8 flex max-w-2xl flex-col gap-4 rounded-lg border border-line p-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-body text-ink">
            The full page for this authenticator (its metadata statement, status reports, certificates and raw data) moves to
            the new interface next. It works as before in the current interface.
          </p>
          {/* A plain link: next/link would add the /beta base path. */}
          <a href="/" className={buttonClassName({ variant: 'secondary', size: 'sm' })}>
            Open the current interface
          </a>
        </div>
      </>
    );
  } else if (loading) {
    body = (
      <p className="flex items-center gap-2 text-body-lg text-ink-muted">
        <Spinner />
        Authenticator metadata is loading…
      </p>
    );
  } else {
    body = (
      <>
        <h3 ref={headingRef} tabIndex={-1} className="text-heading font-semibold text-ink outline-none">
          Authenticator not found
        </h3>
        <p className="mt-2 text-body-lg break-words text-ink-muted">
          No authenticator in the list has the identifier <code className="text-ink">{entryId}</code>.
        </p>
      </>
    );
  }

  return (
    <div data-mds-entry={entryId} className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none">
      <Button variant="secondary" size="sm" title="Return to authenticator list" onClick={onBack} icon={<span aria-hidden="true">←</span>}>
        Back
      </Button>
      <div className="mt-6">{body}</div>
    </div>
  );
}
