import { ENTRY_LINK_MESSAGES } from '@legacy/advanced/mds/explorer/entry-link.js';
import { useEffect, useMemo, useRef, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/icons';

import { BackButton, EntryHeader } from './EntryHeader';
import { entrySections, rawData } from './entryModel';
import { EntrySections } from './EntrySections';
import { RawEntryDialog } from './RawEntryDialog';
import type { EntryDetail } from './useEntryDetail';

type EntryPageProps = {
  entryId: string;
  detail: EntryDetail;
  onBack: () => void;
  onRetry: () => void;
  /** Opens a certificate's page (MdsSection gives it once it shows them). */
  onOpenCertificate?: (number: number, certificate: string) => void;
  busyCertificate?: number | null;
};

// An authenticator opened from the list or a link (#mds/<entryId>): everything
// the current page shows of it, in its order, as sections; and while it is not
// there yet, or cannot be, what the jump from a saved credential says.
export function EntryPage({ entryId, detail, onBack, onRetry, onOpenCertificate, busyCertificate = null }: EntryPageProps) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const rawButtonRef = useRef<HTMLButtonElement>(null);
  const [rawOpen, setRawOpen] = useState(false);
  const entry = detail.phase === 'found' ? detail.entry : null;
  const sections = useMemo(() => (entry ? entrySections(entry) : []), [entry]);
  const hasRaw = useMemo(() => Boolean(entry && rawData(entry)), [entry]);

  // The heading takes the focus once there is one: at once, or when the entry arrives.
  useEffect(() => {
    headingRef.current?.focus({ preventScroll: true });
  }, [entryId, detail.phase]);

  let body;
  if (detail.phase === 'found') {
    body = (
      <>
        <EntryHeader
          ref={headingRef}
          entry={detail.entry}
          hasRaw={hasRaw}
          onBack={onBack}
          onRaw={() => setRawOpen(true)}
          rawButtonRef={rawButtonRef}
        />
        <EntrySections
          sections={sections}
          entry={detail.entry}
          idBase="mds-entry"
          certificates={{ onOpen: onOpenCertificate, busy: busyCertificate }}
        />
        <RawEntryDialog entry={detail.entry} open={rawOpen} onClose={() => setRawOpen(false)} returnFocusTo={() => rawButtonRef.current} />
      </>
    );
  } else if (detail.phase === 'waiting' || detail.phase === 'resolving') {
    body = (
      <>
        <BackButton onBack={onBack} title="Return to authenticator list" />
        <p role="status" className="mt-6 flex items-center gap-2 text-body-lg text-ink-muted">
          <Spinner />
          {detail.phase === 'waiting' ? ENTRY_LINK_MESSAGES.opening : ENTRY_LINK_MESSAGES.locating}
        </p>
      </>
    );
  } else if (detail.phase === 'missing' || detail.phase === 'failed') {
    const failed = detail.phase === 'failed';
    body = (
      <>
        <BackButton onBack={onBack} title="Return to authenticator list" />
        <h3 ref={headingRef} tabIndex={-1} className="mt-6 text-heading font-semibold text-ink outline-none">
          {failed ? ENTRY_LINK_MESSAGES.failed : ENTRY_LINK_MESSAGES.notFound}
        </h3>
        {detail.message ? (
          <p role="alert" className={failed ? 'mt-2 text-body-lg text-danger' : 'mt-2 text-body-lg text-ink-muted'}>
            {detail.message}
          </p>
        ) : null}
        <p className="mt-2 text-body break-words text-ink-muted">
          <code className="font-mono text-label text-ink">{entryId}</code>
        </p>
        {failed ? (
          <Button variant="secondary" size="sm" className="mt-4" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </>
    );
  }

  return (
    <div data-mds-entry={entryId} className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none">
      {body}
    </div>
  );
}
