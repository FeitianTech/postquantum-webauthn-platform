import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';

import type { SectionRoute } from '@/lib/useSection';

import { CertificatePage } from './CertificatePage';
import { cleanCertificate, entrySections } from './entryModel';
import { EntryPage } from './EntryPage';
import type { MdsEntry } from './model';
import { useCertificateDecode } from './useCertificateDecode';
import { useEntryDetail } from './useEntryDetail';
import type { ExplorerPhase } from './useMdsExplorer';

const CERTIFICATE_NUMBER = /^[1-9]\d*$/;

// What #mds/<entryId>… shows: the entry's page, and over it one of its
// certificates (…/certificate/<n>). The entry's page stays in the page under a
// certificate, and Back finds it where it was, the focus on that certificate's
// button. A path this page does not know (a certificate the entry does not have,
// another word) shows the entry, and the URL says so.
export function EntryRouter({ route, entries, phase }: { route: SectionRoute; entries: MdsEntry[]; phase: ExplorerPhase }) {
  const [entryId = '', kind, numberText = ''] = route.path;
  const { detail, retry } = useEntryDetail(entryId, entries, phase);
  const { decode, viewFor } = useCertificateDecode();
  const [busy, setBusy] = useState<number | null>(null);
  const entryScroll = useRef(0);
  // The entry shown now ('' once the page has gone): a decode that ends later opens nothing.
  const current = useRef(entryId);
  current.current = entryId;
  useEffect(
    () => () => {
      current.current = '';
    },
    [],
  );

  const entry = detail.phase === 'found' ? detail.entry : null;
  const certificates = useMemo(
    () => (entry ? (entrySections(entry).find((section) => section.certificates)?.certificates ?? []) : []),
    [entry],
  );
  const wanted = kind === 'certificate' && route.path.length === 3 && CERTIFICATE_NUMBER.test(numberText) ? Number(numberText) : null;
  const certificate = certificates.find((candidate) => candidate.number === wanted && cleanCertificate(candidate.certificate)) ?? null;
  const unknownPath = route.path.length > 1 && Boolean(entry) && !certificate;
  const { replace, open, close } = route;

  useEffect(() => {
    if (unknownPath) replace([entryId]);
  }, [unknownPath, replace, entryId]);

  const openCertificate = useCallback(
    async (number: number, value: string) => {
      if (!cleanCertificate(value)) return;
      entryScroll.current = window.scrollY;
      setBusy(number);
      await decode(value);
      setBusy(null);
      if (current.current === entryId) open([entryId, 'certificate', String(number)]);
    },
    [decode, open, entryId],
  );

  // Opening a certificate starts at the top; leaving it finds the entry as it was.
  const shown = certificate?.number ?? null;
  const previous = useRef<number | null>(null);
  useLayoutEffect(() => {
    const left = previous.current;
    previous.current = shown;
    if (shown) {
      window.scrollTo({ top: 0 });
      return;
    }
    if (left === null) return;
    window.scrollTo({ top: entryScroll.current });
    entryScroll.current = 0;
    document.querySelector<HTMLElement>(`[data-mds-entry] [data-certificate="${left}"]`)?.focus({ preventScroll: true });
  }, [shown]);

  const shownCertificate = certificate?.certificate ?? '';
  const decodeShown = useCallback(() => {
    void decode(shownCertificate);
  }, [decode, shownCertificate]);

  return (
    <>
      <div hidden={Boolean(certificate)}>
        <EntryPage
          entryId={entryId}
          detail={detail}
          onBack={() => close()}
          onRetry={retry}
          onOpenCertificate={openCertificate}
          busyCertificate={busy}
          active={!certificate}
        />
      </div>
      {entry && certificate ? (
        <CertificatePage
          entry={entry}
          certificate={certificate}
          view={viewFor(certificate.certificate)}
          onDecode={decodeShown}
          onBack={() => close([entryId])}
        />
      ) : null}
    </>
  );
}
