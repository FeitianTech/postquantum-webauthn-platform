import { useEffect, useRef } from 'react';

import { CodeBlock } from '@/components/ui/CodeBlock';
import { Spinner } from '@/components/ui/icons';
import { useEntrance } from '@/lib/entrance';

import { CertificateSummary } from './CertificateSummary';
import { CondensedBar } from './CondensedBar';
import { BackButton } from './EntryHeader';
import { type CertificateLink, type CertificateView, cleanCertificate, entryTitle } from './entryModel';
import type { MdsEntry } from './model';

// An attestation root certificate of an entry (#mds/<entryId>/certificate/<n>):
// its subject as the title and its issuer under it, its summary, then the
// certificate as given and the server's decoded output, each with copy. A
// failure is said where the summary would be, and in the decoded output, as the
// current page does. Reached from the entry's button, the decode is already
// there; by a link or a reload, the page asks for it.
export function CertificatePage({
  entry,
  certificate,
  view,
  onDecode,
  onBack,
}: {
  entry: MdsEntry;
  certificate: CertificateLink;
  view: CertificateView | null;
  onDecode: () => void;
  onBack: () => void;
}) {
  const entrance = useEntrance(true);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const backTitle = `Return to ${entryTitle(entry)}`;
  const idBase = `mds-certificate-${certificate.number}`;

  useEffect(() => {
    if (!view) onDecode();
  }, [view, onDecode]);

  useEffect(() => {
    headingRef.current?.focus({ preventScroll: true });
  }, [certificate.number, Boolean(view)]);

  if (!view) {
    return (
      <div data-mds-certificate={certificate.number}>
        <BackButton onBack={onBack} title={backTitle} />
        <p role="status" className="mt-6 flex items-center gap-2 text-body-lg text-ink-muted">
          <Spinner />
          Decoding {certificate.label.toLowerCase()}…
        </p>
      </div>
    );
  }

  return (
    <div data-mds-certificate={certificate.number} className={entrance}>
      <CondensedBar watch={headingRef} title={view.title} subtitle={view.subtitle} onBack={onBack} backTitle={backTitle} />
      <BackButton onBack={onBack} title={backTitle} />
      <h3 ref={headingRef} tabIndex={-1} className="mt-6 text-heading font-semibold break-words text-ink outline-none">
        {view.title}
      </h3>
      {view.subtitle ? <p className="mt-2 text-body-lg break-words text-ink-muted">{view.subtitle}</p> : null}

      <div className="mt-8">
        {view.summary ? (
          <CertificateSummary summary={view.summary} idBase={idBase} />
        ) : (
          <div role={view.failed ? 'alert' : undefined}>
            <p className={view.failed ? 'text-body-lg text-danger' : 'text-body-lg text-ink-muted'}>{view.message}</p>
            {view.reason ? <p className="mt-1 text-body text-danger">{view.reason}</p> : null}
          </div>
        )}
      </div>

      <div className="mt-10 grid grid-cols-1 gap-x-8 gap-y-8 xl:grid-cols-2">
        <section aria-labelledby={`${idBase}-raw`} className="min-w-0 border-t border-line pt-6">
          <h4 id={`${idBase}-raw`} className="text-title font-semibold text-ink">
            Raw
          </h4>
          <CodeBlock className="mt-4" value={cleanCertificate(certificate.certificate)} label="raw certificate" />
        </section>
        <section aria-labelledby={`${idBase}-decoded`} className="min-w-0 border-t border-line pt-6">
          <h4 id={`${idBase}-decoded`} className="text-title font-semibold text-ink">
            Decoded Output
          </h4>
          <CodeBlock className="mt-4" value={view.output} label="decoded certificate" />
        </section>
      </div>
    </div>
  );
}
