import {
  type CertificateView,
  describeCertificate,
  normaliseCertificateBase64,
  requestCertificateDecode,
} from '@/logic/mds/explorer/certificate.js';
import { useCallback, useRef, useState } from 'react';

// The certificates decoded while the explorer is open, by their base64: POST /api/mds/decode-certificate once for each,
// and again only after a failure. A decode already running is shared.
export function useCertificateDecode() {
  const [views, setViews] = useState<ReadonlyMap<string, CertificateView>>(() => new Map());
  const known = useRef(new Map<string, CertificateView>());
  const running = useRef(new Map<string, Promise<CertificateView>>());

  const decode = useCallback((certificate: string) => {
    const cleaned = normaliseCertificateBase64(certificate);
    const done = known.current.get(cleaned);
    if (done && !done.failed) return Promise.resolve(done);
    const pending = running.current.get(cleaned);
    if (pending) return pending;
    const request = requestCertificateDecode(cleaned)
      .then(
        (details) => describeCertificate({ details }),
        (error: unknown) => describeCertificate({ error }),
      )
      .then((view) => {
        running.current.delete(cleaned);
        known.current.set(cleaned, view);
        setViews(new Map(known.current));
        return view;
      });
    running.current.set(cleaned, request);
    return request;
  }, []);

  const viewFor = useCallback((certificate: string) => views.get(normaliseCertificateBase64(certificate)) ?? null, [views]);

  return { decode, viewFor };
}
