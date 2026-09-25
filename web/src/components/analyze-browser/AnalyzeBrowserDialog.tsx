import { copyReport } from '@legacy/shared/browser/report.js';
import { AUTHENTICATOR_FACTS, WEBAUTHN_FACTS } from '@legacy/shared/browser/webauthn-facts.js';
import { type ReactNode, useRef } from 'react';
import { flushSync } from 'react-dom';

import { ANALYZE_PANEL_ID } from '@/components/shell/Header';
import { Button } from '@/components/ui/Button';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';
import { cx } from '@/lib/cx';

import { ClientCapabilities } from './ClientCapabilities';
import { FactList } from './FactList';
import { IdentitySummary } from './IdentitySummary';
import type { Analysis, ClientCapabilities as CapabilitiesAnswer, Fact } from './types';

export type CopyResult = { copied: boolean; message: string; text: string };

type AnalyzeBrowserDialogProps = {
  open: boolean;
  onClose: () => void;
  analysis: Analysis | null;
  returnFocusTo: () => HTMLElement | null;
  /** The last copy's outcome; it stays until the next copy, across closing and reopening. */
  copy: CopyResult | null;
  onCopied: (result: CopyResult) => void;
};

function PanelSection({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="border-t border-line pt-5">
      <h3 id={id} className="text-title-sm font-semibold text-ink">
        {title}
      </h3>
      <div className="mt-2">{children}</div>
    </section>
  );
}

// The Analyze Browser panel: what the browser says about itself and about
// WebAuthn, each answer with where it came from, or why there is none. The
// answers and their words come from the logic modules in
// frontend/static/scripts/shared/browser; docs/ui-parity/analyze-browser.md maps
// every item of the current panel to this one.
export function AnalyzeBrowserDialog({ open, onClose, analysis, returnFocusTo, copy, onCopied }: AnalyzeBrowserDialogProps) {
  const reportRef = useRef<HTMLTextAreaElement>(null);

  const onCopy = async () => {
    if (!analysis) return;
    const result: CopyResult = await copyReport(analysis);
    flushSync(() => onCopied(result));
    if (!result.copied) {
      reportRef.current?.focus();
      reportRef.current?.select();
    }
  };

  const facts = analysis?.webauthn.facts as Record<string, Fact> | undefined;
  const capabilities = analysis?.webauthn.clientCapabilities as CapabilitiesAnswer | undefined;

  return (
    <Dialog
      id={ANALYZE_PANEL_ID}
      open={open}
      onClose={onClose}
      labelledBy="analyze-browser-heading"
      returnFocusTo={returnFocusTo}
    >
      <OverlayHeader
        titleId="analyze-browser-heading"
        title="Browser Analysis"
        closeLabel="Close browser analysis"
        onClose={onClose}
        actions={
          <Button variant="secondary" size="sm" onClick={onCopy}>
            Copy report
          </Button>
        }
      />
      <OverlayBody className="flex flex-col gap-6">
        {/* The live region is always there (empty until the first copy), so the
            outcome is announced; empty, it takes no room. */}
        <p
          role="status"
          aria-live="polite"
          data-role="copy-status"
          data-outcome={copy ? (copy.copied ? 'copied' : 'failed') : undefined}
          className={cx('text-label', !copy && 'sr-only', copy?.copied === false ? 'text-danger' : 'text-success')}
        >
          {copy?.message ?? ''}
        </p>
        <textarea
          ref={reportRef}
          data-role="report-text"
          data-text-field=""
          aria-label="Browser analysis report, as JSON"
          rows={10}
          readOnly
          hidden={copy?.copied !== false}
          value={copy?.copied === false ? copy.text : ''}
          className="block w-full resize-y rounded-sm border border-line-strong bg-surface px-3 py-2.5 font-mono text-[0.78125rem] leading-[1.65] text-ink outline-none"
        />
        {analysis && facts && capabilities ? (
          <>
            <IdentitySummary identity={analysis.identity} />
            <PanelSection id="analyze-browser-webauthn-heading" title="WebAuthn">
              <FactList definitions={WEBAUTHN_FACTS} facts={facts} />
            </PanelSection>
            <PanelSection id="analyze-browser-capabilities-heading" title="Client capabilities">
              <p className="mb-2 text-label text-ink-muted">
                What <code>PublicKeyCredential.getClientCapabilities()</code> returned (WebAuthn Level 3).
              </p>
              <ClientCapabilities answer={capabilities} />
            </PanelSection>
            <PanelSection id="analyze-browser-authenticators-heading" title="Authenticators">
              <FactList definitions={AUTHENTICATOR_FACTS} facts={facts} />
              <p className="mt-2 text-label text-ink-muted">
                A web page cannot ask which authenticator transports a browser supports. USB, NFC and Bluetooth security
                keys are handled by the browser and the operating system and cannot be detected here; the only way to
                know is to try one.
              </p>
            </PanelSection>
            <PanelSection id="analyze-browser-pqc-heading" title="Post-quantum">
              <p className="text-label text-ink-muted">
                The browser passes the algorithms a site offers on to the authenticator, ML-DSA included (COSE -48
                ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87). Whether a credential uses ML-DSA depends on the authenticator,
                and only a registration can show it: offer ML-DSA in the Advanced Authentication tab and read the new
                credential&apos;s algorithm.
              </p>
            </PanelSection>
          </>
        ) : null}
      </OverlayBody>
    </Dialog>
  );
}
