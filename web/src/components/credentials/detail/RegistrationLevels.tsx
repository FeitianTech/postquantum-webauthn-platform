import type { ReactNode } from 'react';

import { AttestationFindings } from '@/components/ceremony/AttestationFindings';
import { DecodeInCodec } from '@/components/codec/DecodeInCodec';
import { CertificateSummary } from '@/components/mds/CertificateSummary';
import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { type AttestationView, type CertificateView, REGISTRATION_TEXT } from '@/logic/credentials/registration/describe.js';
import { type RegistrationView } from '@/logic/credentials/registration/view.js';
import type { CodecPayloads } from '@/logic/credentials/detail/codec-payloads.js';
import { certificateSummary } from '@/logic/mds/explorer/certificate.js';
import { type AttestationFindings as Findings, FINDINGS_TITLE, hasFindings } from '@/logic/shared/registration-findings.js';

import { DetailSection } from './DetailSections';

/** What each level hands the Codec, and what it is told when one of its parts leaves for it. */
export type CodecLinks = { payloads: CodecPayloads; onLeave: (part: string, button: HTMLElement) => void };

// A part's heading with its way into the Codec beside it.
function PartHeading({ children, part, payload, codec }: { children: ReactNode; part: string; payload: string; codec: CodecLinks }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
      {children}
      <DecodeInCodec part={part} payload={payload} onLeave={(button) => codec.onLeave(part, button)} />
    </div>
  );
}

function Placeholder({ text }: { text: string }) {
  return <p className="text-body text-ink-muted italic">{text}</p>;
}

function Failure({ text }: { text: string }) {
  return (
    <p role="alert" className="text-body text-danger [overflow-wrap:anywhere]">
      {text}
    </p>
  );
}

function Attestation({
  attestation,
  idBase,
  onCertificate,
  onAuthenticatorData,
  codec,
}: {
  attestation: AttestationView;
  idBase: string;
  onCertificate: (number: number) => void;
  onAuthenticatorData: () => void;
  codec: CodecLinks;
}) {
  const { body } = attestation;
  return (
    <DetailSection id={`${idBase}-attestation`} title={REGISTRATION_TEXT.attestationTitle}>
      <div>
        <PartHeading part="attestation object" payload={codec.payloads.attestationObject} codec={codec}>
          {/* A heading of its own (the recorded specs split the words there). */}
          <h5 className="min-w-0 text-title-sm font-semibold text-ink" data-recorded-heading="">
            {REGISTRATION_TEXT.attestationObject}
          </h5>
        </PartHeading>
        <div className="mt-2">
          {body.kind === 'json' ? (
            <CodeBlock value={body.text} label="attestation object" />
          ) : body.kind === 'error' ? (
            <Failure text={body.text} />
          ) : (
            <Placeholder text={body.text} />
          )}
        </div>
      </div>
      {attestation.certificates.length || attestation.hasAuthenticatorData ? (
        <ul className="flex flex-wrap gap-2">
          {attestation.certificates.map((certificate) => (
            <li key={certificate.index}>
              <Button
                variant="secondary"
                size="sm"
                data-level-open={`certificate-${certificate.index + 1}`}
                onClick={() => onCertificate(certificate.index + 1)}
              >
                {certificate.title}
              </Button>
            </li>
          ))}
          {attestation.hasAuthenticatorData ? (
            <li>
              <Button variant="secondary" size="sm" data-level-open="authenticator-data" onClick={onAuthenticatorData}>
                {REGISTRATION_TEXT.authenticatorData}
              </Button>
            </li>
          ) : null}
        </ul>
      ) : null}
      {attestation.certificateMessage ? <Placeholder text={attestation.certificateMessage} /> : null}
      {attestation.authenticatorError ? <Failure text={attestation.authenticatorError} /> : null}
    </DetailSection>
  );
}

/**
 * The registration's level: the attestation's findings in words, when the
 * record keeps any (the section's title at once, its list once the list's
 * chunk has arrived), the browser's response and its client data, what the
 * server made of it, and the attestation, whose certificates and authenticator
 * data open levels of their own.
 */
export function RegistrationLevel({
  registration,
  findings,
  idBase,
  onCertificate,
  onAuthenticatorData,
  codec,
}: {
  registration: RegistrationView;
  findings: Findings;
  idBase: string;
  onCertificate: (number: number) => void;
  onAuthenticatorData: () => void;
  codec: CodecLinks;
}) {
  const { response } = registration;
  // The level starts under the dialog's header: its first section needs no hairline.
  return (
    <div className="space-y-8 [&>section:first-child]:border-t-0 [&>section:first-child]:pt-0">
      {hasFindings(findings) ? (
        <DetailSection id={`${idBase}-findings`} title={FINDINGS_TITLE}>
          <AttestationFindings findings={findings} titled={false} />
        </DetailSection>
      ) : null}
      <DetailSection id={`${idBase}-response`} title={REGISTRATION_TEXT.responseTitle}>
        <ol className="list-decimal space-y-5 pl-5 marker:text-ink-muted">
          <li className="min-w-0 pl-1">
            <PartHeading part="response" payload={codec.payloads.response} codec={codec}>
              <h5 className="min-w-0 text-title-sm font-semibold text-ink">{REGISTRATION_TEXT.createResponse}</h5>
            </PartHeading>
            <div className="mt-2">
              {response.credential ? (
                <CodeBlock value={response.credential} label="registration response" />
              ) : (
                <Placeholder text={REGISTRATION_TEXT.noCredentialResponse} />
              )}
            </div>
          </li>
          <li className="min-w-0 pl-1">
            <PartHeading part="client data" payload={codec.payloads.clientDataJSON} codec={codec}>
              <h5 className="min-w-0 text-title-sm font-semibold text-ink">{REGISTRATION_TEXT.parsedClientData}</h5>
            </PartHeading>
            <div className="mt-2">
              {response.clientData ? (
                <CodeBlock value={response.clientData} label="client data" />
              ) : (
                <Placeholder text={REGISTRATION_TEXT.noClientData} />
              )}
            </div>
          </li>
        </ol>
      </DetailSection>
      <DetailSection id={`${idBase}-server`} title={REGISTRATION_TEXT.serverDataTitle}>
        {response.relyingParty ? (
          <CodeBlock value={response.relyingParty} label="server-retrieved data" />
        ) : (
          <Placeholder text={REGISTRATION_TEXT.noRelyingParty} />
        )}
      </DetailSection>
      {registration.attestation ? (
        <Attestation
          attestation={registration.attestation}
          idBase={idBase}
          onCertificate={onCertificate}
          onAuthenticatorData={onAuthenticatorData}
          codec={codec}
        />
      ) : null}
    </div>
  );
}

/**
 * An attestation certificate's level, in the MDS certificate page's
 * language: its subject and issuer, its summary, then the certificate's text,
 * or why there is none.
 */
export function CertificateLevel({
  view,
  idBase,
  payload,
  codec,
}: {
  view: CertificateView;
  idBase: string;
  payload: string;
  codec: CodecLinks;
}) {
  const summary = certificateSummary(view.details);
  const subject = typeof view.details.subject === 'string' ? view.details.subject.trim() : '';
  const issuer = typeof view.details.issuer === 'string' ? view.details.issuer.trim() : '';
  return (
    <div className="space-y-8">
      {subject || issuer || summary ? (
        <div data-certificate-summary="" className="space-y-6">
          {subject ? (
            <h4 className="text-title font-semibold break-words text-ink" data-certificate-subject="">
              {subject}
            </h4>
          ) : null}
          {issuer ? <p className="-mt-4 text-body-lg break-words text-ink-muted">{issuer}</p> : null}
          {summary ? <CertificateSummary summary={summary} idBase={idBase} /> : null}
        </div>
      ) : null}
      {payload ? (
        <div>
          <DecodeInCodec part="certificate" payload={payload} onLeave={(button) => codec.onLeave('certificate', button)} />
        </div>
      ) : null}
      {view.text ? (
        <DetailSection id={`${idBase}-text`} title="Decoded Output">
          <CodeBlock value={view.text} label="certificate text" />
        </DetailSection>
      ) : view.error ? (
        <Failure text={view.error} />
      ) : (
        <Placeholder text={view.placeholder} />
      )}
    </div>
  );
}

/** The authenticator data's level: the decoded data as JSON, and its bytes' way into the Codec. */
export function AuthenticatorDataLevel({ text, codec }: { text: string; codec: CodecLinks }) {
  const payload = codec.payloads.authenticatorData;
  return (
    <div className="space-y-4">
      {payload ? (
        <div>
          <DecodeInCodec part="authenticator data" payload={payload} onLeave={(button) => codec.onLeave('authenticator data', button)} />
        </div>
      ) : null}
      <CodeBlock value={text} label="authenticator data" />
    </div>
  );
}
