import { CertificateSummary } from '@/components/mds/CertificateSummary';
import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';

import { DetailSection } from './DetailSections';
import { type AttestationView, type CertificateView, REGISTRATION_WORDS, type RegistrationView, summaryOf } from './model';

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
}: {
  attestation: AttestationView;
  idBase: string;
  onCertificate: (number: number) => void;
  onAuthenticatorData: () => void;
}) {
  const { body } = attestation;
  return (
    <DetailSection id={`${idBase}-attestation`} title={REGISTRATION_WORDS.attestationTitle}>
      <div>
        {/* A heading of its own in the current view too (the parity check splits there). */}
        <h5 className="text-title-sm font-semibold text-ink" data-parity-heading="">
          {REGISTRATION_WORDS.attestationObject}
        </h5>
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
                {REGISTRATION_WORDS.authenticatorData}
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
 * The registration's level: the browser's response and its
 * client data, what the server made of it, and the attestation, whose
 * certificates and authenticator data open levels of their own.
 */
export function RegistrationLevel({
  registration,
  idBase,
  onCertificate,
  onAuthenticatorData,
}: {
  registration: RegistrationView;
  idBase: string;
  onCertificate: (number: number) => void;
  onAuthenticatorData: () => void;
}) {
  const { response } = registration;
  // The level starts under the dialog's header: its first section needs no hairline.
  return (
    <div className="space-y-8 [&>section:first-child]:border-t-0 [&>section:first-child]:pt-0">
      <DetailSection id={`${idBase}-response`} title={REGISTRATION_WORDS.responseTitle}>
        <ol className="list-decimal space-y-5 pl-5 marker:text-ink-muted">
          <li className="min-w-0 pl-1">
            <h5 className="text-title-sm font-semibold text-ink">{REGISTRATION_WORDS.createResponse}</h5>
            <div className="mt-2">
              {response.credential ? (
                <CodeBlock value={response.credential} label="registration response" />
              ) : (
                <Placeholder text={REGISTRATION_WORDS.noCredentialResponse} />
              )}
            </div>
          </li>
          <li className="min-w-0 pl-1">
            <h5 className="text-title-sm font-semibold text-ink">{REGISTRATION_WORDS.parsedClientData}</h5>
            <div className="mt-2">
              {response.clientData ? (
                <CodeBlock value={response.clientData} label="client data" />
              ) : (
                <Placeholder text={REGISTRATION_WORDS.noClientData} />
              )}
            </div>
          </li>
        </ol>
      </DetailSection>
      <DetailSection id={`${idBase}-server`} title={REGISTRATION_WORDS.serverDataTitle}>
        {response.relyingParty ? (
          <CodeBlock value={response.relyingParty} label="server-retrieved data" />
        ) : (
          <Placeholder text={REGISTRATION_WORDS.noRelyingParty} />
        )}
      </DetailSection>
      {registration.attestation ? (
        <Attestation
          attestation={registration.attestation}
          idBase={idBase}
          onCertificate={onCertificate}
          onAuthenticatorData={onAuthenticatorData}
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
export function CertificateLevel({ view, idBase }: { view: CertificateView; idBase: string }) {
  const summary = summaryOf(view.details);
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

/** The authenticator data's level: the decoded data as JSON. */
export function AuthenticatorDataLevel({ text }: { text: string }) {
  return <CodeBlock value={text} label="authenticator data" />;
}
