// The registration's levels from the views the logic composes: what each says
// when the record lacks a part, and a certificate that is only partly known.
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  type AttestationView,
  type CertificateView,
  REGISTRATION_TEXT,
  type RegistrationView,
} from '@/logic/credentials/registration/view.js';

import { CertificateLevel, RegistrationLevel } from './RegistrationLevels';

const NO_ATTESTATION_OBJECT: AttestationView = {
  body: { kind: 'placeholder', text: REGISTRATION_TEXT.noAttestationObject },
  certificates: [],
  certificateMessage: '',
  hasAuthenticatorData: false,
  authenticatorError: '',
};

function renderRegistration(registration: RegistrationView) {
  const onCertificate = vi.fn();
  const onAuthenticatorData = vi.fn();
  render(<RegistrationLevel registration={registration} idBase="detail" onCertificate={onCertificate} onAuthenticatorData={onAuthenticatorData} />);
  return { onCertificate, onAuthenticatorData };
}

const sectionOf = (title: string) => screen.getByRole('heading', { name: title }).closest('section')!;

describe('the registration\'s level', () => {
  it('says which of the response, its client data and the server\'s data the record lacks, with no attestation', () => {
    renderRegistration({ response: { credential: '', clientData: '', relyingParty: '' }, attestation: null });

    expect(screen.getByText(REGISTRATION_TEXT.noCredentialResponse)).toBeVisible();
    expect(screen.getByText(REGISTRATION_TEXT.noClientData)).toBeVisible();
    expect(screen.getByText(REGISTRATION_TEXT.noRelyingParty)).toBeVisible();
    expect(screen.queryByRole('heading', { name: REGISTRATION_TEXT.attestationTitle })).toBeNull();
  });

  it('says there is no attestation object, and opens no further level', () => {
    renderRegistration({ response: { credential: '{}', clientData: '{}', relyingParty: '{}' }, attestation: NO_ATTESTATION_OBJECT });

    const attestation = sectionOf(REGISTRATION_TEXT.attestationTitle);
    expect(within(attestation).getByText(REGISTRATION_TEXT.noAttestationObject)).toBeVisible();
    expect(within(attestation).queryByRole('button')).toBeNull();
  });

  it('opens the certificates alone when the authenticator data is not there', async () => {
    const { onCertificate } = renderRegistration({
      response: { credential: '{}', clientData: '{}', relyingParty: '{}' },
      attestation: { ...NO_ATTESTATION_OBJECT, body: { kind: 'json', text: '{}' }, certificates: [{ index: 0, title: REGISTRATION_TEXT.certificate }] },
    });

    const attestation = sectionOf(REGISTRATION_TEXT.attestationTitle);
    expect(within(attestation).queryByRole('button', { name: REGISTRATION_TEXT.authenticatorData })).toBeNull();
    await userEvent.click(within(attestation).getByRole('button', { name: REGISTRATION_TEXT.certificate }));
    expect(onCertificate).toHaveBeenCalledWith(1);
  });

  it('says why there is no certificate and why the authenticator data could not be decoded', () => {
    renderRegistration({
      response: { credential: '{}', clientData: '{}', relyingParty: '{}' },
      attestation: {
        ...NO_ATTESTATION_OBJECT,
        body: { kind: 'json', text: '{}' },
        certificateMessage: REGISTRATION_TEXT.noCertificates,
        hasAuthenticatorData: true,
        authenticatorError: 'The authenticator data is too short.',
      },
    });

    const attestation = sectionOf(REGISTRATION_TEXT.attestationTitle);
    expect(within(attestation).getByText(REGISTRATION_TEXT.noCertificates)).toBeVisible();
    expect(within(attestation).getByRole('alert')).toHaveTextContent('The authenticator data is too short.');
    expect(within(attestation).getByRole('button', { name: REGISTRATION_TEXT.authenticatorData })).toBeVisible();
  });
});

describe('a certificate\'s level', () => {
  const certificate = (view: Partial<CertificateView>): CertificateView => ({
    title: REGISTRATION_TEXT.certificate,
    details: {},
    text: '',
    error: '',
    placeholder: REGISTRATION_TEXT.noCertificateDetails,
    ...view,
  });

  it('gives no summary for a certificate it knows nothing of, and says so', () => {
    const { container } = render(<CertificateLevel view={certificate({})} idBase="certificate" />);

    expect(container.querySelector('[data-certificate-summary]')).toBeNull();
    expect(screen.getByText(REGISTRATION_TEXT.noCertificateDetails)).toBeVisible();
  });

  it('gives the issuer alone when the certificate names no subject', () => {
    const { container } = render(<CertificateLevel view={certificate({ details: { issuer: ' CN=Fixture Root ' } })} idBase="certificate" />);

    expect(container.querySelector('[data-certificate-subject]')).toBeNull();
    expect(container.querySelector('[data-certificate-summary]')).toHaveTextContent('CN=Fixture Root');
  });

  it('gives the subject alone when the certificate names no issuer', () => {
    const { container } = render(<CertificateLevel view={certificate({ details: { subject: 'CN=Fixture Key' } })} idBase="certificate" />);

    expect(container.querySelector('[data-certificate-subject]')).toHaveTextContent('CN=Fixture Key');
    expect(container.querySelector('[data-certificate-summary] p')).toBeNull();
  });
});
