// A saved credential's details at their own URL, through the whole shell, over the server's
// recorded answers: the registrations, the decoder's answers the details ask for,
// and an advanced registration's stored artifact.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { DETAIL_SCENARIO, artifactAnswer, decodeRoute, keepRecords, savedRecord, storedRecords, warmUpRoutes } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

import { forgetCompletedRecords } from './detail/useCredentialDetail';

const ES256 = savedRecord(DETAIL_SCENARIO, {}, 0);
const EDDSA = savedRecord(DETAIL_SCENARIO, { userName: 'eddsa@example.com' }, 1);
const MLDSA = savedRecord(DETAIL_SCENARIO, { userName: 'mldsa@example.com' }, 2);
const X5C = savedRecord(DETAIL_SCENARIO, { userName: 'x5c@example.com' }, 3);
const ADVANCED = savedRecord('advanced-register-packed-x5c-everything', { userName: 'advanced@example.com' });
const ARTIFACT = artifactAnswer('advanced-register-packed-x5c-everything');

const keyOf = (record: Record<string, unknown>) => `id:${record.credentialIdBase64Url}`;
const urlOf = (record: Record<string, unknown>, ...levels: string[]) => ['#simple/credential', keyOf(record), ...levels].join('/');

function renderShell(records: Record<string, unknown>[], hash = '', routes = {}) {
  window.history.replaceState({ fromNext: true }, '', `/${hash}`);
  keepRecords(records);
  const fetch = stubFetch({ ...warmUpRoutes(), '/api/codec': decodeRoute(), ...routes });
  renderPage(<AppShell />);
  return fetch;
}

const dialog = () => screen.getByRole('dialog');
const shownLevel = () => dialog().querySelector<HTMLElement>('[data-level]:not([hidden])')!;
const section = (title: string) => shownLevel().querySelector<HTMLElement>(`[data-section="${title}"]`)!;

async function frame() {
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });
}

async function openDetail(name = 'user@example.com') {
  const button = await screen.findByRole('button', { name });
  await userEvent.click(button);
  await frame();
  await screen.findByRole('button', { name: 'Show registration details' });
  return button;
}

async function toRegistration() {
  await userEvent.click(screen.getByRole('button', { name: 'Show registration details' }));
  await screen.findByRole('heading', { level: 2, name: 'Registration Details' });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  forgetCompletedRecords();
});

describe('a saved credential\'s details, the detail', () => {
  it('open from its name at their own URL, as a history entry of their own', async () => {
    renderShell([ES256]);
    const length = window.history.length;
    await openDetail();

    expect(window.location.hash).toBe(urlOf(ES256));
    expect(window.history.length).toBe(length + 1);
    expect(within(dialog()).getByRole('heading', { level: 2, name: 'Credential Details' })).toBeVisible();
    expect(within(dialog()).getByRole('heading', { level: 3, name: 'user@example.com' })).toBeVisible();
  });

  it('give the properties, the checks with their note, and which roots were tried', async () => {
    renderShell([X5C]);
    await openDetail('x5c@example.com');

    const properties = section('Properties');
    // A Simple record keeps its extension outputs, not the resident key's or large blob's own fields.
    expect(properties.querySelector('[data-item="discoverable"] [data-value]')).toHaveTextContent('false');
    expect(properties.querySelector('[data-item="largeBlob"] [data-value]')).toHaveTextContent('false');
    expect(properties.querySelector('[data-item="minPinLength"]')).toHaveTextContent('Authenticator minPinLength8');
    expect(properties.querySelector('[data-checks] p')).toHaveTextContent(
      'In formal WebAuthn, any false result below causes registration to fail.',
    );
    const checks = Array.from(properties.querySelectorAll('[data-check]')).map((check) => [
      check.getAttribute('data-check'),
      check.querySelector('[data-value]')!.getAttribute('data-value'),
    ]);
    expect(checks).toEqual([
      ['Signature Valid', 'true'],
      ['Root Valid', 'missing'],
      ['RPID Hash Valid', 'true'],
      ['AAGUID Match', 'true'],
    ]);
    expect(properties.querySelector('[data-root-checks]')).toHaveTextContent('FIDO MDS');
    expect(properties.querySelector('[data-root-checks]')).toHaveTextContent('Chain');
  });

  it('give the user at creation, each identifier in every spelling and the AAGUID, in Geist Mono with copy', async () => {
    renderShell([ES256]);
    await openDetail();

    const user = section('User info at creation');
    expect(user.querySelector('[data-item="name"]')).toHaveTextContent('Nameuser@example.com');
    const credentialId = user.querySelector('[data-identifier="Credential ID:"]')!;
    const spellings = Array.from(credentialId.querySelectorAll('code')).map((code) => code.textContent);
    expect(spellings[1]).toBe(ES256.credentialIdBase64Url);
    expect(spellings[2]).toBe(ES256.credentialIdHex);
    expect(within(user).getByRole('button', { name: 'Copy Credential ID (hex)' })).toBeInTheDocument();
    const aaguid = user.querySelector('[data-identifier="AAGUID"]')!;
    expect(Array.from(aaguid.querySelectorAll('code')).map((code) => code.textContent)).toEqual([
      'ABEiM0RVZneImaq7zN3u/w==',
      'ABEiM0RVZneImaq7zN3u_w',
      '00112233445566778899aabbccddeeff',
      '00112233-4455-6677-8899-aabbccddeeff',
    ]);
  });

  it('give an identifier that is not base64url as it is stored, and say so', async () => {
    const odd = { ...EDDSA, userHandle: 'not base64url!' };
    renderShell([odd]);
    await openDetail('eddsa@example.com');

    const handle = section('User info at creation').querySelector('[data-identifier="User handle (User ID):"]')!;
    expect(handle.querySelector('code')).toHaveTextContent('not base64url!');
    expect(handle).toHaveTextContent('Not valid base64url: shown as stored.');
  });

  it('give the format, the flags and counter, the extension outputs and the public key', async () => {
    renderShell([X5C]);
    await openDetail('x5c@example.com');

    expect(section('Attestation Format')).toHaveTextContent('packed');
    expect(section('Client extension outputs (registration)').querySelector('pre')).toHaveTextContent('"minPinLength": 8');
    const key = section('Public Key');
    expect(key.querySelector('[data-item="Algorithm:"]')).toHaveTextContent('ES256 (-7)');
    expect(key.querySelector('[data-item="COSE key type:"]')).toHaveTextContent('EC2 (2)');
  });

  it('name an EdDSA key and an ML-DSA key with its parameter set', async () => {
    renderShell([EDDSA, MLDSA]);
    await openDetail('eddsa@example.com');
    expect(section('Public Key')).toHaveTextContent('EdDSA (-8)');
    expect(section('Public Key')).toHaveTextContent('OKP (1)');

    await userEvent.click(screen.getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await openDetail('mldsa@example.com');
    const key = section('Public Key');
    expect(key).toHaveTextContent('ML-DSA-65 (PQC) (-49)');
    expect(key.querySelector('[data-item="ML-DSA parameter set:"]')).toHaveTextContent('ML-DSA-65');
  });

  it('complete an advanced record from its server artifact first, and save the snapshot it brings', async () => {
    const fetch = renderShell([ADVANCED], '', {
      [`/api/advanced/credential-artifacts/${encodeURIComponent(ARTIFACT.storageId)}`]: () => json(ARTIFACT),
    });
    await openDetail('advanced@example.com');

    expect(fetch.mock.calls.some(([url]) => String(url).includes('/credential-artifacts/HhfJJ'))).toBe(true);
    expect(section('Attestation Format')).toHaveTextContent('packed');
    expect(dialog().querySelector('[data-hydration]')).toBeNull();
  });

  it('say the artifact could not be fetched, and show what this browser keeps', async () => {
    renderShell([ADVANCED], '', {
      [`/api/advanced/credential-artifacts/${encodeURIComponent(ARTIFACT.storageId)}`]: () => json({ error: 'Store unavailable.' }, 503),
    });
    await openDetail('advanced@example.com');

    expect(dialog().querySelector('[data-hydration="failed"]')).toHaveTextContent('Unable to fetch credential artifact');
    expect(section('Properties')).toBeInTheDocument();
  });
});

describe('a saved credential\'s details, what some records hold', () => {
  it('keep the registration snapshot the artifact brings, so the list reads it again', async () => {
    const snapshot = {
      schemaVersion: 2,
      capturedAt: '2026-09-27T10:00:00Z',
      state: { authenticatorDataHash: 'abcd' },
      response: { credential: { id: ADVANCED.credentialIdBase64Url, type: 'public-key', response: {} }, relyingParty: { attestationFmt: 'packed' } },
    };
    const path = `/api/advanced/credential-artifacts/${encodeURIComponent(ARTIFACT.storageId)}`;
    renderShell([ADVANCED], '', {
      [path]: () => json({ ...ARTIFACT, artifact: { ...ARTIFACT.artifact, registrationDetailSnapshot: snapshot } }),
      [`${path}/snapshot`]: () => json({ status: 'OK' }),
    });
    await openDetail('advanced@example.com');

    await waitFor(() => expect(storedRecords()[0].registrationDetailSnapshot).toMatchObject({ schemaVersion: 2 }));
    await toRegistration();
    expect(section('Authenticator Response').querySelector('pre')).toHaveTextContent(ADVANCED.credentialIdBase64Url as string);
  });

  it('give the metadata\'s warning in amber, and FIDO MDS beside the AAGUID when it has an entry', async () => {
    const known = {
      ...ES256,
      aaguidHex: 'f1d0f1d0000040008000000000000001',
      attestationSummary: { rootValid: true, metadata: { verification_warning: 'The metadata entry is revoked.' } },
    };
    renderShell([known]);
    await openDetail();

    expect(section('Properties').querySelector('[data-warning]')).toHaveTextContent('The metadata entry is revoked.');
    await userEvent.click(within(section('User info at creation')).getByRole('button', { name: 'FIDO MDS' }));
    await waitFor(() => expect(window.location.hash).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001'));
  });

  it('give a stored AAGUID no spelling reads as stored, marked, under the four N/A spellings', async () => {
    renderShell([{ ...EDDSA, aaguid: 'abcde', aaguidHex: undefined }]);
    await openDetail('eddsa@example.com');

    const aaguid = section('User info at creation').querySelector('[data-aaguid]')!;
    expect(aaguid.querySelector('[data-unreadable="aaguid"]')).toHaveTextContent('Unreadable');
    expect(aaguid.querySelector('[data-unreadable="aaguid"] code')).toHaveTextContent('abcde');
  });

  it('read the all-zero AAGUID a record keeps in base64url as sixteen zero bytes, in the row and the details', async () => {
    const zero = '0'.repeat(32);
    const zeroGuid = '00000000-0000-0000-0000-000000000000';
    const properties = { ...(EDDSA.properties as object), aaguid: zero, aaguidHex: zero, aaguidGuid: zeroGuid };
    renderShell([{ ...EDDSA, aaguid: 'AAAAAAAAAAAAAAAAAAAAAA', aaguidHex: undefined, properties }]);
    const name = await screen.findByRole('button', { name: 'eddsa@example.com' });

    const row = name.closest('li')!;
    expect(row).toHaveTextContent(zeroGuid);
    expect(row.querySelector('[data-unreadable]')).toBeNull();
    await openDetail('eddsa@example.com');
    const aaguid = section('User info at creation').querySelector<HTMLElement>('[data-aaguid]')!;
    for (const spelling of ['AAAAAAAAAAAAAAAAAAAAAA==', zero, zeroGuid]) expect(aaguid).toHaveTextContent(spelling);
    expect(aaguid).not.toHaveTextContent('aaaaaaaaaaaaaaaaaaaaaa');
  });

  it('say a certificate could not be parsed, and give no summary for it', async () => {
    const broken = { ...ES256, attestationCertificates: [{ parsedX5c: { error: 'The certificate is not DER.' } }], attestationObject: '' };
    renderShell([broken], urlOf(ES256, 'registration', 'certificate', '1'));
    // The title shows while the details are still being composed: wait for the level.
    await waitFor(() => expect(shownLevel()).not.toBeNull());

    expect(within(shownLevel()).getByRole('alert')).toHaveTextContent('The certificate is not DER.');
    expect(shownLevel().querySelector('[data-certificate-summary]')).toBeNull();
  });
});

describe('a saved credential\'s details, the registration', () => {
  it('give the browser\'s response, its client data and what the server kept, each as a block with copy', async () => {
    renderShell([ES256]);
    await openDetail();
    await toRegistration();

    expect(window.location.hash).toBe(urlOf(ES256, 'registration'));
    const response = section('Authenticator Response');
    expect(response).toHaveTextContent('Response for navigator.credentials.create()');
    expect(response.querySelectorAll('pre')[0]).toHaveTextContent(ES256.credentialIdBase64Url as string);
    expect(response.querySelectorAll('pre')[1]).toHaveTextContent('"type": "webauthn.create"');
    expect(section('Server-retrieved Data').querySelector('pre')).toHaveTextContent('"rpIdHash"');
    expect(within(response).getByRole('button', { name: 'Copy registration response' })).toBeInTheDocument();
  });

  it('give the attestation object, and no certificate for a none attestation', async () => {
    renderShell([ES256]);
    await openDetail();
    await toRegistration();

    const attestation = section('Attestation Information');
    expect(attestation.querySelector('pre')).toHaveTextContent('"fmt": "none"');
    expect(attestation).toHaveTextContent('No attestation certificates available.');
    expect(within(attestation).getByRole('button', { name: 'Authenticator Data' })).toBeInTheDocument();
  });

  it('say why the attestation object could not be decoded', async () => {
    renderShell([{ ...EDDSA, attestationObject: 'bm90LWNib3I' }]);
    await openDetail('eddsa@example.com');
    await toRegistration();

    expect(within(section('Attestation Information')).getByRole('alert')).toHaveTextContent('The payload is not valid CBOR.');
  });

  it('open a certificate at its own URL, with its summary above the current text', async () => {
    renderShell([X5C]);
    await openDetail('x5c@example.com');
    await toRegistration();
    await userEvent.click(within(section('Attestation Information')).getByRole('button', { name: 'Attestation Certificate' }));

    expect(window.location.hash).toBe(urlOf(X5C, 'registration', 'certificate', '1'));
    expect(within(dialog()).getByRole('heading', { level: 2, name: 'Attestation Certificate' })).toBeVisible();
    const level = shownLevel();
    expect(level.querySelector('[data-certificate-subject]')).toHaveTextContent('CN=');
    expect(section('Decoded Output').querySelector('pre')).toHaveTextContent('Signature Algorithm:');
  });

  it('open the authenticator data at its own URL, as JSON', async () => {
    renderShell([ES256]);
    await openDetail();
    await toRegistration();
    await userEvent.click(within(section('Attestation Information')).getByRole('button', { name: 'Authenticator Data' }));

    expect(window.location.hash).toBe(urlOf(ES256, 'registration', 'authenticator-data'));
    expect(within(dialog()).getByRole('heading', { level: 2, name: 'Authenticator Data' })).toBeVisible();
    expect(shownLevel().querySelector('pre')).toHaveTextContent('"rpIdHash"');
  });
});

describe('a saved credential\'s details, the levels', () => {
  it('go back a level with Back, the focus on what opened the one left', async () => {
    renderShell([X5C]);
    await openDetail('x5c@example.com');
    await toRegistration();
    await userEvent.click(screen.getByRole('button', { name: 'Attestation Certificate' }));

    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(window.location.hash).toBe(urlOf(X5C, 'registration')));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Attestation Certificate' })).toHaveFocus());

    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(window.location.hash).toBe(urlOf(X5C)));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Show registration details' })).toHaveFocus());
  });

  it('open a certificate from a link or a reload, and close every level with ×', async () => {
    renderShell([X5C], urlOf(X5C, 'registration', 'certificate', '1'));
    await screen.findByRole('heading', { level: 2, name: 'Attestation Certificate' });

    await userEvent.click(screen.getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(window.location.hash).toBe('#simple');
  });

  it('correct a certificate the credential does not have to its registration, and another word to the detail', async () => {
    renderShell([X5C], urlOf(X5C, 'registration', 'certificate', '9'));
    await waitFor(() => expect(window.location.hash).toBe(urlOf(X5C, 'registration')));
    await screen.findByRole('heading', { level: 2, name: 'Registration Details' });

    window.history.replaceState({ fromNext: true }, '', `/${urlOf(X5C, 'elsewhere')}`);
    await act(async () => {
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    await waitFor(() => expect(window.location.hash).toBe(urlOf(X5C)));
  });

  it('close on Escape by going back, with the focus on the name that opened them', async () => {
    renderShell([ES256]);
    const name = await openDetail();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(window.location.hash).toBe(''));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(name).toHaveFocus();
  });

  it('show the list, and correct the URL, for a credential this browser does not keep', async () => {
    renderShell([ES256], '#simple/credential/id:unknown');
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('are the only thing the section\'s URL can open', async () => {
    renderShell([ES256], '#simple/elsewhere');
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(await screen.findByRole('button', { name: 'user@example.com' })).toBeVisible();
  });

  it('go up one level on the browser\'s Back, and close every level from the deepest with Escape', async () => {
    renderShell([ES256]);
    await openDetail();
    await toRegistration();
    await userEvent.click(screen.getByRole('button', { name: 'Authenticator Data' }));

    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(window.location.hash).toBe(urlOf(ES256, 'registration')));
    await screen.findByRole('heading', { level: 2, name: 'Registration Details' });

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(window.location.hash).toBe('');
  });
});
