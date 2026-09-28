// An MDS entry's attestation root certificate (MDS-X1..X4) through the whole
// page: the button, the decode, the URL (#mds/<entryId>/certificate/<n>), the
// page, and Back to the entry.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';
import { entryNamed, fixtureRoutes, json, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

// What POST /api/mds/decode-certificate answers for the fixture's EC root (its shape).
const DETAILS = {
  subject: 'C=SE, O=Characterization Test, OU=Authenticator Attestation, CN=Fixture FIDO2 Attestation Root',
  issuer: 'C=SE, O=Characterization Test, OU=Authenticator Attestation, CN=Fixture FIDO2 Attestation Root',
  validity: { notBefore: '2024-01-01T00:00:00+00:00', notAfter: '2044-01-01T00:00:00+00:00' },
  serialNumber: { decimal: '1001', hex: '03E9' },
  publicKeyInfo: { type: 'EC', algorithm: { name: 'ECDSA', namedCurve: 'secp256r1' }, keySize: 256, uncompressedPoint: '04ABCD' },
  signature: { algorithm: 'ECDSA_SHA256', hash: 'sha256', hex: '3045022100' },
  summary: 'Version: 3 (0x2)\nSerial Number: 1001',
};

const L1 = () => entryNamed('Fixture Security Key L1');
const firstCertificate = () => (L1().attestationCertificates as string[])[0];

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function renderApp(hash: string, decodeRoute = () => json({ details: DETAILS }) as Response | Promise<Response>) {
  window.history.replaceState({ fromNext: true }, '', `/${hash}`);
  const fetch = stubFetch(fixtureRoutes({ '/api/mds/decode-certificate': decodeRoute }));
  renderPage(
    <ToastProvider>
      <AppShell />
    </ToastProvider>,
  );
  return fetch;
}

const decodeCalls = (fetch: ReturnType<typeof stubFetch>) =>
  fetch.mock.calls.filter(([url]) => String(url) === '/api/mds/decode-certificate');

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('an attestation certificate of an MDS entry', () => {
  it('MDS-X1: keeps its button busy while the certificate is decoded', async () => {
    const pending = deferred<Response>();
    const fetch = renderApp(`#mds/${L1().entryId}`, () => pending.promise);
    const button = await screen.findByRole('button', { name: 'Certificate 1' });

    await userEvent.click(button);
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(decodeCalls(fetch)[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ certificate: firstCertificate() }) });
    await act(async () => pending.resolve(json({ details: DETAILS })));
    await screen.findByRole('heading', { level: 3, name: DETAILS.subject });
  });

  it('MDS-X1..X3: opens at its own URL over the entry, with the summary, Raw and Decoded Output', async () => {
    renderApp(`#mds/${L1().entryId}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));

    const heading = await screen.findByRole('heading', { level: 3, name: DETAILS.subject });
    expect(heading).toHaveFocus();
    expect(window.location.hash).toBe(`#mds/${L1().entryId}/certificate/1`);
    const page = document.querySelector<HTMLElement>('[data-mds-certificate]')!;
    expect(page).toHaveTextContent(DETAILS.issuer);
    for (const label of ['Subject', 'Issuer', 'Not Before', 'Not After', 'Serial Number', 'Serial Number (Hex)']) {
      expect(page.querySelector(`[data-item="${label}"]`)).not.toBeNull();
    }
    expect(within(page).getAllByRole('heading', { level: 4 }).map((node) => node.textContent)).toEqual([
      'Public Key',
      'Signature',
      'Raw',
      'Decoded Output',
    ]);
    expect(within(page).getByRole('button', { name: 'Copy serial number' })).toBeInTheDocument();
    expect(within(page).getByRole('button', { name: 'Copy raw certificate' })).toBeInTheDocument();
    expect(page.querySelectorAll('pre')[2]).toHaveTextContent(firstCertificate());
    expect(page.querySelectorAll('pre')[3].textContent).toBe(DETAILS.summary);
    expect(document.querySelector('[data-mds-entry]')!.parentElement).not.toBeVisible();
  });

  it('MDS-X4: its Back returns to the entry, with the focus on the certificate\'s button', async () => {
    renderApp(`#mds/${L1().entryId}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));
    await screen.findByRole('heading', { level: 3, name: DETAILS.subject });

    const back = within(document.querySelector<HTMLElement>('[data-mds-certificate]')!).getByRole('button', { name: 'Back' });
    expect(back).toHaveAttribute('title', 'Return to Fixture Security Key L1');
    await userEvent.click(back);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Certificate 1' })).toHaveFocus());
    expect(window.location.hash).toBe(`#mds/${L1().entryId}`);
  });

  it('MDS-X2, X4: decodes a certificate once, and the browser\'s Back returns to the entry', async () => {
    const fetch = renderApp(`#mds/${L1().entryId}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));
    await screen.findByRole('heading', { level: 3, name: DETAILS.subject });
    act(() => window.history.back());
    await waitFor(() => expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible());

    await userEvent.click(screen.getByRole('button', { name: 'Certificate 1' }));
    await screen.findByRole('heading', { level: 3, name: DETAILS.subject });
    expect(decodeCalls(fetch)).toHaveLength(1);
  });

  it('decodes on the page when a link opens it, and its Back shows the entry', async () => {
    const pending = deferred<Response>();
    renderApp(`#mds/${L1().entryId}/certificate/1`, () => pending.promise);
    expect(await screen.findByText('Decoding certificate 1…')).toBeInTheDocument();
    await act(async () => pending.resolve(json({ details: DETAILS })));
    await screen.findByRole('heading', { level: 3, name: DETAILS.subject });

    const length = window.history.length;
    await userEvent.click(within(document.querySelector<HTMLElement>('[data-mds-certificate]')!).getByRole('button', { name: 'Back' }));
    expect(window.location.hash).toBe(`#mds/${L1().entryId}`);
    expect(window.history.length).toBe(length);
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
  });

  it('MDS-X2: opens on a failure too, with the sentence, the server reason, and a new try from the entry', async () => {
    let answer = () => json({ error: 'Invalid certificate encoding.' }, 400);
    const fetch = renderApp(`#mds/${L1().entryId}`, () => answer());
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));

    expect(await screen.findByRole('heading', { level: 3, name: 'Attestation Certificate' })).toBeInTheDocument();
    const page = document.querySelector<HTMLElement>('[data-mds-certificate]')!;
    expect(within(page).getByRole('alert')).toHaveTextContent('Certificate decode failed with status 400');
    expect(within(page).getByRole('alert')).toHaveTextContent('Invalid certificate encoding.');
    expect(page.querySelectorAll('pre')[1].textContent).toBe('Certificate decode failed with status 400');

    answer = () => json({ details: DETAILS });
    await userEvent.click(within(page).getByRole('button', { name: 'Back' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));
    expect(await screen.findByRole('heading', { level: 3, name: DETAILS.subject })).toBeInTheDocument();
    expect(decodeCalls(fetch)).toHaveLength(2);
  });

  it('MDS-X2: says a decode that could not be sent', async () => {
    renderApp(`#mds/${L1().entryId}/certificate/1`, () => {
      throw new TypeError('Failed to fetch');
    });
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to fetch');
  });

  it('MDS-X1: says there is nothing to summarise, and keeps Decoded Output', async () => {
    renderApp(`#mds/${L1().entryId}/certificate/1`, () => json({ details: { summary: 'Unable to parse attestation certificate' } }));
    expect(await screen.findByText('No decoded certificate details available.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(document.querySelectorAll('[data-mds-certificate] pre')[1].textContent).toBe('Unable to parse attestation certificate');
  });

  it('MDS-X3: gives a value that is a list a line for each', async () => {
    renderApp(`#mds/${L1().entryId}/certificate/1`, () =>
      json({ details: { subject: ['CN=First', '', 'CN=Second'], serialNumber: { hex: '0A' } } }),
    );
    const subject = await waitFor(() => {
      const value = document.querySelector<HTMLElement>('[data-mds-certificate] [data-item="Subject"] [data-role="value"]');
      expect(value).not.toBeNull();
      return value!;
    });
    expect([...subject.querySelectorAll('.flex-col > span')].map((line) => line.textContent)).toEqual(['CN=First', 'CN=Second']);
  });

  it('MDS-X3: shows a summary that has only a section', async () => {
    renderApp(`#mds/${L1().entryId}/certificate/1`, () => json({ details: { signature: { algorithm: 'ECDSA_SHA256' } } }));
    await waitFor(() => expect(document.querySelector('[data-mds-certificate] [data-section="Signature"]')).not.toBeNull());
    const page = document.querySelector<HTMLElement>('[data-mds-certificate]')!;
    expect(page.querySelector('[data-item="Subject"]')).toBeNull();
    expect(page.querySelector('[data-section="Signature"] [data-item="Algorithm"]')).toHaveTextContent('ECDSA_SHA256');
  });

  it('opens nothing for a certificate that is only whitespace, nor for an entry without certificates', async () => {
    const blank = { ...L1(), entryId: 'aaguid:blank', name: 'Blank Root', attestationCertificates: ['  '] };
    const bare = { ...L1(), entryId: 'aaguid:bare', name: 'No Roots', attestationCertificates: [] };
    window.history.replaceState({ fromNext: true }, '', '/#mds/aaguid:blank/certificate/1');
    const fetch = stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/resolve': (_init, url) => json({ entry: url.includes('blank') ? blank : bare }),
      }),
    );
    renderPage(
      <ToastProvider>
        <AppShell />
      </ToastProvider>,
    );
    expect(await screen.findByRole('heading', { level: 3, name: 'Blank Root' })).toBeVisible();
    await waitFor(() => expect(window.location.hash).toBe('#mds/aaguid:blank'));
    await userEvent.click(screen.getByRole('button', { name: 'Certificate 1' }));
    expect(window.location.hash).toBe('#mds/aaguid:blank');
    expect(decodeCalls(fetch)).toHaveLength(0);

    act(() => {
      window.history.replaceState({ fromNext: true }, '', '/#mds/aaguid:bare/certificate/1');
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    expect(await screen.findByRole('heading', { level: 3, name: 'No Roots' })).toBeVisible();
    await waitFor(() => expect(window.location.hash).toBe('#mds/aaguid:bare'));
  });

  it('shows the entry for a certificate it does not have, and says so in the URL', async () => {
    renderApp(`#mds/${L1().entryId}/certificate/9`);
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
    await waitFor(() => expect(window.location.hash).toBe(`#mds/${L1().entryId}`));
  });

  it('leaves an entry\'s page alone when the list is left while a certificate decodes', async () => {
    const pending = deferred<Response>();
    renderApp(`#mds/${L1().entryId}`, () => pending.promise);
    await userEvent.click(await screen.findByRole('button', { name: 'Certificate 1' }));
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    await act(async () => pending.resolve(json({ details: DETAILS })));
    expect(window.location.hash).toBe('#mds');
  });
});
