// The MDS entry page over the fixture's real entries (tests/fixtures/mds).
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { getAuthenticatorRawData } from '@/logic/mds/raw-data.js';
import { stringifyAuthenticatorRawData } from '@/logic/mds/raw-stringify.js';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, entryNamed, fixtureRoutes, json, resolveFrom, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { EntryPage } from './EntryPage';
import { MdsSection } from './MdsSection';
import type { EntryDetail } from './useEntryDetail';

function renderEntry(entry: MdsEntry, props: Partial<Parameters<typeof EntryPage>[0]> = {}) {
  const onBack = vi.fn();
  const onRetry = vi.fn();
  renderPage(
    <ToastProvider>
      <EntryPage entryId={entry.entryId} detail={{ phase: 'found', entry }} onBack={onBack} onRetry={onRetry} {...props} />
    </ToastProvider>,
  );
  return { onBack, onRetry };
}

const section = (key: string) => document.querySelector<HTMLElement>(`[data-section="${key}"]`)!;
const field = (scope: HTMLElement, label: string) => scope.querySelector<HTMLElement>(`[data-item="${label}"] [data-role="value"]`)!;
const chips = (label: string) =>
  [...document.querySelectorAll<HTMLElement>(`[data-chips="${label}"] li`)].map((chip) => chip.textContent);

const L1 = () => entryNamed('Fixture Security Key L1');

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the MDS entry page', () => {
  it('shows Back, the name, the subtitle with copyable identifiers, and Raw', async () => {
    const entry = L1();
    const { onBack } = renderEntry(entry);

    const heading = screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' });
    expect(heading).toHaveFocus();
    const subtitle = document.querySelector<HTMLElement>('[data-entry-subtitle]')!;
    expect(subtitle).toHaveTextContent(`AAGUID:${entry.aaguid}`);
    expect(subtitle).toHaveTextContent('FIDO2');
    expect(within(subtitle).getByRole('button', { name: 'Copy AAGUID' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Raw' })).toHaveAttribute('title', 'View raw authenticator data');

    const back = screen.getByRole('button', { name: 'Back' });
    expect(back).toHaveAttribute('title', 'Return to authenticator list');
    await userEvent.click(back);
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it('names an AAID and a key identifier by their kind, and the blank name "Authenticator"', () => {
    const uaf = entryNamed('Fixture UAF Authenticator');
    renderEntry({ ...uaf, name: '  ' });
    expect(screen.getByRole('heading', { level: 3, name: 'Authenticator' })).toBeInTheDocument();
    const subtitle = document.querySelector<HTMLElement>('[data-entry-subtitle]')!;
    expect(subtitle).toHaveTextContent('ID:F1D0#0012');
    expect(subtitle).toHaveTextContent('Uaf');
    expect(within(subtitle).getByRole('button', { name: 'Copy AAID' })).toBeInTheDocument();
  });

  it('shows every section, in order', () => {
    renderEntry(L1());
    expect(screen.getAllByRole('heading', { level: 4 }).map((heading) => heading.textContent)).toEqual([
      'Overview',
      'Metadata Statement',
      'User Verification Details',
      'Attestation Root Certificates',
      'Authenticator Get Info',
      'Status Reports',
    ]);
  });

  it('shows the overview, identifiers in Geist Mono with copy, certification as the list does', () => {
    const entry = L1();
    renderEntry(entry);
    const overview = section('overview');
    // An AAGUID entry's identifier is its AAGUID: both rows copy it.
    expect(within(overview).getAllByRole('button', { name: 'Copy AAGUID' })).toHaveLength(2);
    expect(field(overview, 'Identifier').querySelector('code')).toHaveTextContent(entry.id);
    expect(field(overview, 'Protocol')).toHaveTextContent('FIDO2');
    expect(field(overview, 'Certification')).toHaveTextContent('FIDO Certified L1Fixture Security Key • (FIDO20020260901001)');
    expect(field(overview, 'Authenticator Version')).toHaveTextContent('2');
    expect(field(overview, 'Date Updated')).toHaveTextContent(entry.dateUpdated);
  });

  it('shows the statement, its long text across the row, key identifiers with copy, and the chip lists', () => {
    const u2f = entryNamed('Fixture U2F Key');
    renderEntry(u2f);
    const statement = section('metadataStatement');
    expect(field(statement, 'Description')).toHaveTextContent('Fixture U2F Key');
    expect(statement.querySelector('[data-item="Legal Header"]')).toHaveClass('col-span-full');
    expect(field(statement, 'Schema')).toHaveTextContent('3');
    expect(field(statement, 'UPV')).toHaveTextContent('1.1');
    expect(within(statement).getByRole('button', { name: 'Copy key identifier' })).toBeInTheDocument();
    expect(field(statement, 'Attestation Certificate Key IDs')).toHaveTextContent(u2f.attestationKeyIdentifiers as unknown as string);
    expect(chips('Authentication Algorithms')).toEqual(['secp256r1_ecdsa_sha256_raw']);
    expect(chips('Attestation Types')).toEqual(['basic_full']);
    expect(chips('Matcher Protection')).toEqual(['on_chip']);
  });

  it('lists the combinations, each method and what it says of its accuracy', () => {
    renderEntry(entryNamed('Fixture Key With Every User Verification Method'));
    const combinations = [...section('userVerification').querySelectorAll<HTMLElement>('[data-combination]')];
    expect(combinations).toHaveLength(10);
    expect(combinations[0]).toHaveTextContent('Combination 1');
    expect(combinations[0]).toHaveTextContent('passcode_internal');
    expect(combinations[0]).toHaveTextContent('Base: 10 • Min length: 6 • Max retries: 8 • Block slowdown: 30');
    expect(combinations[0]).toHaveTextContent('fingerprint_internal');
    expect(combinations[0]).toHaveTextContent(
      'Self-attested FRR: 0.01 • Self-attested FAR: 0.00002 • Max templates: 5 • Max retries: 5 • Block slowdown: 30',
    );
    expect(combinations[1]).toHaveTextContent('pattern_internalMin complexity: 9 • Max retries: 5 • Block slowdown: 60');
    expect(combinations[9]).toHaveTextContent('Combination 10none');
  });

  it('numbers the certificates; without a page to open them they wait', () => {
    const entry = entryNamed('Fixture Key With Many Attestation Roots');
    renderEntry(entry);
    const buttons = within(section('certificates')).getAllByRole('button');
    expect(buttons.map((button) => button.textContent)).toEqual(Array.from({ length: 15 }, (_, index) => `Certificate ${index + 1}`));
    expect(buttons[0]).toBeDisabled();
  });

  it('a certificate button opens its page and is busy while it decodes', async () => {
    const onOpen = vi.fn();
    const entry = L1();
    const { rerender } = render(
      <EntryPage entryId={entry.entryId} detail={{ phase: 'found', entry }} onBack={vi.fn()} onRetry={vi.fn()} onOpenCertificate={onOpen} />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Certificate 1' }));
    expect(onOpen).toHaveBeenCalledWith(1, (entry.attestationCertificates as string[])[0]);

    rerender(
      <EntryPage
        entryId={entry.entryId}
        detail={{ phase: 'found', entry }}
        onBack={vi.fn()}
        onRetry={vi.fn()}
        onOpenCertificate={onOpen}
        busyCertificate={1}
      />,
    );
    expect(screen.getByRole('button', { name: 'Certificate 1' })).toHaveAttribute('aria-busy', 'true');
  });

  it('shows getInfo: its AAGUID with copy, every number, the chips and the options', () => {
    const entry = L1();
    renderEntry(entry);
    const info = section('authenticatorGetInfo');
    expect(field(info, 'AAGUID').querySelector('code')).toHaveTextContent(entry.aaguid!);
    expect(within(info).getByRole('button', { name: 'Copy AAGUID' })).toBeInTheDocument();
    for (const [label, value] of [
      ['Max Message Size', '1200'],
      ['Max Credential Count', '8'],
      ['Max Credential ID Length', '128'],
      ['Max Serialized Large Blob Array', '1024'],
      ['Min PIN Length', '6'],
      ['Firmware Version', '327941'],
      ['Max Cred Blob Length', '32'],
      ['Max RP IDs for Set Min PIN Length', '1'],
      ['Remaining Discoverable Credentials', '25'],
    ]) {
      expect(field(info, label)).toHaveTextContent(value);
    }
    expect(chips('Versions')).toEqual(['FIDO_2_0', 'FIDO_2_1']);
    expect(chips('Algorithms')).toEqual(['{"alg":-7,"type":"public-key"}', '{"alg":-8,"type":"public-key"}']);
    expect(chips('pinUvAuth Protocols')).toEqual(['1', '2']);
    expect(chips('Options')).toContain('uv: false');
    expect(chips('Options')).toContain('rk: true');
  });

  it('shows every status report, with its descriptor, URL, every other field and its certificate', () => {
    renderEntry(L1());
    expect(field(section('statusReports'), 'Last Status Change')).toHaveTextContent(/^2026-09-01$/);
    const table = within(section('statusReports')).getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual([
      'Status',
      'Effective Date',
      'Authenticator Version',
      'Certificate Number',
      'Descriptor',
    ]);
    const rows = [...table.querySelectorAll<HTMLElement>('[data-report]')];
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getAllByRole('cell').map((cell) => cell.textContent)).toEqual(['NOT_FIDO_CERTIFIED', '2025-11-03', '1', '—', '—']);
    const latest = within(rows[2]).getAllByRole('cell');
    expect(latest[0]).toHaveTextContent('FIDO_CERTIFIED_L1');
    expect(latest[3].querySelector('code')).toHaveTextContent('FIDO20020260901001');
    expect(within(latest[3]).getByRole('button', { name: 'Copy certificate number' })).toBeInTheDocument();
    expect(latest[4]).toHaveTextContent('Fixture Security Key • https://fixture.example/certificates/FIDO20020260901001');
    expect(latest[4]).toHaveTextContent(
      'Policy: 1.4.0 • Requirements: 1.3 • Profiles: consumer, enterprise • Sunset Date: 2029-09-01 • ' +
        'FIPS Revision: 3 • FIPS Physical Security Level: 2 • Fixture Future Field: A field no MDS3 version defines',
    );
    expect(latest[4]).toHaveAttribute('data-label', 'Descriptor');
    const certificate = latest[4].querySelector<HTMLElement>('[data-report-certificate]')!;
    expect(certificate).toHaveTextContent(/^Certificate/);
    expect(certificate.querySelector('code')?.textContent).toMatch(/^MII/);
    expect(within(certificate).getByRole('button', { name: 'Copy status report certificate' })).toBeInTheDocument();
    // The earlier reports have none.
    expect(rows[1].querySelector('[data-report-certificate]')).toBeNull();
  });

  it('shows the statement\'s descriptions and friendly names in each of their languages', () => {
    renderEntry(entryNamed('Fixture Security Key L2'));
    const statement = section('metadataStatement');
    expect(field(statement, 'Description (de-DE)')).toHaveTextContent(/^Fixture Sicherheitsschlüssel L2$/);
    expect(field(statement, 'Friendly Name (en-US)')).toHaveTextContent(/^Fixture Security Key L2$/);
    expect(field(statement, 'Friendly Name (zh-CN)')).toHaveTextContent(/^Fixture 安全密钥 L2$/);
  });

  it('says whether the statement\'s key is restricted, wants fresh user verification, or syncs', () => {
    renderEntry(entryNamed('Fixture Security Key L2'));
    const statement = section('metadataStatement');
    expect(field(statement, 'Key Restricted')).toHaveTextContent(/^true$/);
    expect(field(statement, 'Fresh User Verification Required')).toHaveTextContent(/^false$/);
    expect(field(statement, 'Multi-Device Credential Support')).toHaveTextContent(/^unsupported$/);
  });

  it('shows the supported extensions and the transaction display\'s content type and PNG', () => {
    renderEntry(entryNamed('Fixture Security Key L2'));
    const statement = section('metadataStatement');
    expect(chips('Supported Extensions')).toEqual(['hmac-secret', 'credProtect (tag 1, data 03, fail if unknown)']);
    expect(chips('TC Display')).toEqual(['any', 'hardware']);
    expect(field(statement, 'TC Display Content Type')).toHaveTextContent(/^image\/png$/);
    expect(field(statement, 'TC Display PNG 2')).toHaveTextContent(/Palette: rgb\(255, 255, 255\), rgb\(0, 0, 0\)$/);
  });

  it('shows the biometric status reports in a table of their own, and the rogue list over the status reports', () => {
    const entry = entryNamed('Fixture Security Key L2');
    renderEntry(entry);
    expect(screen.getAllByRole('heading', { level: 4 }).map((heading) => heading.textContent).slice(-2)).toEqual([
      'Status Reports',
      'Biometric Status Reports',
    ]);
    const status = section('statusReports');
    expect(field(status, 'Rogue List URL')).toHaveTextContent('https://fixture.example/rogue-lists/fixture-security-key-l2.json');
    expect(field(status, 'Rogue List Hash').querySelector('code')).toHaveTextContent(entry.rogueListHash as string);
    expect(within(status).getByRole('button', { name: 'Copy Rogue List Hash' })).toBeInTheDocument();
    const table = within(section('biometricStatusReports')).getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual([
      'Modality',
      'Effective Date',
      'Certification Level',
      'Certificate Number',
      'Descriptor',
    ]);
    const [report] = [...table.querySelectorAll<HTMLElement>('[data-report]')];
    const cells = within(report).getAllByRole('cell');
    expect(cells.slice(0, 3).map((cell) => cell.textContent)).toEqual(['fingerprint_internal', '2026-08-15', '1']);
    expect(cells[2]).toHaveAttribute('data-label', 'Certification Level');
    expect(cells[3].querySelector('code')).toHaveTextContent('FIDOBIO20260815002');
    expect(cells[4]).toHaveTextContent('Fixture Fingerprint SensorPolicy: 1.4.0 • Requirements: 3.0');
  });

  it('reads "—" for a missing identifier and leaves out what an entry does not have', () => {
    renderEntry({ entryId: 'entry:bare', name: 'Bare' } as unknown as MdsEntry);
    expect(field(section('overview'), 'Identifier')).toHaveTextContent('—');
    expect(screen.getAllByRole('heading', { level: 4 }).map((heading) => heading.textContent)).toEqual(['Overview', 'Metadata Statement']);
    expect(screen.getByRole('button', { name: 'Raw' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Raw' })).toHaveAttribute('title', 'Raw authenticator data unavailable');
  });

  it('shows the entry as MDS publishes it, titled as the window was, and gives focus back to Raw', async () => {
    const entry = L1();
    renderEntry(entry);
    const raw = screen.getByRole('button', { name: 'Raw' });
    await userEvent.click(raw);

    const dialog = await screen.findByRole('dialog', { name: 'Fixture Security Key L1 – Authenticator Raw Data' });
    expect(dialog).toHaveTextContent(`AAGUID: ${entry.aaguid} • FIDO2`);
    const text = dialog.querySelector('pre')!.textContent!;
    expect(text).toBe(stringifyAuthenticatorRawData(getAuthenticatorRawData(entry)));
    expect(JSON.parse(text).metadataStatement.attestationRootCertificates).toEqual(entry.attestationCertificates);
    expect(within(dialog).getByRole('button', { name: 'Copy Raw authenticator metadata' })).toBeInTheDocument();

    const saved: Blob[] = [];
    Object.assign(URL, { createObjectURL: (blob: Blob) => (saved.push(blob), 'blob:x'), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('aaguid-f1d0f1d0-0000-4000-8000-000000000001.json');
    });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Download JSON' }));
    expect(click).toHaveBeenCalledTimes(1);
    await expect(saved[0].text()).resolves.toBe(text);
    click.mockRestore();

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(raw).toHaveFocus();
  });

  it('keeps a condensed header in view once the title has scrolled under the top bar', async () => {
    const observers: { callback: IntersectionObserverCallback; options?: IntersectionObserverInit; disconnect: ReturnType<typeof vi.fn> }[] = [];
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        disconnect = vi.fn();
        constructor(callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
          observers.push({ callback, options, disconnect: this.disconnect });
        }
        observe() {}
      },
    );
    const header = document.createElement('header');
    header.setAttribute('data-shell-header', '');
    header.getBoundingClientRect = () => ({ bottom: 57 }) as DOMRect;
    document.body.append(header);
    const entry = L1();
    const { onBack } = renderEntry(entry);

    const bar = document.querySelector<HTMLElement>('[data-condensed-header]')!;
    expect(bar).not.toBeVisible();
    expect(bar.style.top).toBe('57px');
    expect(observers[0].options).toEqual({ rootMargin: '-57px 0px 0px 0px' });

    const scroll = (isIntersecting: boolean, top: number) =>
      act(() => observers.at(-1)!.callback([{ isIntersecting, boundingClientRect: { top } } as IntersectionObserverEntry], {} as IntersectionObserver));
    scroll(false, 200);
    expect(bar).not.toBeVisible();
    scroll(false, -40);
    expect(bar).toBeVisible();
    expect(within(bar).getByText('Fixture Security Key L1')).toHaveAttribute('title', 'Fixture Security Key L1');
    expect(within(bar).getByText(`AAGUID: ${entry.aaguid} • FIDO2`)).toBeInTheDocument();

    const raw = within(bar).getByRole('button', { name: 'Raw' });
    await userEvent.click(raw);
    await screen.findByRole('dialog');
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(raw).toHaveFocus());
    await userEvent.click(within(bar).getByRole('button', { name: 'Back' }));
    expect(onBack).toHaveBeenCalledTimes(1);

    act(() => window.dispatchEvent(new Event('resize')));
    expect(observers[0].disconnect).toHaveBeenCalled();
    expect(observers).toHaveLength(2);
    scroll(true, 0);
    expect(bar).not.toBeVisible();
    header.remove();
  });

  it('keeps the condensed header away while a certificate covers the entry', () => {
    let report: IntersectionObserverCallback = () => {};
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(callback: IntersectionObserverCallback) {
          report = callback;
        }
        observe() {}
        disconnect() {}
      },
    );
    const entry = L1();
    const page = (active: boolean) => (
      <EntryPage entryId={entry.entryId} detail={{ phase: 'found', entry }} onBack={vi.fn()} onRetry={vi.fn()} active={active} />
    );
    const { rerender } = renderPage(page(true));
    act(() => report([{ isIntersecting: false, boundingClientRect: { top: -40 } } as IntersectionObserverEntry], {} as IntersectionObserver));
    const bar = document.querySelector<HTMLElement>('[data-condensed-header]')!;
    expect(bar).toBeVisible();
    rerender(
      <>
        <div id="app-root">{page(false)}</div>
        <div id="overlay-root" />
      </>,
    );
    expect(document.querySelector<HTMLElement>('[data-condensed-header]')).not.toBeVisible();
  });

  it('says it is opening while the list loads and locating while the server is asked', () => {
    const { rerender } = render(<EntryPage entryId="aaguid:x" detail={{ phase: 'waiting' }} onBack={vi.fn()} onRetry={vi.fn()} />);
    expect(screen.getByRole('status')).toHaveTextContent('Opening authenticator metadata...');
    rerender(<EntryPage entryId="aaguid:x" detail={{ phase: 'resolving' }} onBack={vi.fn()} onRetry={vi.fn()} />);
    expect(screen.getByRole('status')).toHaveTextContent('Locating metadata entry...');
  });

  it('says the server has no such entry, or could not answer, with Retry', async () => {
    const missing: EntryDetail = { phase: 'missing', message: 'Metadata entry not found.' };
    const onRetry = vi.fn();
    const { rerender } = render(<EntryPage entryId="aaguid:x" detail={missing} onBack={vi.fn()} onRetry={onRetry} />);
    expect(screen.getByRole('heading', { level: 3, name: 'Authenticator metadata not found.' })).toHaveFocus();
    expect(screen.getByRole('alert')).toHaveTextContent('Metadata entry not found.');
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();

    rerender(<EntryPage entryId="aaguid:x" detail={{ phase: 'failed', message: 'The server is unavailable. Try again in a moment.' }} onBack={vi.fn()} onRetry={onRetry} />);
    expect(screen.getByRole('heading', { level: 3, name: 'Unable to open authenticator metadata.' })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveClass('text-danger');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<EntryPage entryId="aaguid:x" detail={{ phase: 'missing', message: '' }} onBack={vi.fn()} onRetry={onRetry} />);
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

describe('the MDS entry page: what an entry may lack', () => {
  it('shows a level with nothing after it', () => {
    renderEntry(entryNamed('Fixture Uncertified Key'));
    expect(field(section('overview'), 'Certification')).toHaveTextContent(/^NOT FIDO Certified$/);
  });

  it('shows a method known only by its accuracy, and a descriptor or a version line alone', () => {
    renderEntry({
      ...L1(),
      metadataStatement: { userVerificationDetails: [[{ caDesc: { base: 36, minLength: 4 } }]] },
      statusReports: [
        { status: 'FIDO_CERTIFIED', url: 'https://example.com/only-the-url' },
        { status: 'FIDO_CERTIFIED', certificationPolicyVersion: '1.4.0' },
      ],
    } as unknown as MdsEntry);
    const combination = section('userVerification').querySelector('[data-combination]')!;
    expect(combination).toHaveTextContent(/^Combination 1Base: 36 • Min length: 4$/);
    expect(combination.querySelector('.font-mono')).toBeNull();
    const [urlOnly, versionOnly] = within(section('statusReports')).getAllByRole('row').slice(1);
    expect(within(urlOnly).getAllByRole('cell')[4]).toHaveTextContent(/^https:\/\/example.com\/only-the-url$/);
    expect(within(versionOnly).getAllByRole('cell')[4]).toHaveTextContent(/^Policy: 1.4.0$/);
  });
});

describe('an entry the list does not hold', () => {
  const uploaded = { ...entryNamed('Fixture Certified Key'), entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000099', name: 'Fixture Uploaded Key' };

  function renderSection(entryId: string) {
    const close = vi.fn();
    renderPage(
      <ToastProvider>
        <div role="tablist" aria-label="Sections">
          <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
            FIDO MDS Authenticators
          </button>
        </div>
        <MdsSection active route={{ path: [entryId], open: vi.fn(), close, replace: vi.fn(), closeAll: vi.fn() }} />
      </ToastProvider>,
    );
    return { close };
  }

  it('asks the server once the list has loaded, and shows what it answers', async () => {
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/resolve': resolveFrom([...FIXTURE_ENTRIES, uploaded as MdsEntry]) }));
    renderSection(uploaded.entryId);
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Uploaded Key' })).toBeInTheDocument();
    expect(fetch.mock.calls.map(([url]) => String(url))).toContain(
      '/api/mds/metadata/resolve?entryId=aaguid%3Af1d0f1d0-0000-4000-8000-000000000099',
    );
  });

  it('asks again after a failure, and says what failed meanwhile', async () => {
    let fail = true;
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/resolve': (init, url) =>
          fail ? json({ error: 'Metadata resolution failed.' }, 500) : resolveFrom([uploaded as MdsEntry])(init, url),
      }),
    );
    renderSection(uploaded.entryId);
    expect(await screen.findByRole('heading', { level: 3, name: 'Unable to open authenticator metadata.' })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Metadata resolution failed.');

    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Uploaded Key' })).toBeInTheDocument();
  });

  it('says a request that could not be sent failed', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/resolve': () => {
          throw new TypeError('Failed to fetch');
        },
      }),
    );
    renderSection('aaguid:unreachable');
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to fetch');
  });

  it('asks the server even when the list failed to load', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({}),
        '/api/mds/metadata/explorer/full': () => json(null, 502),
        '/api/mds/metadata/resolve': resolveFrom([uploaded as MdsEntry]),
      }),
    );
    renderSection(uploaded.entryId);
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Uploaded Key' })).toBeInTheDocument();
  });

  it('says the entry is not found when the server answers without one, and a failure that is not an error', async () => {
    stubFetch(fixtureRoutes({ '/api/mds/metadata/resolve': () => json({ entry: null }) }));
    renderSection('aaguid:unanswered');
    expect(await screen.findByRole('heading', { level: 3, name: 'Authenticator metadata not found.' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('says a failure that is not an error without a sentence of its own', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/resolve': () => {
          throw 'offline';
        },
      }),
    );
    renderSection('aaguid:unreachable');
    expect(await screen.findByRole('heading', { level: 3, name: 'Unable to open authenticator metadata.' })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('forgets an answer for an entry no longer shown', async () => {
    let release!: (response: Response) => void;
    stubFetch(fixtureRoutes({ '/api/mds/metadata/resolve': () => new Promise<Response>((resolve) => (release = resolve)) }));
    const view = (entryId: string) => (
      <ToastProvider>
        <div role="tablist" aria-label="Sections">
          <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
            FIDO MDS Authenticators
          </button>
        </div>
        <MdsSection active route={{ path: [entryId], open: vi.fn(), close: vi.fn(), replace: vi.fn(), closeAll: vi.fn() }} />
      </ToastProvider>
    );
    const { rerender } = renderPage(view('aaguid:first'));
    await screen.findByText('Locating metadata entry...');
    // The sentence shows before the request is sent; under load the request can come later.
    await waitFor(() => expect(release).toBeTypeOf('function'));
    const first = release;
    rerender(
      <>
        <div id="app-root">{view('aaguid:second')}</div>
        <div id="overlay-root" />
      </>,
    );
    await act(async () => first(json({ entry: { ...L1(), entryId: 'aaguid:first', name: 'Too late' } })));
    expect(screen.queryByRole('heading', { level: 3, name: 'Too late' })).toBeNull();
    expect(screen.getByText('Locating metadata entry...')).toBeInTheDocument();
  });

  it('asks the server for a listed entry that came without its detail', async () => {
    const light = { ...L1(), metadataStatement: null, isLightweightEntry: true };
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/explorer/full': () => json({ meta: { entryCount: 1 }, entries: [light] }),
        '/api/mds/metadata/info': () => json({}),
      }),
    );
    renderSection(light.entryId);
    await waitFor(() => expect(screen.getAllByRole('heading', { level: 4 }).length).toBeGreaterThan(2));
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeInTheDocument();
  });
});
