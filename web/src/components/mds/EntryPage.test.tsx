// The MDS entry page over the fixture's real entries (tests/fixtures/mds). The
// IDs name the items of docs/ui-parity/mds.md.
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, entryNamed, fixtureRoutes, json, resolveFrom, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { EntryPage } from './EntryPage';
import { rawData, rawText } from './entryModel';
import { MdsSection } from './MdsSection';
import type { MdsEntry } from './model';
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
  it('MDS-D1: shows Back, the name, the subtitle with copyable identifiers, and Raw', async () => {
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

  it('MDS-D1: names an AAID and a key identifier by their kind, and the blank name "Authenticator"', () => {
    const uaf = entryNamed('Fixture UAF Authenticator');
    renderEntry({ ...uaf, name: '  ' });
    expect(screen.getByRole('heading', { level: 3, name: 'Authenticator' })).toBeInTheDocument();
    const subtitle = document.querySelector<HTMLElement>('[data-entry-subtitle]')!;
    expect(subtitle).toHaveTextContent('ID:F1D0#0012');
    expect(subtitle).toHaveTextContent('Uaf');
    expect(within(subtitle).getByRole('button', { name: 'Copy AAID' })).toBeInTheDocument();
  });

  it('MDS-D3..D8: shows every section in the current page order', () => {
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

  it('MDS-D3: shows the overview, identifiers in Geist Mono with copy, certification as the list does', () => {
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

  it('MDS-D4: shows the statement, its long text across the row, key identifiers with copy, and the chip lists', () => {
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

  it('MDS-D5: lists the combinations, each method and what it says of its accuracy', () => {
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

  it('MDS-D6: numbers the certificates; without a page to open them they wait', () => {
    const entry = entryNamed('Fixture Key With Many Attestation Roots');
    renderEntry(entry);
    const buttons = within(section('certificates')).getAllByRole('button');
    expect(buttons.map((button) => button.textContent)).toEqual(Array.from({ length: 15 }, (_, index) => `Certificate ${index + 1}`));
    expect(buttons[0]).toBeDisabled();
  });

  it('MDS-D6/X1: a certificate button opens its page and is busy while it decodes', async () => {
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

  it('MDS-D7: shows getInfo: its AAGUID with copy, every number, the chips and the options', () => {
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

  it('MDS-D8: shows every status report, with its descriptor, URL and versions', () => {
    renderEntry(L1());
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
    expect(latest[4]).toHaveTextContent('Policy: 1.4.0 • Requirements: 1.3');
    expect(latest[4]).toHaveAttribute('data-label', 'Descriptor');
  });

  it('MDS-D9: reads "—" for a missing identifier and leaves out what an entry does not have', () => {
    renderEntry({ entryId: 'entry:bare', name: 'Bare' } as unknown as MdsEntry);
    expect(field(section('overview'), 'Identifier')).toHaveTextContent('—');
    expect(screen.getAllByRole('heading', { level: 4 }).map((heading) => heading.textContent)).toEqual(['Overview', 'Metadata Statement']);
    expect(screen.getByRole('button', { name: 'Raw' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Raw' })).toHaveAttribute('title', 'Raw authenticator data unavailable');
  });

  it('MDS-W1: shows the entry as MDS publishes it, titled as the window was, and gives focus back to Raw', async () => {
    const entry = L1();
    renderEntry(entry);
    const raw = screen.getByRole('button', { name: 'Raw' });
    await userEvent.click(raw);

    const dialog = await screen.findByRole('dialog', { name: 'Fixture Security Key L1 – Authenticator Raw Data' });
    expect(dialog).toHaveTextContent(`AAGUID: ${entry.aaguid} • FIDO2`);
    const text = dialog.querySelector('pre')!.textContent!;
    expect(text).toBe(rawText(rawData(entry)));
    expect(JSON.parse(text).metadataStatement.attestationRootCertificates).toEqual(entry.attestationCertificates);
    expect(within(dialog).getByRole('button', { name: 'Copy Raw authenticator metadata' })).toBeInTheDocument();

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(raw).toHaveFocus();
  });

  it('MDS-D1: keeps a condensed header in view once the title has scrolled under the top bar', async () => {
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

  it('MDS-J2: says it is opening while the list loads and locating while the server is asked', () => {
    const { rerender } = render(<EntryPage entryId="aaguid:x" detail={{ phase: 'waiting' }} onBack={vi.fn()} onRetry={vi.fn()} />);
    expect(screen.getByRole('status')).toHaveTextContent('Opening authenticator metadata...');
    rerender(<EntryPage entryId="aaguid:x" detail={{ phase: 'resolving' }} onBack={vi.fn()} onRetry={vi.fn()} />);
    expect(screen.getByRole('status')).toHaveTextContent('Locating metadata entry...');
  });

  it('MDS-D2/J2: says the server has no such entry, or could not answer, with Retry', async () => {
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

describe('an entry the list does not hold (MDS-D2)', () => {
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
        <MdsSection active route={{ path: [entryId], open: vi.fn(), close }} />
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
