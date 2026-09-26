// The FIDO MDS section's loading and status line, over the fixture snapshot
// (tests/fixtures/mds). The IDs name the items of docs/ui-parity/mds.md.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, FIXTURE_INFO, FIXTURE_SNAPSHOT, SNAPSHOT_URL, fixtureRoutes, json, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { MdsSection } from './MdsSection';

function renderSection(active = true) {
  return renderPage(
    <ToastProvider>
      <div role="tablist" aria-label="Sections">
        <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
          FIDO MDS Authenticators
        </button>
      </div>
      <MdsSection active={active} />
    </ToastProvider>,
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

const status = () => screen.getAllByRole('status').find((element) => element.hasAttribute('data-variant'))!;
const bodyRows = () => screen.getAllByRole('row').filter((row) => row.hasAttribute('data-entry-id') && !row.hidden);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the MDS section', () => {
  it('MDS-H2: shows the title and description the current UI shows', () => {
    stubFetch(fixtureRoutes());
    renderSection();
    const panel = screen.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
    expect(within(panel).getByRole('heading', { level: 2 })).toHaveTextContent('FIDO MDS Authenticators');
    expect(panel).toHaveTextContent('Explore the authenticators published by the FIDO Metadata Service (MDS).');
  });

  it('MDS-L1/L3: asks what to start from, then loads the packaged snapshot for a session without uploads', async () => {
    const fetch = stubFetch(fixtureRoutes());
    renderSection();

    await waitFor(() => expect(bodyRows()).toHaveLength(FIXTURE_ENTRIES.length));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      [SNAPSHOT_URL, 'default'],
    ]);
  });

  it('MDS-L3: asks the API alone when the server names no packaged snapshot', async () => {
    const { snapshotUrl: _url, ...info } = FIXTURE_INFO;
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => json(info) }));
    renderSection();

    await waitFor(() => expect(bodyRows()).toHaveLength(FIXTURE_ENTRIES.length));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      ['/api/mds/metadata/explorer/full', 'no-store'],
    ]);
  });

  it('MDS-H3/S4: counts the entries and says what it loaded, with the legal header as a tooltip', async () => {
    stubFetch(fixtureRoutes());
    renderSection();

    await waitFor(() => expect(status()).toHaveAttribute('data-variant', 'success'));
    expect(status()).toHaveTextContent(/^Loaded 32 authenticators\. Last updated .+\.$/);
    expect(status()).toHaveAttribute('title', FIXTURE_SNAPSHOT.meta!.legalHeader as string);
    expect(screen.getByText(/^Entries:/)).toHaveTextContent('Entries: 32 of 32 total');
  });

  it('MDS-S1/S2/S3/E1: says the snapshot it is about to load, then that it is loading, with a loading row', async () => {
    const snapshot = deferred<Response>();
    const info = deferred<Response>();
    stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => info.promise, [SNAPSHOT_URL]: () => snapshot.promise }));
    renderSection();

    expect(status()).toHaveTextContent('Packaged FIDO metadata is available. Explorer data is loading in the background.');
    expect(screen.getByText('Authenticator metadata is loading…')).toBeInTheDocument();
    expect(screen.getByText(/^Entries:/)).toHaveTextContent('Entries: 0');

    await act(async () => info.resolve(json(FIXTURE_INFO)));
    expect(status()).toHaveTextContent('Loading authenticator explorer…');

    await act(async () => snapshot.resolve(json(FIXTURE_SNAPSHOT)));
    expect(screen.queryByText('Authenticator metadata is loading…')).toBeNull();
    expect(bodyRows()).toHaveLength(32);
  });

  it('MDS-L2: waits until the section is first shown, and loads once', async () => {
    const fetch = stubFetch(fixtureRoutes());
    const { rerender } = renderSection(false);
    expect(fetch).not.toHaveBeenCalled();

    const again = (active: boolean) =>
      rerender(
        <>
          <div id="app-root">
            <ToastProvider>
              <div role="tablist" aria-label="Sections">
                <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
                  FIDO MDS Authenticators
                </button>
              </div>
              <MdsSection active={active} />
            </ToastProvider>
          </div>
          <div id="overlay-root" />
        </>,
      );
    again(true);
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    again(false);
    again(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('MDS-L3: asks the session its own list when it has uploads', async () => {
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => json({ ...FIXTURE_INFO, customEntriesState: 'present' }) }));
    renderSection();
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      ['/api/mds/metadata/explorer/full', 'no-store'],
    ]);
  });

  it('MDS-L4: falls back to the session list when the packaged file cannot be had', async () => {
    const fetch = stubFetch(fixtureRoutes({ [SNAPSHOT_URL]: () => json({ error: 'gone' }, 404) }));
    renderSection();
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(['/api/mds/metadata/info', SNAPSHOT_URL, '/api/mds/metadata/explorer/full']);
  });

  it('MDS-L1: without what to start from, asks the session list and keeps the first sentence', async () => {
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => Promise.reject(new TypeError('offline')) }));
    renderSection();
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(['/api/mds/metadata/info', '/api/mds/metadata/explorer/full']);
  });

  it('MDS-S6/S7: shows a failure, in the line and in the list, and Retry asks again, forced', async () => {
    let failing = true;
    const fetch = stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({ ...FIXTURE_INFO, customEntriesState: 'unknown' }),
        '/api/mds/metadata/explorer/full': () => (failing ? json({ error: 'The server is resting.' }, 503) : json(FIXTURE_SNAPSHOT)),
      }),
    );
    renderSection();

    await waitFor(() => expect(status()).toHaveAttribute('data-variant', 'error'));
    expect(status()).toHaveTextContent('The server is resting.');
    const retries = screen.getAllByRole('button', { name: 'Retry' });
    expect(retries).toHaveLength(2);

    failing = false;
    await userEvent.click(retries[0]);
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(status()).toHaveTextContent(/ Explorer refreshed\.$/);
    expect(fetch.mock.calls.at(-1)).toEqual(['/api/mds/metadata/explorer/full', { cache: 'reload' }]);
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('MDS-S6: words a status without an error of its own', async () => {
    stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => json({}), '/api/mds/metadata/explorer/full': () => json(null, 502) }));
    renderSection();
    await waitFor(() => expect(status()).toHaveTextContent('Explorer request failed with status 502.'));
  });

  it('MDS-S5/E3: shows the missing-snapshot sentence when there is nothing to list', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({ snapshotUrl: SNAPSHOT_URL, customEntriesState: 'none' }),
        [SNAPSHOT_URL]: () => json({ error: 'nope' }, 404),
        '/api/mds/metadata/explorer/full': () =>
          json({ meta: { entryCount: 0, baseEntryCount: 0, customEntryCount: 0, hasCustomEntries: false }, entries: [] }),
      }),
    );
    renderSection();

    await waitFor(() => expect(status()).toHaveTextContent('Loaded 0 authenticators.'));
    expect(status()).toHaveAttribute('data-variant', 'info');
    expect(screen.getByText('Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present.')).toBeInTheDocument();
    expect(screen.getByText(/^Entries:/)).toHaveTextContent('Entries: 0');
  });

  it('MDS-S5: shows the server words for a 404 of the session list', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({}),
        '/api/mds/metadata/explorer/full': () => json({ error: 'Verified metadata snapshot is not available.' }, 404),
      }),
    );
    renderSection();

    await waitFor(() => expect(status()).toHaveTextContent('Verified metadata snapshot is not available.'));
    expect(screen.getByText('Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present.')).toBeInTheDocument();
  });
});
