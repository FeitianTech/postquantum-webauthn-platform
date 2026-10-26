// The FIDO MDS section's loading and status line, over the fixture snapshot
// (tests/fixtures/mds).
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, FIXTURE_INFO, FIXTURE_SNAPSHOT, NO_UPLOADS, SNAPSHOT_URL, fixtureRoutes, json, stubFetch } from '@/test/mds';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
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
  it('shows the section\'s title and description', () => {
    stubFetch(fixtureRoutes());
    renderSection();
    const panel = screen.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
    expect(within(panel).getByRole('heading', { level: 2 })).toHaveTextContent('FIDO MDS Authenticators');
    expect(panel).toHaveTextContent('Explore the authenticators published by the FIDO Metadata Service (MDS).');
  });

  it('asks what to start from, then loads the packaged snapshot for a session without uploads', async () => {
    const fetch = stubFetch(fixtureRoutes());
    renderSection();

    await waitFor(() => expect(bodyRows()).toHaveLength(FIXTURE_ENTRIES.length));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      [SNAPSHOT_URL, 'default'],
    ]);
  });

  it('asks only for the packaged list, at its one URL, while the session has no uploads', async () => {
    const fetch = stubFetch(fixtureRoutes());
    renderSection();

    await waitFor(() => expect(bodyRows()).toHaveLength(FIXTURE_ENTRIES.length));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      [SNAPSHOT_URL, 'default'],
    ]);
  });

  it('counts the entries and says what it loaded, with the legal header as a tooltip', async () => {
    stubFetch(fixtureRoutes());
    renderSection();

    await waitFor(() => expect(status()).toHaveAttribute('data-variant', 'success'));
    expect(status()).toHaveTextContent(/^Loaded 32 authenticators\. Last updated .+\.$/);
    expect(status()).toHaveAttribute('title', FIXTURE_SNAPSHOT.meta!.legalHeader as string);
    expect(screen.getByText(/^Entries:/)).toHaveTextContent('Entries: 32 of 32 total');
  });

  it('says the snapshot it is about to load, then that it is loading, with a loading row', async () => {
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

  it('waits until the section is first shown, and loads once', async () => {
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

  it('asks the session its own entries beside the packaged list when it has uploads', async () => {
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => json({ ...FIXTURE_INFO, customEntriesState: 'present' }) }));
    renderSection();
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(fetch.mock.calls.map(([url, init]) => [url, init?.cache])).toEqual([
      ['/api/mds/metadata/info', 'no-store'],
      [SNAPSHOT_URL, 'default'],
      ['/api/mds/metadata/explorer/custom', 'no-store'],
    ]);
  });

  it('shows the uploads alone when the server has no packaged list', async () => {
    const upload = { ...FIXTURE_ENTRIES[0], entryId: 'aaguid:f1d0c0de-0000-4000-8000-00000000c0de', aaguid: 'f1d0c0de-0000-4000-8000-00000000c0de' } as MdsEntry;
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({ customEntriesState: 'present' }),
        [SNAPSHOT_URL]: () => json({ error: 'gone' }, 404),
        '/api/mds/metadata/explorer/custom': () =>
          json({ meta: { entryCount: 1, baseEntryCount: 0, customEntryCount: 1, hasCustomEntries: true }, entries: [upload] }),
      }),
    );
    renderSection();

    await waitFor(() => expect(bodyRows()).toHaveLength(1));
    expect(status()).toHaveTextContent('Loaded 1 authenticators. Including 1 session metadata entry.');
  });

  it('without what to start from, asks both parts and keeps the first sentence', async () => {
    const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => Promise.reject(new TypeError('offline')) }));
    renderSection();
    await waitFor(() => expect(bodyRows()).toHaveLength(32));
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(['/api/mds/metadata/info', SNAPSHOT_URL, '/api/mds/metadata/explorer/custom']);
  });

  it('shows a failure, in the line and in the list, and Retry asks again, forced', async () => {
    let failing = true;
    const fetch = stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({ ...FIXTURE_INFO, customEntriesState: 'unknown' }),
        '/api/mds/metadata/explorer/custom': () => (failing ? json({ error: 'The server is resting.' }, 503) : json(NO_UPLOADS)),
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
    expect(fetch.mock.calls.at(-1)).toEqual(['/api/mds/metadata/explorer/custom', { cache: 'reload' }]);
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('words a status without an error of its own', async () => {
    stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => json({}), '/api/mds/metadata/explorer/custom': () => json(null, 502) }));
    renderSection();
    await waitFor(() => expect(status()).toHaveTextContent('Explorer request failed with status 502.'));
  });

  it('words a packaged list that cannot be had', async () => {
    stubFetch(fixtureRoutes({ [SNAPSHOT_URL]: () => json({ error: 'The list is resting.' }, 503) }));
    renderSection();
    await waitFor(() => expect(status()).toHaveTextContent('The list is resting.'));
    expect(status()).toHaveAttribute('data-variant', 'error');
  });

  it('shows the missing-snapshot sentence when there is nothing to list', async () => {
    stubFetch(
      fixtureRoutes({
        '/api/mds/metadata/info': () => json({ customEntriesState: 'none' }),
        [SNAPSHOT_URL]: () => json({ error: 'nope' }, 404),
      }),
    );
    renderSection();

    await waitFor(() => expect(status()).toHaveTextContent('Loaded 0 authenticators.'));
    expect(status()).toHaveAttribute('data-variant', 'info');
    expect(screen.getByText('Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present.')).toBeInTheDocument();
    expect(screen.getByText(/^Entries:/)).toHaveTextContent('Entries: 0');
  });
});
