// Manage Trusted Metadata over the fixture snapshot.
import { act, createEvent, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, FIXTURE_INFO, FIXTURE_SNAPSHOT, SNAPSHOT_URL, fixtureRoutes, json, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { MdsSection } from './MdsSection';
import type { MdsEntry } from './model';

const UPLOADED = {
  ...FIXTURE_ENTRIES[0],
  entryId: 'aaguid:f1d0c0de-0000-4000-8000-00000000c0de',
  name: 'Fixture Uploaded Authenticator',
  id: 'f1d0c0de-0000-4000-8000-00000000c0de',
  source: 'session',
} as MdsEntry;
const WITH_UPLOAD = {
  meta: { ...FIXTURE_SNAPSHOT.meta, entryCount: 33, customEntryCount: 1, hasCustomEntries: true },
  entries: [UPLOADED, ...FIXTURE_ENTRIES],
};
const ITEM = {
  entry: {},
  source: { storedFilename: '0f1e.json', originalFilename: 'custom-metadata.json', uploadedAt: '2026-09-26T10:00:00+00:00' },
  legalHeader: 'Fixture.',
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

type Routes = Parameters<typeof fixtureRoutes>[0];

async function renderSection(routes: Routes = {}, { waitForRows = true } = {}) {
  const fetch = stubFetch(fixtureRoutes({ '/api/mds/metadata/custom': () => json({ items: [] }), ...routes }));
  renderPage(
    <ToastProvider>
      <div role="tablist" aria-label="Sections">
        <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
          FIDO MDS Authenticators
        </button>
      </div>
      <MdsSection active />
    </ToastProvider>,
  );
  if (waitForRows) await waitFor(() => expect(rowNames()).toHaveLength(32));
  return fetch;
}

const rowNames = () =>
  [...document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-entry-id]')].filter((row) => !row.hidden).map((row) => row.querySelector('a')?.textContent);
const manage = () => screen.getByRole('button', { name: 'Manage Metadata' });
const dialog = () => screen.getByRole('dialog', { name: 'Manage Trusted Metadata' });
const fileInput = () => document.querySelector<HTMLInputElement>('[data-mds-file-input]')!;
const message = () => document.querySelector('[data-mds-message]');
const status = () => screen.getAllByRole('status').find((element) => element.hasAttribute('data-variant'))!;
const file = (name: string, type = 'application/json') => new File(['{}'], name, { type });

async function openDialog() {
  await userEvent.click(manage());
  return dialog();
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Manage Trusted Metadata', () => {
  it('opens from Manage Metadata, takes focus, and Escape gives it back', async () => {
    await renderSection();
    expect(manage()).toHaveAttribute('aria-haspopup', 'dialog');
    expect(manage()).toHaveAttribute('aria-expanded', 'false');
    const panel = await openDialog();
    expect(manage()).toHaveAttribute('aria-expanded', 'true');
    expect(panel).toHaveFocus();

    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(manage()).toHaveFocus();
  });

  it('closes from its Close button', async () => {
    await renderSection();
    const panel = await openDialog();
    await userEvent.click(within(panel).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('says what it does and how files are chosen', async () => {
    await renderSection();
    const panel = await openDialog();
    expect(panel).toHaveTextContent(
      'Drop JSON metadata files here or select them from your device. Uploaded files are trusted only for this browser session.',
    );
    const browse = within(panel).getByRole('button', { name: 'Drop JSON files here or click to browse' });
    expect(browse).toHaveAccessibleDescription('Only .json files are accepted.');
    expect(within(panel).getByText('.json').tagName).toBe('CODE');
    expect(fileInput()).toHaveAttribute('accept', '.json,application/json');
    expect(fileInput()).toHaveAttribute('multiple');

    const click = vi.spyOn(fileInput(), 'click');
    await userEvent.click(browse);
    expect(click).toHaveBeenCalled();
  });

  it('lists the files this session uploaded, or says there are none', async () => {
    let items: unknown[] = [];
    await renderSection({ '/api/mds/metadata/custom': () => json({ items }) });
    let panel = await openDialog();
    expect(await within(panel).findByText('No custom metadata has been added yet.')).toBeInTheDocument();

    await userEvent.keyboard('{Escape}');
    items = [ITEM, { source: {} }];
    panel = await openDialog();
    expect(await within(panel).findByText('custom-metadata.json')).toBeInTheDocument();
    expect(panel).toHaveTextContent(`Uploaded ${new Date('2026-09-26T10:00:00+00:00').toLocaleString()} · Includes legal header`);
    expect(within(panel).getByRole('button', { name: 'Delete custom-metadata.json' })).toHaveAttribute('title', 'Delete custom-metadata.json');
    // An item without a stored name cannot be deleted.
    expect(within(panel).getByText('metadata.json')).toBeInTheDocument();
    expect(within(panel).getAllByRole('button', { name: /^Delete / })).toHaveLength(1);
  });

  it('keeps the list shown when it cannot be had', async () => {
    await renderSection({ '/api/mds/metadata/custom': () => Promise.reject(new TypeError('offline')) });
    const panel = await openDialog();
    expect(await within(panel).findByText('No custom metadata has been added yet.')).toBeInTheDocument();
  });

  it('uploads the chosen files and shows their entries at once', async () => {
    let listed: unknown[] = [];
    const fetch = await renderSection({
      '/api/mds/metadata/upload': () => {
        listed = [ITEM];
        return json({ items: [ITEM], snapshot: WITH_UPLOAD });
      },
      '/api/mds/metadata/custom': () => json({ items: listed }),
    });
    const panel = await openDialog();
    await userEvent.upload(fileInput(), file('custom-metadata.json'));

    await waitFor(() => expect(message()).toHaveTextContent('Metadata uploaded successfully.'));
    expect(message()).toHaveAttribute('data-variant', 'success');
    const [, init] = fetch.mock.calls.find(([url]) => url === '/api/mds/metadata/upload')!;
    expect(init?.method).toBe('POST');
    expect((init?.body as FormData).getAll('files').map((value) => (value as File).name)).toEqual(['custom-metadata.json']);

    await waitFor(() => expect(rowNames()).toContain('Fixture Uploaded Authenticator'));
    expect(status()).toHaveTextContent(/ Including 1 session metadata entry\. Custom metadata updated\.$/);
    expect(await within(panel).findByText('custom-metadata.json')).toBeInTheDocument();
  });

  it('says where an upload is while it runs', async () => {
    const answer = deferred<Response>();
    await renderSection({ '/api/mds/metadata/upload': () => answer.promise });
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    expect(document.querySelector('[data-mds-progress]')).toHaveTextContent('Uploading metadata…');
    expect(message()).toHaveTextContent('Uploading metadata…');
    expect(screen.getByRole('button', { name: 'Drop JSON files here or click to browse' })).toBeDisabled();

    await act(async () => answer.resolve(json({ items: [ITEM], snapshot: WITH_UPLOAD })));
    expect(document.querySelector('[data-mds-progress]')).toHaveTextContent('Completing metadata update...');
    await waitFor(() => expect(document.querySelector('[data-mds-progress]')).toBeNull());
  });

  it('passes on the warnings of an upload that partly worked', async () => {
    await renderSection({ '/api/mds/metadata/upload': () => json({ items: [ITEM], errors: ['b.json is not a JSON file.'], snapshot: WITH_UPLOAD }) });
    await openDialog();
    await userEvent.upload(fileInput(), [file('a.json'), file('b.json')]);
    await waitFor(() => expect(message()).toHaveTextContent('Metadata uploaded with warnings: b.json is not a JSON file.'));
    expect(message()).toHaveAttribute('data-variant', 'warning');
  });

  it('keeps the server reason for a refused upload', async () => {
    await renderSection({ '/api/mds/metadata/upload': () => json({ items: [], errors: ['a.json must contain a JSON object.'] }, 400) });
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    await waitFor(() => expect(message()).toHaveTextContent('a.json must contain a JSON object.'));
    expect(message()).toHaveAttribute('data-variant', 'error');
    expect(document.querySelector('[data-mds-progress]')).toHaveTextContent('Metadata update failed.');
  });

  it('says an upload failed when the request did', async () => {
    await renderSection({ '/api/mds/metadata/upload': () => Promise.reject(new TypeError('offline')) });
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    await waitFor(() => expect(message()).toHaveTextContent('Failed to upload metadata files.'));
  });

  it('loads the session list again when an upload answers without it', async () => {
    let uploaded = false;
    const fetch = await renderSection({
      '/api/mds/metadata/upload': () => {
        uploaded = true;
        return json({ items: [ITEM] });
      },
      '/api/mds/metadata/explorer/full': () => json(uploaded ? WITH_UPLOAD : FIXTURE_SNAPSHOT),
    });
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    await waitFor(() => expect(rowNames()).toContain('Fixture Uploaded Authenticator'));
    expect(fetch.mock.calls.at(-2)).toEqual(['/api/mds/metadata/explorer/full', { cache: 'reload' }]);
    expect(status()).toHaveTextContent(/ Custom metadata updated\.$/);
  });

  it('refuses files that are not JSON, and sends the others', async () => {
    const fetch = await renderSection({ '/api/mds/metadata/upload': () => json({ items: [ITEM], snapshot: WITH_UPLOAD }) });
    await openDialog();

    fireEvent.change(fileInput(), { target: { files: [new File(['x'], 'notes.txt', { type: 'text/plain' })] } });
    await waitFor(() => expect(message()).toHaveTextContent('Ignored non-JSON files: notes.txt'));
    expect(fetch.mock.calls.some(([url]) => url === '/api/mds/metadata/upload')).toBe(false);

    fireEvent.change(fileInput(), { target: { files: [] } });
    await waitFor(() => expect(message()).toHaveTextContent('Please select one or more JSON files.'));

    fireEvent.change(fileInput(), { target: { files: [new File(['x'], 'notes.txt'), file('a.json')] } });
    await waitFor(() => expect(message()).toHaveTextContent('Metadata uploaded successfully.'));
  });

  it('takes files dropped on the zone, lighting it up while they are over it', async () => {
    await renderSection({ '/api/mds/metadata/upload': () => json({ items: [ITEM], snapshot: WITH_UPLOAD }) });
    const panel = await openDialog();
    const zone = panel.querySelector<HTMLElement>('[data-mds-dropzone]')!;
    const dataTransfer = { files: [file('a.json')], dropEffect: 'none' };

    fireEvent.dragEnter(zone, { dataTransfer });
    expect(zone).toHaveAttribute('data-active', 'true');
    expect(dataTransfer.dropEffect).toBe('copy');
    // jsdom has no DragEvent, so the element the pointer went to is set by hand.
    const leave = (to: Element) => {
      const event = createEvent.dragLeave(zone, { dataTransfer });
      Object.defineProperty(event, 'relatedTarget', { value: to });
      fireEvent(zone, event);
    };
    leave(zone.querySelector('button')!);
    expect(zone).toHaveAttribute('data-active', 'true');
    leave(document.body);
    expect(zone).not.toHaveAttribute('data-active');

    fireEvent.dragOver(zone, { dataTransfer });
    fireEvent.drop(zone, { dataTransfer });
    expect(zone).not.toHaveAttribute('data-active');
    await waitFor(() => expect(message()).toHaveTextContent('Metadata uploaded successfully.'));
  });

  it('deletes an uploaded file, and the list and the table follow', async () => {
    let listed: unknown[] = [ITEM];
    const fetch = await renderSection({
      '/api/mds/metadata/custom': () => json({ items: listed }),
      '/api/mds/metadata/custom/0f1e.json': () => {
        listed = [];
        return json({ deleted: true, snapshot: FIXTURE_SNAPSHOT });
      },
    });
    const panel = await openDialog();
    await userEvent.click(await within(panel).findByRole('button', { name: 'Delete custom-metadata.json' }));

    await waitFor(() => expect(message()).toHaveTextContent('custom-metadata.json removed.'));
    expect(fetch.mock.calls.find(([url]) => url === '/api/mds/metadata/custom/0f1e.json')?.[1]?.method).toBe('DELETE');
    expect(await within(panel).findByText('No custom metadata has been added yet.')).toBeInTheDocument();
    expect(status()).toHaveTextContent(/ Custom metadata updated\.$/);
  });

  it('says a file was already gone, as a warning', async () => {
    await renderSection({
      '/api/mds/metadata/custom': () => json({ items: [ITEM] }),
      '/api/mds/metadata/custom/0f1e.json': () => json({ deleted: false, message: 'Metadata entry not found.' }, 404),
    });
    const panel = await openDialog();
    await userEvent.click(await within(panel).findByRole('button', { name: 'Delete custom-metadata.json' }));
    await waitFor(() => expect(message()).toHaveTextContent('Metadata entry not found.'));
    expect(message()).toHaveAttribute('data-variant', 'warning');
    expect(document.querySelector('[data-mds-progress]')).toHaveTextContent('No metadata changes detected.');
  });

  it('keeps the server reason for a refused delete, and says when the request failed', async () => {
    let fail: 'refuse' | 'throw' = 'refuse';
    await renderSection({
      '/api/mds/metadata/custom': () => json({ items: [ITEM] }),
      '/api/mds/metadata/custom/0f1e.json': () =>
        fail === 'refuse' ? json({ error: 'Invalid metadata filename.' }, 400) : Promise.reject(new TypeError('offline')),
    });
    const panel = await openDialog();
    await userEvent.click(await within(panel).findByRole('button', { name: 'Delete custom-metadata.json' }));
    await waitFor(() => expect(message()).toHaveTextContent('Invalid metadata filename.'));
    expect(message()).toHaveAttribute('data-variant', 'error');
    expect(document.querySelector('[data-mds-progress]')).toHaveTextContent('Metadata removal failed.');

    fail = 'throw';
    await userEvent.click(await within(panel).findByRole('button', { name: 'Delete custom-metadata.json' }));
    await waitFor(() => expect(message()).toHaveTextContent('Failed to delete metadata file.'));
  });

  it('loads the session list again when a delete answers without it', async () => {
    const fetch = await renderSection({
      '/api/mds/metadata/custom': () => json({ items: [ITEM] }),
      '/api/mds/metadata/custom/0f1e.json': () => json({ deleted: true }),
    });
    const panel = await openDialog();
    await userEvent.click(await within(panel).findByRole('button', { name: 'Delete custom-metadata.json' }));
    await waitFor(() => expect(message()).toHaveTextContent('custom-metadata.json removed.'));
    expect(fetch.mock.calls.some(([url, init]) => url === '/api/mds/metadata/explorer/full' && init?.cache === 'reload')).toBe(true);
  });

  it('shows an upload over a load still out, and drops that load when it comes', async () => {
    const snapshot = deferred<Response>();
    await renderSection(
      {
        '/api/mds/metadata/info': () => json(FIXTURE_INFO),
        [SNAPSHOT_URL]: () => snapshot.promise,
        '/api/mds/metadata/upload': () => json({ items: [ITEM], snapshot: WITH_UPLOAD }),
      },
      { waitForRows: false },
    );
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    await waitFor(() => expect(rowNames()).toHaveLength(33));

    await act(async () => snapshot.resolve(json(FIXTURE_SNAPSHOT)));
    expect(rowNames()).toHaveLength(33);
  });

  it('drops a failed load an upload has overtaken', async () => {
    const snapshot = deferred<Response>();
    await renderSection(
      {
        '/api/mds/metadata/info': () => json(FIXTURE_INFO),
        [SNAPSHOT_URL]: () => snapshot.promise,
        '/api/mds/metadata/explorer/full': () => json({ error: 'Late.' }, 500),
        '/api/mds/metadata/upload': () => json({ items: [ITEM], snapshot: WITH_UPLOAD }),
      },
      { waitForRows: false },
    );
    await openDialog();
    await userEvent.upload(fileInput(), file('a.json'));
    await waitFor(() => expect(rowNames()).toHaveLength(33));

    await act(async () => snapshot.resolve(json(null, 404)));
    expect(status()).not.toHaveTextContent('Late.');
  });
});
