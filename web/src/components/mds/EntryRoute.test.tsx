// Opening an MDS entry from the list and going back, through the whole page:
// the URL (#mds/<entryId>), the history, and the list found as it was.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';
import { entryNamed, fixtureRoutes, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

function renderApp(hash: string) {
  window.history.replaceState({ fromNext: true }, '', `/beta${hash}`);
  stubFetch(fixtureRoutes());
  renderPage(
    <ToastProvider>
      <AppShell />
    </ToastProvider>,
  );
}

const list = () => document.querySelector<HTMLElement>('[data-mds-list]')!;
const frame = () => document.querySelector<HTMLDivElement>('[data-mds-frame]')!;
const link = (entryId: string) => document.querySelector<HTMLElement>(`[data-entry-link="${CSS.escape(entryId)}"]`)!;
const loaded = () => waitFor(() => expect(link('aaguid:f1d0f1d0-0000-4000-8000-000000000001')).toBeTruthy());

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('an MDS entry in the URL', () => {
  it('opens from its row as a new history entry, and the page Back returns to the list as it was', async () => {
    renderApp('#mds');
    await loaded();
    const entry = entryNamed('Fixture U2F Key');
    await userEvent.type(screen.getByRole('searchbox', { name: 'Name' }), 'Fixture');
    frame().scrollTop = 120;
    const length = window.history.length;

    await userEvent.click(link(entry.entryId));
    expect(window.location.hash).toBe('#mds/akid:f1d0000000000000000000000000000000000011');
    expect(window.history.length).toBe(length + 1);
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: true });
    expect(list()).not.toBeVisible();
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture U2F Key' })).toHaveFocus();
    frame().scrollTop = 0;

    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(list()).toBeVisible());
    expect(window.location.hash).toBe('#mds');
    expect(link(entry.entryId)).toHaveFocus();
    expect(frame().scrollTop).toBe(120);
    expect(screen.getByRole('searchbox', { name: 'Name' })).toHaveValue('Fixture');
  });

  it('closes with the browser Back too, and opens again with Forward', async () => {
    renderApp('#mds');
    await loaded();
    const entry = entryNamed('Fixture Security Key L2');
    await userEvent.click(link(entry.entryId));
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L2' })).toBeInTheDocument();

    act(() => window.history.back());
    await waitFor(() => expect(list()).toBeVisible());
    expect(link(entry.entryId)).toHaveFocus();

    act(() => window.history.forward());
    await waitFor(() => expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L2' })).toBeInTheDocument());
  });

  it('opens an entry a link names once the list has loaded, and Back leaves no entry behind', async () => {
    renderApp('#mds/aaid:F1D0%230012');
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture UAF Authenticator' })).toBeInTheDocument();
    expect(list()).not.toBeVisible();
    const length = window.history.length;

    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(window.location.hash).toBe('#mds');
    expect(window.history.length).toBe(length);
    expect(list()).toBeVisible();
    expect(link('aaid:F1D0#0012')).toHaveFocus();
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({ block: 'center' });
  });

  it('says when a link names an entry the list does not have', async () => {
    renderApp('#mds/aaguid:not-listed');
    expect(await screen.findByRole('heading', { level: 3, name: 'Authenticator not found' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(list()).toBeVisible();
  });

  it('leaves the entry when another section is chosen', async () => {
    renderApp('#mds');
    await loaded();
    await userEvent.click(link('aaguid:f1d0f1d0-0000-4000-8000-000000000002'));
    await userEvent.click(within(screen.getByRole('tablist', { name: 'Sections' })).getByRole('tab', { name: 'Codec' }));
    expect(window.location.hash).toBe('#codec');
    await userEvent.click(within(screen.getByRole('tablist', { name: 'Sections' })).getByRole('tab', { name: 'FIDO MDS Authenticators' }));
    expect(list()).toBeVisible();
  });
});
