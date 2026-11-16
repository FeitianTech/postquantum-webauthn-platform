// Opening an MDS entry from the list and going back, through the whole page:
// the URL (#mds/<entryId>), the history, and the list found as it was.
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { forgetCompletedRecords } from '@/components/credentials/detail/useCredentialDetail';
import { renderApp } from '@/test/app';
import { DETAIL_SCENARIO, decodeRoute, keepRecords, savedRecord, warmUpRoutes } from '@/test/credentials';
import type { Route } from '@/test/fetch';
import { entryNamed, fixtureRoutes, stubFetch } from '@/test/mds';

// The decoder's answers, late once `slow` is set: details mounted again then
// compose their level after they have opened.
let slow = false;
function decoder(): Route {
  const decode = decodeRoute();
  return async (init, url) => {
    if (slow) await new Promise((resolve) => setTimeout(resolve, 200));
    return decode(init, url);
  };
}

function openAt(hash: string, records: object[] = []) {
  slow = false;
  keepRecords(records);
  stubFetch(fixtureRoutes({ ...warmUpRoutes(), '/api/codec': decoder() }));
  renderApp(hash);
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
  forgetCompletedRecords();
});

describe('an MDS entry in the URL', () => {
  it('opens from its row as a new history entry, and the page Back returns to the list as it was', async () => {
    openAt('#mds');
    await loaded();
    const entry = entryNamed('Fixture U2F Key');
    await userEvent.type(screen.getByRole('searchbox', { name: 'Name' }), 'Fixture');
    frame().scrollTop = 120;
    const length = window.history.length;

    await userEvent.click(link(entry.entryId));
    expect(window.location.hash).toBe('#mds/akid:f1d0000000000000000000000000000000000011');
    expect(window.history.length).toBe(length + 1);
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: 1 });
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
    openAt('#mds');
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
    openAt('#mds/aaid:F1D0%230012');
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

  it('asks the server for an entry the list does not have, and says when it has none', async () => {
    openAt('#mds/aaguid:not-listed');
    expect(await screen.findByRole('heading', { level: 3, name: 'Authenticator metadata not found.' })).toBeInTheDocument();
    expect(screen.getByText('Metadata entry not found.')).toBeInTheDocument();
    expect(screen.getByText('aaguid:not-listed')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(list()).toBeVisible();
  });

  it('leaves the entry when another section is chosen', async () => {
    openAt('#mds');
    await loaded();
    await userEvent.click(link('aaguid:f1d0f1d0-0000-4000-8000-000000000002'));
    await userEvent.click(within(screen.getByRole('tablist', { name: 'Sections' })).getByRole('tab', { name: 'Codec' }));
    expect(window.location.hash).toBe('#codec');
    await userEvent.click(within(screen.getByRole('tablist', { name: 'Sections' })).getByRole('tab', { name: 'FIDO MDS Authenticators' }));
    expect(list()).toBeVisible();
  });
});

describe('a saved credential\'s details over an MDS entry', () => {
  const L1 = 'aaguid:f1d0f1d0-0000-4000-8000-000000000001';
  // A credential of the L1 fixture's AAGUID, which FIDO MDS knows.
  const KEY_L1 = savedRecord(DETAIL_SCENARIO, { userName: 'key@example.com', aaguidHex: 'f1d0f1d0000040008000000000000001', attestationSummary: { rootValid: true } });
  const at = (entryId: string) => `#mds/${entryId}/credential/id:${KEY_L1.credentialIdBase64Url}`;

  it('open at their own URL over the entry, which stays under them, and × closes them back to it', async () => {
    openAt(at(L1), [KEY_L1]);
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByRole('button', { name: 'Show registration details' });
    expect(within(dialog).getByRole('heading', { level: 3, name: 'key@example.com' })).toBeVisible();
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1', hidden: true })).toBeInTheDocument();
    // FIDO MDS would only open this entry again.
    expect(within(dialog).queryByRole('button', { name: 'FIDO MDS' })).toBeNull();

    await userEvent.click(within(dialog).getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(window.location.hash).toBe(`#mds/${L1}`);
    expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
  });

  it('go up a level with Back and keep the entry, its levels under the entry\'s URL', async () => {
    openAt(at(L1), [KEY_L1]);
    await userEvent.click(await screen.findByRole('button', { name: 'Show registration details' }));
    await waitFor(() => expect(window.location.hash).toBe(`${at(L1)}/registration`));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(window.location.hash).toBe(at(L1)));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('offer FIDO MDS over another entry, and correct a credential this browser does not keep to the entry', async () => {
    openAt(at('aaguid:f1d0f1d0-0000-4000-8000-000000000002'), [KEY_L1]);
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByRole('button', { name: 'FIDO MDS' })).toBeVisible();

    // After the Codec, × gives the focus to the entry's heading, which lists no such credential.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Show registration details' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Decode in Codec: attestation object' }));
    await waitFor(() => expect(window.location.hash).toBe('#codec'));
    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Decode in Codec: attestation object' })).toHaveFocus());
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L2' })).toHaveFocus());

    act(() => {
      window.location.hash = `#mds/${L1}/credential/id:unknown`;
    });
    await waitFor(() => expect(window.location.hash).toBe(`#mds/${L1}`));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });
});

describe('an MDS entry\'s saved credentials', () => {
  const L1 = 'aaguid:f1d0f1d0-0000-4000-8000-000000000001';
  const OF_L1 = savedRecord(DETAIL_SCENARIO, { userName: 'l1@example.com', aaguidHex: 'f1d0f1d0000040008000000000000001' });
  const ELSEWHERE = savedRecord(DETAIL_SCENARIO, { userName: 'other@example.com' }, 1);
  const saved = () => document.querySelector<HTMLElement>('[data-section="savedCredentials"]');

  it('are listed under the header, those with its AAGUID only, each opening its details over the entry', async () => {
    openAt('#mds', [OF_L1, ELSEWHERE]);
    await loaded();
    await userEvent.click(link(L1));
    await waitFor(() => expect(saved()).not.toBeNull());
    expect(within(saved()!).getByRole('heading', { level: 4, name: 'Saved Credentials' })).toBeVisible();
    expect(within(saved()!).getAllByRole('button').map((button) => button.textContent)).toEqual(['l1@example.com']);

    const opener = within(saved()!).getByRole('button', { name: 'l1@example.com' });
    await userEvent.click(opener);
    expect(window.location.hash).toBe(`#mds/${L1}/credential/id:${OF_L1.credentialIdBase64Url}`);
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: 2 });
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByRole('heading', { level: 3, name: 'l1@example.com' });

    // × closes the details alone: the entry is there, the entry's own entry in the history kept.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(window.location.hash).toBe(`#mds/${L1}`));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: 1 });
    await waitFor(() => expect(opener).toHaveFocus());

    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => expect(list()).toBeVisible());
    expect(window.location.hash).toBe('#mds');
  });

  it('open details that find their place again after the Codec, and × gives the focus back to the credential\'s button', async () => {
    openAt('#mds', [OF_L1]);
    await loaded();
    await userEvent.click(link(L1));
    await waitFor(() => expect(saved()).not.toBeNull());
    await userEvent.click(within(saved()!).getByRole('button', { name: 'l1@example.com' }));
    await userEvent.click(await within(await screen.findByRole('dialog')).findByRole('button', { name: 'Show registration details' }));
    const registration = `#mds/${L1}/credential/id:${OF_L1.credentialIdBase64Url}/registration`;
    await waitFor(() => expect(window.location.hash).toBe(registration));
    await userEvent.click(await screen.findByRole('button', { name: 'Decode in Codec: attestation object' }));
    await waitFor(() => expect(window.location.hash).toBe('#codec'));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    // The hidden section let the entry's page and the details go: Back mounts
    // them again, and the button is put back once their level is composed, and
    // kept there while the level's late parts change its size, until the person scrolls.
    const watched: string[] = [];
    const stopped: string[] = [];
    vi.stubGlobal(
      'ResizeObserver',
      class {
        private level = '';
        constructor(private readonly resized: () => void) {}
        observe(target: HTMLElement) {
          if (!target.dataset.level) return;
          this.level = target.dataset.level;
          watched.push(this.level);
          this.resized();
        }
        disconnect() {
          if (this.level) stopped.push(this.level);
        }
      },
    );
    slow = true;
    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(window.location.hash).toBe(registration));
    expect(await screen.findByRole('dialog')).toHaveFocus();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Decode in Codec: attestation object' })).toHaveFocus());
    expect(watched).toEqual(['registration']);
    fireEvent.wheel(document.querySelector('[data-overlay-scroll]')!);
    expect(stopped).toEqual(['registration']);

    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(window.location.hash).toBe(`#mds/${L1}`));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() => expect(within(saved()!).getByRole('button', { name: 'l1@example.com' })).toHaveFocus());
  });

  it('are not there for an entry this browser keeps none of', async () => {
    openAt(`#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000002`, [OF_L1]);
    await screen.findByRole('heading', { level: 3, name: 'Fixture Security Key L2' });
    expect(saved()).toBeNull();
  });
});

describe('an MDS entry\'s Try in Advanced', () => {
  const L1 = 'aaguid:f1d0f1d0-0000-4000-8000-000000000001';
  const editor = () => screen.getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' }) as HTMLTextAreaElement;

  it('opens the Advanced registration asking for what the statement says, and Back returns to the entry', async () => {
    openAt('#mds');
    await loaded();
    await userEvent.click(link(L1));
    await userEvent.click(await screen.findByRole('button', { name: 'Try in Advanced' }));

    await waitFor(() => expect(window.location.hash).toBe('#advanced'));
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: 2 });
    await waitFor(() => expect(JSON.parse(editor().value).publicKey.pubKeyCredParams.map(({ alg }: { alg: number }) => alg)).toEqual([-8, -7]));
    expect(JSON.parse(editor().value).publicKey.authenticatorSelection).toMatchObject({
      userVerification: 'required',
      authenticatorAttachment: 'cross-platform',
    });
    expect(screen.getByRole('tab', { name: 'Registration' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('The Advanced registration now asks for what the metadata of Fixture Security Key L1 says.')).toBeInTheDocument();

    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(window.location.hash).toBe(`#mds/${L1}`));
    // The entry's page comes back as a page arrives: its heading takes the focus.
    await waitFor(() => expect(screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toHaveFocus());
  });
});
