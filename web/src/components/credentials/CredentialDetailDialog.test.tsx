// A saved credential's details at their own URL (CRED-C7, CRED-M1 in
// docs/ui-parity/credentials.md): the 28A dialog, through the whole shell.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { AppShell } from '@/components/shell/AppShell';
import { keepRecords, savedRecord, warmUpRoutes } from '@/test/credentials';
import { stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

const ES256 = savedRecord('simple-register-es256');
const KEY = `id:${ES256.credentialIdBase64Url}`;
const URL_OF_DETAIL = `#simple/credential/id:${ES256.credentialIdBase64Url}`;

function renderShell(hash = '') {
  window.history.replaceState({ fromNext: true }, '', `/beta${hash}`);
  keepRecords([ES256]);
  stubFetch(warmUpRoutes());
  renderPage(<AppShell />);
}

const detail = () => screen.queryByRole('dialog', { name: 'Credential Details' });

async function openFromName() {
  const name = await screen.findByRole('button', { name: 'user@example.com' });
  await userEvent.click(name);
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });
  return name;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a saved credential\'s details', () => {
  it('open from its name at their own URL, as a history entry of their own', async () => {
    renderShell();
    const length = window.history.length;
    await openFromName();

    expect(window.location.hash).toBe(URL_OF_DETAIL);
    expect(window.history.length).toBe(length + 1);
    const dialog = detail()!;
    expect(within(dialog).getByRole('heading', { level: 3, name: 'user@example.com' })).toBeVisible();
    expect(dialog.querySelector(`[data-credential-detail="${KEY}"] code`)).toHaveTextContent(ES256.credentialIdBase64Url as string);
    expect(within(dialog).getByRole('link', { name: 'Open the current interface' })).toHaveAttribute('href', '/');
  });

  it('close on Escape by going back, with the focus on the name that opened them', async () => {
    renderShell();
    const name = await openFromName();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(window.location.hash).toBe(''));
    await waitFor(() => expect(detail()).toBeNull());
    expect(name).toHaveFocus();
  });

  it('open from a link or a reload, and × leaves the URL at the section\'s', async () => {
    renderShell(URL_OF_DETAIL);
    const dialog = await screen.findByRole('dialog', { name: 'Credential Details' });
    const length = window.history.length;
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close credential details' }));
    await waitFor(() => expect(detail()).toBeNull());
    expect(window.location.hash).toBe('#simple');
    expect(window.history.length).toBe(length);
  });

  it('show the list, and correct the URL, for a credential this browser does not keep', async () => {
    renderShell('#simple/credential/id:unknown');
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(detail()).toBeNull();
  });

  it('are the only thing the section\'s URL can open', async () => {
    renderShell('#simple/elsewhere');
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(await screen.findByRole('button', { name: 'user@example.com' })).toBeVisible();
  });
});
