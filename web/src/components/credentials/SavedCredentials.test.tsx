// The saved credentials both sections share (CRED-L, CRED-C, CRED-D, CRED-W in
// docs/ui-parity/credentials.md), over records as the server saved them.
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { keepRecords, savedRecord, storedRecords, warmUpRoutes } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

import { SavedCredentials } from './SavedCredentials';
import { SavedCredentialsProvider, useSavedCredentials } from './useSavedCredentials';

const ES256 = savedRecord('simple-register-es256');
const MLDSA = savedRecord('simple-register-mldsa65', { email: 'ml@example.com', userName: 'ml@example.com' });
const X5C = savedRecord('simple-register-packed-x5c-extensions', { email: 'x5c@example.com', userName: 'x5c@example.com' });
const ADVANCED = savedRecord('advanced-register-packed-x5c-everything', { userName: 'advanced@example.com' });
const ADVANCED_PATH = `/api/advanced/credential-artifacts/${encodeURIComponent(ADVANCED.storageId as string)}`;

function FlashButton({ id }: { id: string }) {
  const saved = useSavedCredentials();
  return (
    <button type="button" onClick={() => saved.flashCredential(id, 'success')}>
      Flash
    </button>
  );
}

function renderList(records: object[], routes = {}) {
  keepRecords(records);
  const fetch = stubFetch({ ...warmUpRoutes(), ...routes });
  const onOpen = vi.fn();
  renderPage(
    <ToastProvider>
      <SavedCredentialsProvider>
        <SavedCredentials onOpen={onOpen} />
        <FlashButton id={ES256.credentialIdBase64Url as string} />
      </SavedCredentialsProvider>
    </ToastProvider>,
  );
  return { onOpen, fetch };
}

const rows = () => Array.from(document.querySelectorAll<HTMLElement>('li[data-credential-key]'));
const rowNamed = (name: string) => rows().find((row) => within(row).queryByRole('button', { name }))!;

async function confirmIn(dialogAction: string) {
  const dialog = await screen.findByRole('alertdialog');
  await userEvent.click(within(dialog).getByRole('button', { name: dialogAction }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the saved credentials', () => {
  it('CRED-L3: says there is none, and Clear All cannot be used', async () => {
    renderList([]);
    expect(await screen.findByText('No credentials registered yet.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Clear All' })).toBeDisabled();
    expect(document.querySelector('[data-count]')).toHaveTextContent('0');
  });

  it('CRED-L1/L2: lists every credential, simple and advanced, in the order stored, and how many', async () => {
    renderList([ES256, ADVANCED, MLDSA]);
    await waitFor(() => expect(rows()).toHaveLength(3));
    expect(rows().map((row) => within(row).getAllByRole('button')[0].textContent)).toEqual([
      'user@example.com',
      'advanced@example.com',
      'ml@example.com',
    ]);
    expect(screen.getByRole('heading', { level: 3, name: 'Saved Credentials' })).toBeVisible();
    expect(document.querySelector('[data-count]')).toHaveTextContent('3');
    expect(screen.getByRole('button', { name: 'Clear All' })).toBeEnabled();
  });

  it('CRED-C2: gives each check with its mark and a word for screen readers', async () => {
    renderList([X5C]);
    const row = await waitFor(() => rowNamed('x5c@example.com'));
    const check = (label: string) => row.querySelector<HTMLElement>(`[data-check="${label}"]`)!;
    expect(check('Signature')).toHaveTextContent('Signature passed✓');
    expect(check('Signature').className).toContain('bg-success-tint');
    expect(check('Root')).toHaveTextContent('Root not known–');
    expect(check('RPID').className).toContain('bg-success-tint');
    expect(check('AAGUID')).toHaveTextContent('AAGUID passed');
  });

  it('CRED-C3: tags the algorithm, in the accent, and large blob support', async () => {
    renderList([ADVANCED, MLDSA]);
    await waitFor(() => expect(rows()).toHaveLength(2));
    const tags = (row: HTMLElement) => within(row).getByRole('list', { name: 'Features' });
    expect(tags(rowNamed('advanced@example.com'))).toHaveTextContent('ES256Large blob');
    expect(within(tags(rowNamed('advanced@example.com'))).getByText('ES256').className).toContain('bg-accent-tint');
    expect(tags(rowNamed('ml@example.com'))).toHaveTextContent('MLDSA65');
  });

  it('shows the credential ID and the AAGUID in Geist Mono, each with copy', async () => {
    renderList([ES256]);
    const row = await waitFor(() => rowNamed('user@example.com'));
    const codes = Array.from(row.querySelectorAll('code')).map((code) => code.textContent);
    expect(codes).toEqual([ES256.credentialIdBase64Url, '00112233-4455-6677-8899-aabbccddeeff']);
    expect(within(row).getByRole('button', { name: 'Copy credential ID' })).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: 'Copy AAGUID' })).toBeInTheDocument();
  });

  it('leaves out an AAGUID the credential does not have, and names an unnamed one', async () => {
    renderList([{ type: 'simple', credentialId: 'AQID', publicKey: 'pQE' }]);
    const row = await waitFor(() => rowNamed('Unknown User'));
    expect(within(row).queryByRole('button', { name: 'Copy AAGUID' })).toBeNull();
    expect(row.querySelector('code')).toHaveTextContent('AQID');
  });

  it('lists a credential whose stored AAGUID no spelling reads with the others, that AAGUID as stored and marked', async () => {
    renderList([ES256, { type: 'simple', userName: 'unreadable', credentialId: 'AQID', aaguid: 'abcde' }, MLDSA]);
    await waitFor(() => expect(rows()).toHaveLength(3));
    const row = rowNamed('unreadable');
    const stored = row.querySelector('[data-unreadable="aaguid"]') as HTMLElement;
    expect(stored).toHaveTextContent('AAGUIDUnreadable');
    expect(stored.querySelector('code')).toHaveTextContent('abcde');
    expect(within(row).getByRole('button', { name: 'Copy stored AAGUID' })).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: 'FIDO MDS' })).toBeNull();
  });

  it('CRED-C7: opens a credential\'s details from its name or its row, and not from its controls', async () => {
    const { onOpen } = renderList([ES256]);
    const row = await waitFor(() => rowNamed('user@example.com'));
    const key = `id:${ES256.credentialIdBase64Url}`;

    await userEvent.click(within(row).getByRole('button', { name: 'user@example.com' }));
    await userEvent.click(within(row).getByRole('list', { name: 'Checks' }));
    expect(onOpen.mock.calls).toEqual([[key], [key]]);

    await userEvent.click(row.querySelector('code')!);
    await userEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    expect(onOpen).toHaveBeenCalledTimes(2);
  });

  it('CRED-C5: has no FIDO MDS button without a valid root or known metadata', async () => {
    renderList([ES256]);
    const row = await waitFor(() => rowNamed('user@example.com'));
    expect(within(row).queryByRole('button', { name: 'FIDO MDS' })).toBeNull();
  });

  it('CRED-C9: tints the row of the credential a ceremony used, for a moment', async () => {
    renderList([ES256, MLDSA]);
    await waitFor(() => expect(rows()).toHaveLength(2));
    vi.useFakeTimers();
    act(() => screen.getByRole('button', { name: 'Flash' }).click());
    expect(rowNamed('user@example.com')).toHaveAttribute('data-flash', 'success');
    expect(rowNamed('ml@example.com')).not.toHaveAttribute('data-flash');
    act(() => vi.advanceTimersByTime(2200));
    expect(rowNamed('user@example.com')).not.toHaveAttribute('data-flash');
  });
});

describe('deleting a saved credential', () => {
  it('CRED-D1/D2: asks first, then removes a simple one from this browser and says so', async () => {
    renderList([ES256, MLDSA]);
    const row = await waitFor(() => rowNamed('user@example.com'));
    await userEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog', { name: 'Delete credential' });
    expect(dialog).toHaveTextContent('Are you sure you want to delete the credential for user@example.com? This action cannot be undone.');

    await confirmIn('Delete');
    expect(await screen.findByText('Deletion successful.')).toBeVisible();
    expect(rows()).toHaveLength(1);
    expect(storedRecords().map((record) => record.email)).toEqual(['ml@example.com']);
  });

  it('keeps the credential when the question is cancelled', async () => {
    renderList([ES256]);
    await userEvent.click(within(await waitFor(() => rowNamed('user@example.com'))).getByRole('button', { name: 'Delete' }));
    await confirmIn('Cancel');
    expect(storedRecords()).toHaveLength(1);
  });

  it('CRED-D3: deletes an advanced one on the server first, then here', async () => {
    const { fetch } = renderList([ADVANCED], { [ADVANCED_PATH]: () => json({ status: 'deleted' }) });
    await userEvent.click(within(await waitFor(() => rowNamed('advanced@example.com'))).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    expect(await screen.findByText('Deletion successful.')).toBeVisible();
    expect(fetch.mock.calls.find(([url]) => String(url) === ADVANCED_PATH)?.[1]).toMatchObject({ method: 'DELETE' });
    expect(storedRecords()).toEqual([]);
  });

  it('CRED-D3: warns under the header when the server no longer had it', async () => {
    renderList([ADVANCED], { [ADVANCED_PATH]: () => json({ status: 'absent' }, 404) });
    await userEvent.click(within(await waitFor(() => rowNamed('advanced@example.com'))).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    const notice = await screen.findByText('Credential was already absent from server storage and has been removed locally.');
    expect(notice).toHaveAttribute('data-notice', 'warning');
  });

  it('CRED-D3/D4: keeps one the server refused to delete, with the server\'s reason, as an alert', async () => {
    renderList([ADVANCED], { [ADVANCED_PATH]: () => json({ error: 'The stored credentials could not be read.' }, 503) });
    await userEvent.click(within(await waitFor(() => rowNamed('advanced@example.com'))).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    expect(await screen.findByRole('alert')).toHaveTextContent('The stored credentials could not be read.');
    expect(rows()).toHaveLength(1);
  });

  it('says what it is doing meanwhile, with its buttons unusable', async () => {
    let answer!: (response: Response) => void;
    renderList([ADVANCED], { [ADVANCED_PATH]: () => new Promise<Response>((resolve) => (answer = resolve)) });
    await userEvent.click(within(await waitFor(() => rowNamed('advanced@example.com'))).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    expect(await screen.findByText('Deleting credential...')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Clear All' })).toBeDisabled();
    expect(within(rowNamed('advanced@example.com')).getByRole('button', { name: 'Delete' })).toBeDisabled();
    await act(async () => answer(json({ status: 'deleted' })));
    await waitFor(() => expect(screen.queryByText('Deleting credential...')).toBeNull());
  });
});

describe('clearing every saved credential', () => {
  it('CRED-D6/D7: asks first, then clears the simple and the advanced ones and says so', async () => {
    renderList([ES256, ADVANCED], { [ADVANCED_PATH]: () => json({ status: 'deleted' }) });
    await waitFor(() => expect(rows()).toHaveLength(2));
    await userEvent.click(screen.getByRole('button', { name: 'Clear All' }));
    expect(await screen.findByRole('alertdialog', { name: 'Clear All' })).toHaveTextContent(
      'Are you sure you want to delete all saved credentials? This action cannot be undone.',
    );
    await confirmIn('Clear All');
    expect(await screen.findByText('Deletion successful.')).toBeVisible();
    expect(await screen.findByText('No credentials registered yet.')).toBeVisible();
    expect(storedRecords()).toEqual([]);
  });

  it('CRED-D7: says under the header which ones it kept', async () => {
    renderList([ES256, ADVANCED], { [ADVANCED_PATH]: () => json({ error: 'Nope.' }, 500) });
    await waitFor(() => expect(rows()).toHaveLength(2));
    await userEvent.click(screen.getByRole('button', { name: 'Clear All' }));
    await confirmIn('Clear All');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Clearing completed with issues: 1 credential could not be deleted from server storage and was kept.',
    );
  });
});

describe('the warm-up after the list is read', () => {
  it('CRED-W1: brings a registration snapshot the server holds into this browser', async () => {
    const snapshot = { schemaVersion: 2, capturedAt: '2026-09-21T14:13:20Z', state: { authenticatorDataHex: 'ab' } };
    const record = { ...ADVANCED, registrationDetailSnapshot: undefined };
    const { fetch } = renderList([record], {
      '/api/advanced/credential-artifacts/bulk': () => json({ artifacts: { [ADVANCED.storageId as string]: { registrationDetailSnapshot: snapshot } } }),
    });
    await waitFor(() => expect(storedRecords()[0].registrationDetailSnapshot).toMatchObject({ schemaVersion: 2 }));
    expect(fetch.mock.calls.some(([url]) => String(url) === '/api/advanced/credential-artifacts/bulk')).toBe(true);
  });
});

describe('the saved credentials\' state', () => {
  it('is only given inside its provider', () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => render(<FlashButton id="x" />)).toThrow('useSavedCredentials needs a SavedCredentialsProvider');
    quiet.mockRestore();
  });
});
