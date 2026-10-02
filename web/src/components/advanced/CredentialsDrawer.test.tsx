// The Advanced tab's drawer of saved credentials, over records as the server
// saved them: what it says while a deletion runs and after, and where the focus
// goes once Clear All has left no row.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { ToastProvider } from '@/components/ui/Toast';
import { keepRecords, savedRecord, warmUpRoutes } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

import { CredentialsDrawer } from './CredentialsDrawer';

const SIMPLE = savedRecord('simple-register-es256');
const ADVANCED = savedRecord('advanced-register-packed-x5c-everything', { userName: 'advanced@example.com' });
const ADVANCED_PATH = `/api/advanced/credential-artifacts/${encodeURIComponent(ADVANCED.storageId as string)}`;

function renderDrawer(records: object[], routes = {}) {
  keepRecords(records);
  stubFetch({ ...warmUpRoutes(), ...routes });
  const onOpen = vi.fn();
  renderPage(
    <ToastProvider>
      <SavedCredentialsProvider>
        <CredentialsDrawer open onClose={() => {}} onOpen={onOpen} returnFocusTo={() => null} />
      </SavedCredentialsProvider>
    </ToastProvider>,
  );
  return { onOpen, drawer: () => screen.getByRole('dialog', { name: 'Saved Credentials' }) };
}

const rows = () => Array.from(document.querySelectorAll<HTMLElement>('li[data-credential-key]'));

async function confirmIn(action: string) {
  const dialog = await screen.findByRole('alertdialog', { name: action === 'Delete' ? 'Delete credential' : action });
  await userEvent.click(within(dialog).getByRole('button', { name: action }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the saved credentials\' drawer', () => {
  it('says in its body what it is deleting, with Clear All unusable meanwhile', async () => {
    let answer!: (response: Response) => void;
    const { drawer } = renderDrawer([ADVANCED], { [ADVANCED_PATH]: () => new Promise<Response>((resolve) => (answer = resolve)) });
    await waitFor(() => expect(rows()).toHaveLength(1));

    await userEvent.click(within(drawer()).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    expect(await within(drawer()).findByText('Deleting credential...')).toHaveAttribute('data-role', 'progress');
    expect(within(drawer()).getByRole('button', { name: 'Clear All' })).toBeDisabled();
    await act(async () => answer(json({ status: 'deleted' })));
    await waitFor(() => expect(within(drawer()).queryByText('Deleting credential...')).toBeNull());
  });

  it('shows what the last deletion left to say above the rows', async () => {
    const { drawer } = renderDrawer([ADVANCED, SIMPLE], { [ADVANCED_PATH]: () => json({ status: 'absent' }, 404) });
    await waitFor(() => expect(rows()).toHaveLength(2));

    await userEvent.click(within(rows()[0]).getByRole('button', { name: 'Delete' }));
    await confirmIn('Delete');
    const notice = await within(drawer()).findByText('Credential was already absent from server storage and has been removed locally.');
    expect(notice).toHaveAttribute('data-notice', 'warning');
    expect(rows()).toHaveLength(1);
  });

  it('takes the focus itself once Clear All has left no row', async () => {
    const { drawer } = renderDrawer([SIMPLE]);
    await waitFor(() => expect(rows()).toHaveLength(1));

    await userEvent.click(within(drawer()).getByRole('button', { name: 'Clear All' }));
    await confirmIn('Clear All');
    await waitFor(() => expect(rows()).toHaveLength(0));
    await waitFor(() => expect(drawer().closest('[data-overlay-panel]') ?? drawer()).toHaveFocus());
  });

  it('opens a credential\'s details from its name', async () => {
    const { onOpen, drawer } = renderDrawer([SIMPLE]);
    await waitFor(() => expect(rows()).toHaveLength(1));

    await userEvent.click(within(drawer()).getByRole('button', { name: 'user@example.com' }));
    expect(onOpen).toHaveBeenCalledWith(rows()[0].dataset.credentialKey);
  });
});
