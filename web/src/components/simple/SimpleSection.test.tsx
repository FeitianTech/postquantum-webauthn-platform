// The Simple tab (docs/ui-parity/simple.md, SIM-*) over the server's recorded
// answers (the characterization goldens) and a stand-in authenticator.
import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { answerResponse, installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';

import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { ToastProvider } from '@/components/ui/Toast';
import { CLOSED_ROUTE } from '@/lib/useSection';
import { answersOf, keepRecords, savedRecord, storedRecords, warmUpRoutes } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

import { SimpleSection } from './SimpleSection';

const REGISTER = answersOf('simple-register-es256');
const MLDSA = answersOf('simple-register-mldsa65');
const AUTHENTICATE = answersOf('simple-authenticate');
const KEPT = savedRecord('simple-authenticate');

type Answer = { status: number; body: unknown };
const answer = (entry: Answer) => () => answerResponse(entry) as Response;

let authenticator: ReturnType<typeof installAuthenticator>;

function renderTab(routes: Record<string, () => Response | Promise<Response>> = {}, records: object[] = []) {
  keepRecords(records);
  const fetch = stubFetch({ ...warmUpRoutes(), ...routes });
  renderPage(
    <ToastProvider>
      <SavedCredentialsProvider>
        <SimpleSection active route={CLOSED_ROUTE} />
      </SavedCredentialsProvider>
    </ToastProvider>,
  );
  return fetch;
}

const field = () => screen.getByRole('textbox', { name: 'Username' });
const button = (name: string) => screen.getByRole('button', { name });

async function useUsername(name: string) {
  await userEvent.clear(field());
  await userEvent.type(field(), name);
}

const ceremonyCalls = (fetch: ReturnType<typeof stubFetch>) =>
  fetch.mock.calls.map(([url]) => String(url).split('?')[0]).filter((path) => !path.startsWith('/api/advanced'));

beforeEach(() => {
  authenticator = installAuthenticator(vi);
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  authenticator.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the Simple tab\'s form', () => {
  it('SIM-F1/F3: has a labelled username field, filled with a random username', async () => {
    renderTab();
    expect(field()).toHaveAttribute('placeholder', 'Enter username');
    await waitFor(() => expect((field() as HTMLInputElement).value).toMatch(/^[A-Za-z0-9]{10}$/));
  });

  it('SIM-F2: fills another random username on request', async () => {
    renderTab();
    await useUsername('alice');
    await userEvent.click(button('Generate random username'));
    expect((field() as HTMLInputElement).value).toMatch(/^[A-Za-z0-9]{10}$/);
  });

  it('SIM-R1/A1: says under the field that it needs a username, and asks nothing', async () => {
    const fetch = renderTab();
    await userEvent.clear(field());
    await userEvent.click(button('Register Passkey'));
    await userEvent.click(button('Authenticate'));
    expect(field()).toHaveAccessibleDescription('Please enter a username.');
    expect(ceremonyCalls(fetch)).toEqual([]);

    await userEvent.type(field(), 'a');
    expect(field()).not.toHaveAccessibleDescription();
  });
});

describe('registering in the Simple tab', () => {
  it('SIM-R2..R7: says each step, keeps the button busy, and says the algorithm when it succeeds', async () => {
    let finish!: () => void;
    const complete = new Promise<Response>((resolve) => (finish = () => resolve(answerResponse(REGISTER[1]))));
    renderTab({ '/api/register/begin': answer(REGISTER[0]), '/api/register/complete': () => complete });
    await useUsername('user@example.com');
    await userEvent.click(button('Register Passkey'));

    expect(await screen.findByText('Completing registration...')).toBeVisible();
    expect(button('Register Passkey')).toHaveAttribute('aria-busy', 'true');
    expect(button('Authenticate')).toBeDisabled();
    await act(async () => finish());

    expect(await screen.findByText('Registration successful! Algorithm: ES256 (ECDSA)')).toBeVisible();
    expect(screen.queryByText('Completing registration...')).toBeNull();
    expect(button('Register Passkey')).toBeEnabled();
  });

  it('SIM-R8: keeps the server\'s record in this browser, for the username, and lists it', async () => {
    renderTab({ '/api/register/begin': answer(MLDSA[0]), '/api/register/complete': answer(MLDSA[1]) });
    await useUsername('alice');
    await userEvent.click(button('Register Passkey'));

    expect(await screen.findByText('Registration successful! Algorithm: ML-DSA-65 (PQC)')).toBeVisible();
    const [record] = storedRecords();
    expect(record).toMatchObject({ type: 'simple', email: 'alice', credentialIdBase64Url: savedRecord('simple-register-mldsa65').credentialIdBase64Url });
    expect(await screen.findByRole('list', { name: 'Saved Credentials' })).toHaveTextContent('MLDSA65');
  });

  it('SIM-E1: keeps a refused registration in place, as the server said it', async () => {
    renderTab({
      '/api/register/begin': answer(REGISTER[0]),
      '/api/register/complete': () => json({ error: 'Registration verification failed.', verified: false }, 400),
    });
    await useUsername('alice');
    await userEvent.click(button('Register Passkey'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Registration failed: Registration verification failed.');
    expect(storedRecords()).toEqual([]);
  });

  it('SIM-E2: says the authenticator\'s refusal by its name', async () => {
    authenticator.create.mockRejectedValueOnce(new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'));
    renderTab({ '/api/register/begin': answer(REGISTER[0]) });
    await useUsername('alice');
    await userEvent.click(button('Register Passkey'));
    expect(await screen.findByRole('alert')).toHaveTextContent('User cancelled or authenticator not available');
  });
});

describe('authenticating in the Simple tab', () => {
  const routes = (complete: Answer) => ({
    '/api/authenticate/begin': answer(AUTHENTICATE[2]),
    '/api/authenticate/complete': answer(complete),
  });

  it('SIM-A7: says so, shows the counter and its verdict, keeps the counter, and tints the credential', async () => {
    renderTab(routes(AUTHENTICATE[3]), [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));

    expect(await screen.findByText('Authentication successful! You have been verified.')).toBeVisible();
    const panel = document.querySelector('[data-ceremony-result]')!;
    expect(panel).toBeVisible();
    expect(panel).toHaveTextContent('Last authentication');
    expect(panel).toHaveTextContent('6 Higher than the last counter the server saw for this credential, as it should be.');
    expect(storedRecords()[0].signCount).toBe(6);
    await waitFor(() => expect(document.querySelector('li[data-credential-key]')).toHaveAttribute('data-flash', 'success'));
  });

  it('SIM-A8/C4: warns of a counter that went backwards, keeps the refusal in place, and tints the credential red', async () => {
    renderTab(routes(AUTHENTICATE[5]), [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));

    expect(await screen.findByRole('alert')).toHaveTextContent('Signature counter did not increase');
    const panel = document.querySelector('[data-ceremony-result]')!;
    expect(panel).toHaveAttribute('data-verdict', 'warning');
    expect(panel).toHaveTextContent('the authenticator may have been cloned. Authentication was rejected.');
    expect(document.querySelector('li[data-credential-key]')).toHaveAttribute('data-flash', 'failure');
  });

  it('SIM-E3: keeps a refused signature in place, with no result to show', async () => {
    renderTab(routes(AUTHENTICATE[7]), [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid signature.');
    expect(document.querySelector('[data-ceremony-result]')).not.toBeVisible();
  });

  it('SIM-A3: says this browser keeps no passkey for the username, and asks nothing', async () => {
    const fetch = renderTab(routes(AUTHENTICATE[3]), [KEPT]);
    await useUsername('bob');
    await userEvent.click(button('Authenticate'));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No credentials stored in this browser for the provided username. Please register first.',
    );
    expect(ceremonyCalls(fetch)).toEqual([]);
  });

  it('SIM-A4: says the server found no credential it could use', async () => {
    renderTab({ '/api/authenticate/begin': answer(AUTHENTICATE[8]) }, [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));
    expect(await screen.findByRole('alert')).toHaveTextContent('No credentials found for this username. Please register first.');
  });

  it('SIM-E2: says an InvalidStateError its own way when authenticating', async () => {
    authenticator.get.mockRejectedValueOnce(new DOMException('invalid', 'InvalidStateError'));
    renderTab(routes(AUTHENTICATE[3]), [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Authenticator error or invalid credential');
  });

  it('SIM-C5: clears the last failure and result when the next ceremony starts', async () => {
    renderTab(routes(AUTHENTICATE[5]), [KEPT]);
    await useUsername('user@example.com');
    await userEvent.click(button('Authenticate'));
    await screen.findByRole('alert');

    authenticator.get.mockReturnValueOnce(new Promise(() => {}));
    await userEvent.click(button('Authenticate'));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(document.querySelector('[data-ceremony-result]')).not.toBeVisible();
    expect(within(document.querySelector('[data-simple-ceremony]')!).getByRole('status', { hidden: false })).toHaveTextContent(
      'Connecting your authenticator device...',
    );
  });
});
