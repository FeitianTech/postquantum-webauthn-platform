// The Advanced tab (ADV-T, ADV-D, ADV-C, ADV-P, ADV-G in docs/ui-parity/advanced.md)
// through the whole shell, over the server's recorded answers (the
// characterization goldens) and a stand-in authenticator.
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  advancedAuthentications,
  advancedDecodeAnswer,
  advancedRegistrations,
  recordedAssertion,
  recordedCredential,
} from '@/test/logic/advanced/auth/advanced-answers.js';
import { answerResponse, goldenAnswers, installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';

import { forgetCompletedRecords } from '@/components/credentials/detail/useCredentialDetail';
import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';
import { keepRecords, savedRecord, storedRecords, warmUpRoutes } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';
import { renderPage } from '@/test/page';

type Answer = { status: number; body: unknown };
const answer = (entry: Answer) => () => answerResponse(entry) as Response;
const [NONE, X5C] = advancedRegistrations();
const KEPT = savedRecord('advanced-register-packed-x5c-everything', { userName: 'kept@example.com' });

let authenticator: ReturnType<typeof installAuthenticator>;

function renderSection(records: object[] = [], routes = {}) {
  window.history.replaceState({ fromNext: true }, '', '/#advanced');
  keepRecords(records);
  const fetch = stubFetch({
    ...warmUpRoutes(),
    '/api/decode': (init) => answerResponse(advancedDecodeAnswer(JSON.parse(String(init?.body)).payload)) as Response,
    ...routes,
  });
  renderPage(
    <ToastProvider>
      <AppShell />
    </ToastProvider>,
  );
  return fetch;
}

/** The routes of a registration the server answers as recorded. */
function registrationRoutes(registration: { begin: Answer; complete: Answer }) {
  const storageId = (registration.complete.body as { storedCredential: { storageId: string } }).storedCredential.storageId;
  return {
    '/api/advanced/register/begin': answer(registration.begin),
    '/api/advanced/register/complete': answer(registration.complete),
    [`/api/advanced/credential-artifacts/${encodeURIComponent(storageId)}/snapshot`]: () => json({ status: 'OK' }),
  };
}

const button = (name: string) => screen.getByRole('button', { name });
const requestsTo = (fetch: ReturnType<typeof stubFetch>, path: string) =>
  fetch.mock.calls.filter(([url]) => String(url).split('?')[0] === path).map(([, init]) => init as RequestInit);
const editorText = () => (screen.getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' }) as HTMLTextAreaElement).value;

async function ready() {
  await waitFor(() => expect(editorText()).toContain('"publicKey"'));
}

beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  authenticator?.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  forgetCompletedRecords();
});

describe('the Advanced tab', () => {
  it('ADV-T1, ADV-T2: is the section the top bar names, with its heading and description', async () => {
    renderSection();
    await ready();

    expect(screen.getByRole('heading', { level: 2, name: 'Advanced Authentication' })).toBeVisible();
    expect(screen.getByText('Configure WebAuthn registration and authentication requests with detailed settings.')).toBeVisible();
  });

  it('ADV-T4, ADV-T5, ADV-T6: switches between Registration and Authentication, each with its form, its editor and its buttons', async () => {
    renderSection();
    await ready();

    expect(button('Create Credential')).toBeVisible();
    await userEvent.click(screen.getByRole('tab', { name: 'Authentication' }));
    expect(screen.queryByRole('button', { name: 'Create Credential' })).toBeNull();
    expect(button('Assert Credential')).toBeVisible();
    expect(screen.getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' })).toBeVisible();
    expect(screen.getByRole('region', { name: 'Credential Selection' })).toBeVisible();
    expect(screen.queryByRole('link', { name: 'Open the current interface' })).toBeNull();
    await userEvent.click(screen.getByRole('tab', { name: 'Registration' }));
    expect(button('Create Credential')).toBeVisible();
    expect(screen.getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' })).toBeVisible();
  });
});

describe('the saved credentials\' drawer', () => {
  it('ADV-D1: opens from Saved Credentials, with how many there are, over the list both tabs share', async () => {
    renderSection([KEPT]);
    await ready();
    const opener = await screen.findByRole('button', { name: 'Saved Credentials 1' });

    await userEvent.click(opener);
    const drawer = screen.getByRole('dialog', { name: 'Saved Credentials' });
    expect(within(drawer).getByRole('button', { name: 'kept@example.com' })).toBeInTheDocument();
    expect(within(drawer).getByRole('button', { name: 'Clear All' })).toBeEnabled();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(opener).toHaveFocus());
  });

  it('ADV-D1: opens a credential\'s details over it, and comes back to it when they close', async () => {
    renderSection([KEPT], { [`/api/advanced/credential-artifacts/${encodeURIComponent(KEPT.storageId as string)}`]: () => json({}, 404) });
    await ready();
    await userEvent.click(await screen.findByRole('button', { name: 'Saved Credentials 1' }));
    const name = within(screen.getByRole('dialog', { name: 'Saved Credentials' })).getByRole('button', { name: 'kept@example.com' });

    await userEvent.click(name);
    await screen.findByRole('heading', { level: 2, name: 'Credential Details' });
    expect(window.location.hash).toMatch(/^#advanced\/credential\//);
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(window.location.hash).toBe('#advanced'));
    expect(screen.getByRole('dialog', { name: 'Saved Credentials' })).toBeInTheDocument();
    await waitFor(() => expect(name).toHaveFocus());
  });

  it('ADV-D1: asks before deleting in a dialog over it, which Escape closes alone', async () => {
    renderSection([KEPT]);
    await ready();
    await userEvent.click(await screen.findByRole('button', { name: 'Saved Credentials 1' }));

    await userEvent.click(within(screen.getByRole('dialog', { name: 'Saved Credentials' })).getByRole('button', { name: 'Delete' }));
    expect(screen.getByRole('alertdialog', { name: 'Delete credential' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(screen.getByRole('dialog', { name: 'Saved Credentials' })).toBeInTheDocument();
    expect(storedRecords()).toHaveLength(1);
  });

  it('closes when another section is chosen', async () => {
    renderSection([KEPT]);
    await ready();
    await userEvent.click(await screen.findByRole('button', { name: 'Saved Credentials 1' }));

    act(() => {
      window.location.hash = '#codec';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Saved Credentials' })).toBeNull());
  });
});

describe('a registration', () => {
  it('ADV-C2, ADV-C5: sends the editor\'s request, then the credential with the session state', async () => {
    authenticator = installAuthenticator(vi, { create: recordedCredential(X5C) });
    const fetch = renderSection([], registrationRoutes(X5C));
    await ready();
    const request = JSON.parse(editorText());

    await userEvent.click(button('Create Credential'));

    await waitFor(() => expect(requestsTo(fetch, '/api/advanced/register/complete')).toHaveLength(1));
    expect(JSON.parse(String(requestsTo(fetch, '/api/advanced/register/begin')[0].body))).toEqual(request);
    const complete = JSON.parse(String(requestsTo(fetch, '/api/advanced/register/complete')[0].body));
    expect(complete.publicKey).toEqual(request.publicKey);
    expect(complete.__session_state).toEqual((X5C.begin.body as { __session_state: unknown }).__session_state);
    expect(complete.__credential_response.id).toBe(recordedCredential(X5C).id);
  });

  it('ADV-C6, ADV-G1: keeps the record and its snapshot, then opens the registration, the detail under it', async () => {
    authenticator = installAuthenticator(vi, { create: recordedCredential(X5C) });
    const fetch = renderSection([], registrationRoutes(X5C));
    await ready();

    await userEvent.click(button('Create Credential'));

    await waitFor(() => expect(window.location.hash).toMatch(/^#advanced\/credential\/.+\/registration$/));
    await screen.findByRole('heading', { level: 2, name: 'Registration Details' });
    const [record] = storedRecords();
    expect(record).toMatchObject({ type: 'advanced', credentialIdBase64Url: recordedCredential(X5C).id });
    expect(record.registrationDetailSnapshot).toMatchObject({ schemaVersion: 2 });
    const snapshot = fetch.mock.calls.find(([url]) => String(url).endsWith('/snapshot'));
    expect(snapshot?.[1]).toMatchObject({ method: 'PUT' });
    await userEvent.click(button('Back'));
    await screen.findByRole('heading', { level: 2, name: 'Credential Details' });
  });

  it('ADV-C6, ADV-P1: says it succeeded with the server\'s warnings, shows where the challenge came from (a replay warns), and draws new values', async () => {
    authenticator = installAuthenticator(vi, { create: recordedCredential(X5C) });
    renderSection([], registrationRoutes(X5C));
    await ready();
    const userId = (screen.getByLabelText('User ID (hex)') as HTMLInputElement).value;

    await userEvent.click(button('Create Credential'));

    expect(await screen.findByText('Advanced registration successful! Algorithm: ES256 (ECDSA) metadata_not_available')).toBeInTheDocument();
    const result = document.querySelector<HTMLElement>('#nav-panel-advanced [data-ceremony-result]')!;
    await waitFor(() => expect(result).toHaveTextContent('Last registration'));
    // The recorded registration reused the scenario's challenge: a replay, which the panel warns of.
    expect(result.querySelector('[data-row="Challenge"]')).toHaveTextContent('server-session Issued by this server for this ceremony. Used before: this is a replay.');
    expect(result).toHaveAttribute('data-verdict', 'warning');
    expect((screen.getByLabelText('User ID (hex)') as HTMLInputElement).value).not.toBe(userId);
  });

  it('ADV-C3: gives the begin answer\'s warnings as a toast', async () => {
    authenticator = installAuthenticator(vi, { create: recordedCredential(NONE) });
    const [warned] = goldenAnswers('advanced-register-begin-pqc-unavailable');
    renderSection([], { ...registrationRoutes(NONE), '/api/advanced/register/begin': answer(warned) });
    await ready();

    await userEvent.click(button('Create Credential'));

    expect(await screen.findByText(/^Unsupported PQC algorithms were skipped/)).toBeInTheDocument();
  });

  it('ADV-C7, ADV-C8: says in place why the server refused it, with where the challenge came from', async () => {
    authenticator = installAuthenticator(vi, { create: recordedCredential(NONE) });
    const [refused] = goldenAnswers('advanced-register-complete-failures');
    const fetch = renderSection([], { ...registrationRoutes(NONE), '/api/advanced/register/complete': answer(refused) });
    await ready();

    await userEvent.click(button('Create Credential'));

    await waitFor(() => expect(requestsTo(fetch, '/api/advanced/register/complete')).toHaveLength(1));
    expect(await screen.findByRole('alert')).toHaveTextContent('Credential registration failed: Credential response is required');
    expect(document.querySelector('#nav-panel-advanced [data-row="Challenge"]')).toHaveTextContent('client-supplied');
    expect(storedRecords()).toEqual([]);
    expect(window.location.hash).toBe('#advanced');
  });

  it('ADV-C8: names what the authenticator may not support when it refuses', async () => {
    const refuse = () => Promise.reject(Object.assign(new Error('refused'), { name: 'NotAllowedError' }));
    authenticator = installAuthenticator(vi, { create: refuse as unknown as ReturnType<typeof recordedCredential> });
    renderSection([], registrationRoutes(NONE));
    await ready();

    await userEvent.click(button('Create Credential'));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /^Credential registration failed: User cancelled or authenticator not available The authenticator may not support: .*credProps extension/,
    );
  });

  it('ADV-C1: refuses an editor text that does not parse, asking nothing of the server', async () => {
    authenticator = installAuthenticator(vi);
    const fetch = renderSection([], registrationRoutes(NONE));
    await ready();
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' }), { target: { value: '{' } });

    await userEvent.click(button('Create Credential'));

    expect(await screen.findByText(/^Credential registration failed: /, { selector: '[data-role="failure"]' })).toBeInTheDocument();
    expect(requestsTo(fetch, '/api/advanced/register/begin')).toEqual([]);
  });
});

describe('an authentication', () => {
  const recorded = advancedAuthentications();
  const [CAPABLE, PLAIN] = recorded.records as Record<string, unknown>[];
  const CAPABLE_ID = CAPABLE.credentialIdBase64Url as string;
  const authText = () => (screen.getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' }) as HTMLTextAreaElement).value;
  const result = () => document.querySelector<HTMLElement>('#nav-panel-advanced [data-ceremony-result]');

  /** The routes of an authentication the server answers as recorded. */
  function authenticationRoutes(authentication: { begin: Answer; complete?: Answer }) {
    return {
      '/api/advanced/authenticate/begin': answer(authentication.begin),
      ...(authentication.complete ? { '/api/advanced/authenticate/complete': answer(authentication.complete) } : {}),
    };
  }

  async function onAuthentication(routes: object, get: unknown = recordedAssertion(recorded.first)) {
    authenticator = installAuthenticator(vi, { get: get as ReturnType<typeof recordedAssertion> });
    const fetch = renderSection([CAPABLE, PLAIN], routes);
    await ready();
    await userEvent.click(screen.getByRole('tab', { name: 'Authentication' }));
    await waitFor(() => expect(authText()).toContain('"publicKey"'));
    return fetch;
  }

  it('ADV-U2, ADV-U3: sends the editor\'s request with the saved credentials, then the assertion, the session state and the hash algorithm', async () => {
    const fetch = await onAuthentication(authenticationRoutes(recorded.first));
    await userEvent.selectOptions(screen.getByLabelText('Hash Algorithm'), 'SHA-384');
    const request = JSON.parse(authText());

    await userEvent.click(button('Assert Credential'));

    await waitFor(() => expect(requestsTo(fetch, '/api/advanced/authenticate/complete')).toHaveLength(1));
    const begin = JSON.parse(String(requestsTo(fetch, '/api/advanced/authenticate/begin')[0].body));
    expect(begin.publicKey).toEqual(request.publicKey);
    expect(begin.__storedCredentials.map((entry: { credentialId: string }) => entry.credentialId)).toEqual([CAPABLE_ID, PLAIN.credentialIdBase64Url]);
    const complete = JSON.parse(String(requestsTo(fetch, '/api/advanced/authenticate/complete')[0].body));
    expect(complete.__hash_algorithm).toBe('SHA-384');
    expect(complete.__session_state).toEqual((recorded.first.begin.body as { __session_state: unknown }).__session_state);
    expect(complete.__assertion_response.id).toBe(CAPABLE_ID);
  });

  it('ADV-U4, ADV-P2, ADV-G2: says it succeeded, shows the counter and the challenge, keeps the counter, tints the row and draws a new challenge, with no dialog', async () => {
    await onAuthentication(authenticationRoutes(recorded.first));
    const challenge = (screen.getByLabelText('Challenge (hex)', { selector: '#nav-panel-advanced [data-authentication-form] input' }) as HTMLInputElement).value;

    await userEvent.click(button('Assert Credential'));

    expect(await screen.findByText('Advanced authentication successful!')).toBeInTheDocument();
    await waitFor(() => expect(result()).toHaveTextContent('Last authentication'));
    expect(result()!.querySelector('[data-row="Signature counter"]')).toHaveTextContent(
      '1 Higher than the last counter the server saw for this credential, as it should be.',
    );
    expect(result()!.querySelector('[data-row="Challenge"]')).toHaveTextContent('server-session Issued by this server for this ceremony. First use.');
    await waitFor(() => expect(storedRecords()[0]).toMatchObject({ signCount: 1 }));
    await waitFor(() => expect(document.querySelector('#nav-panel-simple li[data-credential-key]')).toHaveAttribute('data-flash', 'success'));
    const now = screen.getByLabelText('Challenge (hex)', { selector: '#nav-panel-advanced [data-authentication-form] input' }) as HTMLInputElement;
    expect(now.value).toMatch(/^[0-9a-f]{64}$/);
    expect(now.value).not.toBe(challenge);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(window.location.hash).toBe('#advanced');
  });

  it('ADV-P2: reports a counter that went backwards, and that this tab does not reject the assertion', async () => {
    await onAuthentication(authenticationRoutes(recorded.regressed), recordedAssertion(recorded.regressed));

    await userEvent.click(button('Assert Credential'));

    await waitFor(() => expect(result()).toHaveTextContent('Last authentication'));
    expect(result()!.querySelector('[data-row="Signature counter"]')).toHaveTextContent(
      'The advanced tab reports this and does not reject the assertion.',
    );
    expect(result()).toHaveAttribute('data-verdict', 'warning');
  });

  it('ADV-U5: says in place why the server refused it, tints the credential it names, and shows where the challenge came from', async () => {
    const fetch = await onAuthentication(authenticationRoutes(recorded.refused), recordedAssertion(recorded.refused));

    await userEvent.click(button('Assert Credential'));

    await waitFor(() => expect(requestsTo(fetch, '/api/advanced/authenticate/complete')).toHaveLength(1));
    expect(await screen.findByText(/^Advanced authentication failed: Invalid signature\./, { selector: '[data-role="failure"]' })).toBeInTheDocument();
    expect(result()!.querySelector('[data-row="Challenge"]')).toHaveTextContent('server-session');
    await waitFor(() => expect(document.querySelector('#nav-panel-simple li[data-credential-key]')).toHaveAttribute('data-flash', 'failure'));
    expect(storedRecords()[0]).not.toHaveProperty('signCount', 3);
  });

  it('ADV-U2: says there are no credentials when the server finds none', async () => {
    await onAuthentication(authenticationRoutes({ begin: recorded.none }));

    await userEvent.click(button('Assert Credential'));

    expect(await screen.findByText('Advanced authentication failed: No credentials detected. Please register a credential first.')).toBeInTheDocument();
    expect(authenticator.get).not.toHaveBeenCalled();
  });

  it('ADV-U5: says the browser\'s refusal by its name', async () => {
    const refuse = () => Promise.reject(Object.assign(new Error('refused'), { name: 'NotAllowedError' }));
    await onAuthentication(authenticationRoutes(recorded.first), refuse);

    await userEvent.click(button('Assert Credential'));

    expect(await screen.findByText('Advanced authentication failed: User cancelled or no compatible authenticator detected')).toBeInTheDocument();
  });

  it('ADV-U1: refuses an editor text that does not parse, asking nothing of the server', async () => {
    const fetch = await onAuthentication(authenticationRoutes(recorded.first));
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' }), { target: { value: '{"publicKey": {}}' } });

    await userEvent.click(button('Assert Credential'));

    expect(
      await screen.findByText('Advanced authentication failed: Invalid CredentialRequestOptions: Missing required "challenge" property'),
    ).toBeInTheDocument();
    expect(requestsTo(fetch, '/api/advanced/authenticate/begin')).toEqual([]);
  });

  it('runs one ceremony at a time, and keeps each segment\'s own request and last result', async () => {
    let answerGet: (value: unknown) => void = () => {};
    const pending = () => new Promise((resolve) => (answerGet = resolve));
    await onAuthentication(authenticationRoutes(recorded.first), pending);
    fireEvent.change(screen.getByLabelText('Timeout (milliseconds)', { selector: '#nav-panel-advanced [data-authentication-form] input' }), {
      target: { value: '4321' },
    });

    await userEvent.click(button('Assert Credential'));
    await waitFor(() => expect(authenticator.get).toHaveBeenCalled());
    await userEvent.click(screen.getByRole('tab', { name: 'Registration' }));
    expect(button('Create Credential')).toBeDisabled();
    expect(result()).not.toBeVisible();

    await act(async () => answerGet(recordedAssertion(recorded.first)));
    await waitFor(() => expect(button('Create Credential')).toBeEnabled());
    await userEvent.click(screen.getByRole('tab', { name: 'Authentication' }));
    await waitFor(() => expect(result()).toHaveTextContent('Last authentication'));
    expect(JSON.parse(authText()).publicKey.timeout).toBe(4321);
  });
});
