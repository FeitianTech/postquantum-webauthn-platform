// The Advanced tab's authentication form (ADV-A, ADV-AB, ADV-I19..I29, ADV-X2
// in docs/ui-parity/advanced.md): every field changes the request the JSON
// editor holds, with the current form's rules and words, over the credentials
// the recorded authentications registered.
import { advancedAuthentications } from '@legacy-tests/advanced/auth/advanced-answers.js';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { authEditor, authPublicKey, renderAuthenticationForm } from '@/test/advanced';
import { savedRecord } from '@/test/credentials';

const { records } = advancedAuthentications() as { records: Record<string, unknown>[] };
// The first reported largeBlob and prf support, the second neither.
const CAPABLE: Record<string, unknown> = { ...records[0], userName: 'capable@example.com' };
const PLAIN: Record<string, unknown> = { ...records[1], userName: 'plain@example.com' };
const CAPABLE_ID = CAPABLE.credentialIdHex as string;
const PLAIN_ID = PLAIN.credentialIdHex as string;

const field = (name: string) => screen.getByLabelText(name) as HTMLInputElement;
const section = (title: string) => screen.getByRole('region', { name: title });
const options = (name: string) => within(field(name) as unknown as HTMLElement).getAllByRole('option') as HTMLOptionElement[];
const ids = () => (authPublicKey().allowCredentials ?? []).map((descriptor: { id: { $hex: string } }) => descriptor.id.$hex);

async function ready() {
  await waitFor(() => expect(authEditor().value).toContain('"publicKey"'));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the authentication form, when the page has loaded', () => {
  it('ADV-A, ADV-T10: shows the three sections, each field with its label, the byte fields\' in hex', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();

    for (const title of ['Credential Selection', 'Other Options', 'Extensions']) {
      expect(section(title)).toBeInTheDocument();
    }
    for (const label of ['User Verification', 'Allow Credentials', 'Fake credential ID length', 'Challenge (hex)', 'Timeout (milliseconds)', 'Hash Algorithm', 'largeBlob', 'largeBlob write (hex)', 'prf eval first (hex)', 'prf eval second (hex)']) {
      expect(field(label)).toBeInTheDocument();
    }
    expect(options('User Verification').map((option) => option.textContent)).toEqual(['Preferred (default)', 'Discouraged', 'Required']);
    expect(options('Hash Algorithm').map((option) => option.value)).toEqual(['SHA-256', 'SHA-512', 'SHA-384', 'SHA-1', 'SHA3-256', 'SHA3-384', 'SHA3-512']);
    expect(options('largeBlob').map((option) => option.textContent)).toEqual(['Unspecified (default)', 'Read', 'Write']);
    expect(within(section('Other Options')).getAllByRole('button', { pressed: false }).map((chip) => chip.textContent)).toEqual([
      'Client-device',
      'Hybrid',
      'Security-key',
    ]);
    expect(screen.getAllByRole('button', { name: /^About / })).toHaveLength(11);
  });

  it('ADV-T9, ADV-J2: draws a challenge and a largeBlob value of 32 bytes, and gives the editor the request the defaults build', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();

    expect(field('Challenge (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('largeBlob write (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('largeBlob write (hex)')).toBeDisabled();
    expect(field('Fake credential ID length')).toHaveValue(256);
    expect(authPublicKey()).toEqual({
      challenge: { $hex: field('Challenge (hex)').value },
      timeout: 90000,
      rpId: 'localhost',
      allowCredentials: [
        { type: 'public-key', id: { $hex: CAPABLE_ID } },
        { type: 'public-key', id: { $hex: PLAIN_ID } },
      ],
      userVerification: 'preferred',
      extensions: {},
    });
    expect(screen.getByRole('heading', { level: 3, name: 'JSON Editor (CredentialRequestOptions)' })).toBeInTheDocument();
  });

  it('ADV-A2, ADV-AB1: offers All, Empty and each saved credential with its algorithm and attachment', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();

    expect(options('Allow Credentials').map((option) => [option.value, option.textContent])).toEqual([
      ['all', 'All credentials'],
      ['empty', 'Empty (resident key only)'],
      [CAPABLE_ID, 'capable@example.com (ES256 (-7)) • Cross-platform (Security key / Hybrid)'],
      [PLAIN_ID, 'plain@example.com (ES256 (-7)) • Cross-platform (Security key / Hybrid)'],
    ]);
    await userEvent.selectOptions(field('Allow Credentials'), PLAIN_ID);
    expect(ids()).toEqual([PLAIN_ID]);
    await userEvent.selectOptions(field('Allow Credentials'), 'empty');
    expect(authPublicKey()).not.toHaveProperty('allowCredentials');
  });

  it('ADV-AB1: offers only the credentials the authentication\'s hints allow, a choice that goes falling back to All', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();
    await userEvent.selectOptions(field('Allow Credentials'), PLAIN_ID);
    const client = within(section('Other Options')).getByRole('button', { name: 'Client-device' });

    await userEvent.click(client);
    expect(options('Allow Credentials').map((option) => option.value)).toEqual(['all', 'empty']);
    expect(field('Allow Credentials')).toHaveValue('all');
    expect(ids()).toEqual([]);

    await userEvent.click(client);
    expect(options('Allow Credentials').map((option) => option.value)).toEqual(['all', 'empty', CAPABLE_ID, PLAIN_ID]);
    expect(ids()).toEqual([CAPABLE_ID, PLAIN_ID]);
  });

  it('ADV-AB1: leaves the offer to the authentication, whatever the registration form\'s hints', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();
    await userEvent.selectOptions(field('Allow Credentials'), PLAIN_ID);

    await userEvent.click(screen.getByRole('button', { name: 'Registration hint client-device' }));

    expect(options('Allow Credentials').map((option) => option.value)).toEqual(['all', 'empty', CAPABLE_ID, PLAIN_ID]);
    expect(field('Allow Credentials')).toHaveValue(PLAIN_ID);
  });

  it('ADV-AB1: offers and sends the advanced credentials only: a Simple one is the Simple tab\'s, which the server refuses here', async () => {
    const simple = savedRecord('simple-register-es256', { email: 'simple@example.com', userName: 'simple@example.com' });
    renderAuthenticationForm([CAPABLE, simple, PLAIN]);
    await ready();

    expect(options('Allow Credentials').map((option) => option.value)).toEqual(['all', 'empty', CAPABLE_ID, PLAIN_ID]);
    expect(ids()).toEqual([CAPABLE_ID, PLAIN_ID]);
  });

  it('ADV-AB1: reads an edit whose hints refuse the credential it names as All, and sends the edit as typed', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();
    await userEvent.selectOptions(field('Allow Credentials'), PLAIN_ID);
    const edited = { ...authPublicKey(), hints: ['client-device'] };

    fireEvent.change(authEditor(), { target: { value: JSON.stringify({ publicKey: edited }, null, 2) } });

    await waitFor(() => expect(field('Allow Credentials')).toHaveValue('all'));
    expect(options('Allow Credentials').map((option) => option.value)).toEqual(['all', 'empty']);
    expect(authPublicKey()).toEqual(edited);
  });

  it('ADV-A6: sends the hints chosen, and All the credentials their attachment allows', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();
    const other = within(section('Other Options'));

    await userEvent.click(other.getByRole('button', { name: 'Client-device' }));
    expect(authPublicKey().hints).toEqual(['client-device']);
    expect(authPublicKey().allowCredentials).toEqual([]);
    await userEvent.click(other.getByRole('button', { name: 'Hybrid' }));
    expect(authPublicKey().hints).toEqual(['client-device', 'hybrid']);
    expect(ids()).toEqual([CAPABLE_ID, PLAIN_ID]);
  });

  it('ADV-A1, ADV-A5, ADV-A7: sends the user verification and the timeout; the hash algorithm is not in the request', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();

    await userEvent.selectOptions(field('User Verification'), 'required');
    fireEvent.change(field('Timeout (milliseconds)'), { target: { value: '1234' } });
    await userEvent.selectOptions(field('Hash Algorithm'), 'SHA-512');

    expect(authPublicKey()).toMatchObject({ userVerification: 'required', timeout: 1234 });
    expect(authEditor().value).not.toContain('SHA-512');
  });
});

describe('the extensions', () => {
  it('ADV-AB2, ADV-AB3: lock largeBlob and prf with the current notes when no saved credential can use them', async () => {
    renderAuthenticationForm();
    await ready();

    expect(field('largeBlob')).toBeDisabled();
    expect(options('largeBlob').map((option) => option.disabled)).toEqual([false, true, true]);
    expect(field('largeBlob')).toHaveAccessibleDescription('No largeBlob capable credentials available');
    expect(field('largeBlob write (hex)')).toHaveValue('');
    expect(field('prf eval first (hex)')).toBeDisabled();
    expect(field('prf eval second (hex)')).toBeDisabled();
    expect(field('prf eval first (hex)')).toHaveAccessibleDescription('No credentials with prf support available.');
  });

  it('ADV-AB3: counts no prf for a credential whose registration said prf is not enabled', async () => {
    const disabled = { ...PLAIN, clientExtensionOutputs: { prf: { enabled: false } } };
    renderAuthenticationForm([disabled]);
    await ready();

    expect(field('prf eval first (hex)')).toBeDisabled();
    expect(field('prf eval first (hex)')).toHaveAccessibleDescription('No credentials with prf support available.');
  });

  it('ADV-AB2, ADV-AB3: judge a chosen credential alone, clearing what it cannot ask for', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await ready();
    await userEvent.selectOptions(field('largeBlob'), 'write');
    expect(field('largeBlob write (hex)')).toBeEnabled();
    expect(authPublicKey().extensions.largeBlob).toEqual({ write: { $hex: field('largeBlob write (hex)').value } });
    fireEvent.change(field('prf eval first (hex)'), { target: { value: '11'.repeat(32) } });
    expect(authPublicKey().extensions.prf).toEqual({ eval: { first: { $hex: '11'.repeat(32) } } });

    await userEvent.selectOptions(field('Allow Credentials'), PLAIN_ID);

    expect(field('largeBlob')).toHaveValue('');
    expect(field('largeBlob')).toHaveAccessibleDescription('Selected credential does not support largeBlob.');
    expect(field('prf eval first (hex)')).toHaveValue('');
    expect(field('prf eval first (hex)')).toHaveAccessibleDescription('Selected credential does not support the prf extension.');
    expect(authPublicKey().extensions).toEqual({});

    await userEvent.selectOptions(field('Allow Credentials'), CAPABLE_ID);
    expect(field('largeBlob')).toBeEnabled();
    expect(field('largeBlob')).not.toHaveAccessibleDescription();
  });

  it('ADV-A8, ADV-A9: asks for largeBlob to be read, or written with its value, which the button draws again', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();

    await userEvent.selectOptions(field('largeBlob'), 'read');
    expect(authPublicKey().extensions).toEqual({ largeBlob: { read: true } });
    expect(field('largeBlob write (hex)')).toBeDisabled();
    await userEvent.selectOptions(field('largeBlob'), 'write');
    const before = field('largeBlob write (hex)').value;
    await userEvent.click(within(section('Extensions')).getByRole('button', { name: 'Generate random large blob data' }));
    expect(field('largeBlob write (hex)').value).not.toBe(before);
    expect(authPublicKey().extensions.largeBlob.write.$hex).toBe(field('largeBlob write (hex)').value);
  });

  it('ADV-A10, ADV-A11: open the second prf evaluation with a first, and empty it with the first', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();
    const [first, second] = within(section('Extensions')).getAllByRole('button', { name: 'Generate random PRF evaluation data' });

    expect(field('prf eval second (hex)')).toBeDisabled();
    await userEvent.click(first);
    expect(field('prf eval second (hex)')).toBeEnabled();
    await userEvent.click(second);
    expect(Object.keys(authPublicKey().extensions.prf.eval)).toEqual(['first', 'second']);
    fireEvent.change(field('prf eval first (hex)'), { target: { value: '' } });
    expect(field('prf eval second (hex)')).toHaveValue('');
    expect(authPublicKey().extensions).toEqual({});
  });
});

describe('the byte fields and the fake IDs', () => {
  it('ADV-AB5: say when a byte field holds too few bytes, as they are typed', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();

    fireEvent.change(field('Challenge (hex)'), { target: { value: 'abcd' } });
    expect(field('Challenge (hex)')).toHaveAccessibleDescription('Invalid hex value (minimum 16 bytes required)');
    await userEvent.selectOptions(field('largeBlob'), 'write');
    fireEvent.change(field('largeBlob write (hex)'), { target: { value: 'xyz' } });
    expect(field('largeBlob write (hex)')).toHaveAccessibleDescription('Invalid hex value');
    fireEvent.change(field('prf eval first (hex)'), { target: { value: 'abcd' } });
    expect(field('prf eval first (hex)')).toHaveAccessibleDescription('Invalid hex value (exactly 32 bytes required)');
  });

  it('ADV-A3, ADV-AB4: add fake allow IDs after the saved ones, each deleted on its own', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();
    const selection = within(section('Credential Selection'));

    expect(selection.getByText('No fake allow credential IDs added.')).toBeInTheDocument();
    fireEvent.change(field('Fake credential ID length'), { target: { value: '8' } });
    await userEvent.click(selection.getByRole('button', { name: 'Generate fake credential ID' }));
    const [, fake] = ids();
    expect(fake).toMatch(/^[0-9a-f]{16}$/);
    expect(selection.getByText('8 bytes')).toBeInTheDocument();

    await userEvent.selectOptions(field('Allow Credentials'), 'empty');
    expect(ids()).toEqual([fake]);
    await userEvent.click(selection.getByRole('button', { name: 'Delete' }));
    expect(authPublicKey()).not.toHaveProperty('allowCredentials');
  });
});

describe('the Reset', () => {
  it('ADV-X2: returns to the defaults with a new challenge, keeping the hash algorithm and leaving the registration form alone', async () => {
    renderAuthenticationForm([CAPABLE]);
    await ready();
    await userEvent.click(screen.getByRole('button', { name: 'Registration without algorithms' }));
    const challenge = field('Challenge (hex)').value;
    await userEvent.selectOptions(field('User Verification'), 'required');
    await userEvent.selectOptions(field('Allow Credentials'), 'empty');
    await userEvent.selectOptions(field('Hash Algorithm'), 'SHA-384');
    await userEvent.selectOptions(field('largeBlob'), 'read');
    await userEvent.click(within(section('Other Options')).getByRole('button', { name: 'Hybrid' }));
    fireEvent.change(authEditor(), { target: { value: JSON.stringify({ ...JSON.parse(authEditor().value), note: 1 }) } });

    await userEvent.click(screen.getByRole('button', { name: 'Reset the authentication' }));

    expect(field('Challenge (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('Challenge (hex)').value).not.toBe(challenge);
    expect([field('User Verification').value, field('Allow Credentials').value, field('largeBlob').value]).toEqual(['preferred', 'all', '']);
    expect(field('Hash Algorithm')).toHaveValue('SHA-384');
    expect(field('largeBlob write (hex)')).toHaveValue('');
    expect(authPublicKey()).not.toHaveProperty('hints');
    expect(JSON.parse(authEditor().value)).not.toHaveProperty('note');
    expect(document.querySelector('[data-registration-algorithms]')).toHaveTextContent(/^$/);
  });
});
