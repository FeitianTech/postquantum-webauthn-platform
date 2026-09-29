// The Advanced tab's registration form: every field changes the request the JSON
// editor holds, by the logic's rules and in its words.
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { editor, publicKey, renderForm } from '@/test/advanced';
import { savedRecord } from '@/test/credentials';

const field = (name: string) => screen.getByLabelText(name) as HTMLInputElement;
const section = (title: string) => screen.getByRole('region', { name: title });
const chip = (name: string) => screen.getByRole('button', { name });

async function ready() {
  await waitFor(() => expect(editor().value).toContain('"publicKey"'));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the registration form, when the page has loaded', () => {
  it('draws a User ID and a challenge of 32 bytes and a ten-character name, the display name the same', async () => {
    renderForm();
    await ready();

    expect(field('User ID (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('Challenge (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('User Name').value).toMatch(/^[A-Za-z0-9]{10}$/);
    expect(field('Display Name')).toHaveValue(field('User Name').value);
    expect(field('Display Name')).toHaveAttribute('readonly');
  });

  it('gives the editor the request the defaults build, the algorithms most preferred first', async () => {
    renderForm();
    await ready();

    expect(publicKey()).toEqual({
      rp: { name: 'FIDO2/WebAuthn PQC Developer Tools', id: 'localhost' },
      user: { id: { $hex: field('User ID (hex)').value }, name: field('User Name').value, displayName: field('User Name').value },
      challenge: { $hex: field('Challenge (hex)').value },
      pubKeyCredParams: [-48, -49, -50, -8, -7, -257].map((alg) => ({ type: 'public-key', alg })),
      timeout: 90000,
      authenticatorSelection: { authenticatorAttachment: 'cross-platform', residentKey: 'discouraged', requireResidentKey: false, userVerification: 'preferred' },
      attestation: 'direct',
      excludeCredentials: [],
      extensions: { credProps: true },
    });
  });

  it('ADV-R: shows the four sections, each field with its label, and each select with its options', async () => {
    renderForm();
    await ready();

    for (const title of ['User Identity', 'Authenticator Selection', 'Other Options', 'Extensions']) {
      expect(section(title)).toBeInTheDocument();
    }
    expect(within(field('Resident Key') as unknown as HTMLElement).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'Discouraged (default)',
      'Preferred',
      'Required',
    ]);
    expect(within(field('credProtect') as unknown as HTMLElement).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'Unspecified (default)',
      'userVerificationOptional',
      'userVerificationOptionalWithCredentialIDList',
      'userVerificationRequired',
    ]);
    expect(screen.getByRole('group', { name: 'Public Key Credential Parameters' })).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Hints' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /^About / })).toHaveLength(18);
  });
});

describe('each field changes the request', () => {
  it('the selection and the attestation', async () => {
    renderForm();
    await ready();

    await userEvent.selectOptions(field('Authenticator Attachment'), 'unspecified');
    await userEvent.selectOptions(field('Resident Key'), 'required');
    await userEvent.selectOptions(field('User Verification'), 'discouraged');
    await userEvent.selectOptions(field('Attestation'), 'none');

    expect(publicKey().authenticatorSelection).toEqual({ residentKey: 'required', requireResidentKey: true, userVerification: 'discouraged' });
    expect(publicKey().attestation).toBe('none');
  });

  it('the algorithms, a chip for each, ML-DSA under PQC', async () => {
    renderForm();
    await ready();

    await userEvent.click(chip('EdDSA'));
    await userEvent.click(chip('ES512'));
    await userEvent.click(chip('ML-DSA-65'));

    expect(chip('EdDSA')).toHaveAttribute('aria-pressed', 'false');
    expect(publicKey().pubKeyCredParams.map((param: { alg: number }) => param.alg)).toEqual([-48, -50, -7, -257, -36]);
    expect(screen.getByText('PQC')).toBeInTheDocument();
  });

  it('the hints, in the form\'s order', async () => {
    renderForm();
    await ready();

    await userEvent.click(chip('Security-key'));
    await userEvent.click(chip('Client-device'));
    expect(publicKey().hints).toEqual(['client-device', 'security-key']);
    await userEvent.click(chip('Security-key'));
    await userEvent.click(chip('Client-device'));
    expect(publicKey()).not.toHaveProperty('hints');
  });

  it('the timeout and the extensions', async () => {
    renderForm();
    await ready();

    fireEvent.change(field('Timeout (milliseconds)'), { target: { value: '5000' } });
    await userEvent.click(screen.getByRole('switch', { name: 'credProps' }));
    await userEvent.click(screen.getByRole('switch', { name: 'minPinLength' }));
    await userEvent.selectOptions(field('credProtect'), 'userVerificationRequired');
    await userEvent.selectOptions(field('largeBlob'), 'preferred');

    expect(publicKey().timeout).toBe(5000);
    expect(publicKey().extensions).toEqual({
      minPinLength: true,
      credentialProtectionPolicy: 'userVerificationRequired',
      enforceCredentialProtectionPolicy: true,
      largeBlob: { support: 'preferred' },
    });
  });

  it('prf evaluations only with prf on and a first one, drawn at random by the buttons', async () => {
    renderForm();
    await ready();

    await userEvent.click(screen.getByRole('switch', { name: 'prf' }));
    expect(publicKey().extensions).not.toHaveProperty('prf');
    expect(field('prf eval second (hex)')).toBeDisabled();
    await userEvent.click(within(section('Extensions')).getAllByRole('button', { name: 'Generate random PRF evaluation data' })[0]);
    expect(field('prf eval first (hex)').value).toMatch(/^[0-9a-f]{64}$/);
    expect(field('prf eval second (hex)')).toBeEnabled();
    await userEvent.click(within(section('Extensions')).getAllByRole('button', { name: 'Generate random PRF evaluation data' })[1]);

    expect(publicKey().extensions.prf).toEqual({
      eval: { first: { $hex: field('prf eval first (hex)').value }, second: { $hex: field('prf eval second (hex)').value } },
    });
  });
});

describe('the form\'s rules', () => {
  it('a user name is also the display name', async () => {
    renderForm();
    await ready();

    await userEvent.clear(field('User Name'));
    await userEvent.type(field('User Name'), 'carol');
    expect(field('Display Name')).toHaveValue('carol');
    expect(publicKey().user).toMatchObject({ name: 'carol', displayName: 'carol' });
  });

  it('Enforce credProtect is on and cannot change while credProtect is Unspecified', async () => {
    renderForm();
    await ready();
    const enforce = screen.getByRole('switch', { name: 'Enforce credProtect' });

    expect(enforce).toBeDisabled();
    await userEvent.selectOptions(field('credProtect'), 'userVerificationOptional');
    await userEvent.click(enforce);
    expect(enforce).toHaveAttribute('aria-checked', 'false');
    await userEvent.selectOptions(field('credProtect'), '');
    expect(enforce).toBeDisabled();
    expect(enforce).toHaveAttribute('aria-checked', 'true');
  });

  it('a resident key no longer required asks for no largeBlob', async () => {
    renderForm();
    await ready();

    await userEvent.selectOptions(field('Resident Key'), 'required');
    await userEvent.selectOptions(field('largeBlob'), 'required');
    await userEvent.selectOptions(field('Resident Key'), 'preferred');
    expect(field('largeBlob')).toHaveValue('');
  });

  it('emptying the first prf evaluation empties and locks the second', async () => {
    renderForm();
    await ready();

    fireEvent.change(field('prf eval first (hex)'), { target: { value: 'aa' } });
    fireEvent.change(field('prf eval second (hex)'), { target: { value: 'bb' } });
    fireEvent.change(field('prf eval first (hex)'), { target: { value: '' } });
    expect(field('prf eval second (hex)')).toHaveValue('');
    expect(field('prf eval second (hex)')).toBeDisabled();
  });

  it('a byte field too short, or not hex, says so under it', async () => {
    renderForm();
    await ready();

    fireEvent.change(field('User ID (hex)'), { target: { value: 'zz' } });
    fireEvent.change(field('Challenge (hex)'), { target: { value: '0011' } });
    fireEvent.change(field('prf eval first (hex)'), { target: { value: 'aa' } });

    expect(field('User ID (hex)')).toHaveAccessibleDescription('Invalid hex value (1-64 bytes required)');
    expect(field('Challenge (hex)')).toHaveAccessibleDescription('Invalid hex value (minimum 16 bytes required)');
    expect(field('prf eval first (hex)')).toHaveAccessibleDescription('Invalid hex value (exactly 32 bytes required)');
  });

  it('the buttons draw a new User ID and name, and a new challenge', async () => {
    renderForm();
    await ready();
    const before = [field('User ID (hex)').value, field('User Name').value, field('Challenge (hex)').value];

    await userEvent.click(screen.getByRole('button', { name: 'Generate a new random User ID and username' }));
    await userEvent.click(screen.getByRole('button', { name: 'Generate new random challenge' }));

    const after = [field('User ID (hex)').value, field('User Name').value, field('Challenge (hex)').value];
    after.forEach((value, index) => expect(value).not.toBe(before[index]));
    expect(field('Display Name')).toHaveValue(after[1]);
  });
});

describe('the credentials a registration excludes', () => {
  const OWN = savedRecord('advanced-register-packed-x5c-everything', { userName: 'own@example.com' });

  it('are this user\'s saved credentials while Exclude Credentials is on', async () => {
    renderForm([OWN]);
    await ready();

    fireEvent.change(field('User ID (hex)'), { target: { value: OWN.userHandleHex } });
    await waitFor(() => expect(publicKey().excludeCredentials).toEqual([{ type: 'public-key', id: { $hex: OWN.credentialIdHex } }]));
    await userEvent.click(screen.getByRole('switch', { name: 'Exclude Credentials' }));
    expect(publicKey().excludeCredentials).toEqual([]);
  });

  it('add a fake ID of the length asked for, listed with its size and Delete', async () => {
    renderForm();
    await ready();
    const fakes = within(section('Authenticator Selection'));

    expect(fakes.getByText('No fake credential IDs added.')).toBeInTheDocument();
    fireEvent.change(field('Fake credential ID length'), { target: { value: '16' } });
    await userEvent.click(screen.getByRole('button', { name: 'Generate fake credential ID' }));

    const [id] = publicKey().excludeCredentials.map((entry: { id: { $hex: string } }) => entry.id.$hex);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(fakes.getByText('16 bytes')).toBeInTheDocument();
    await userEvent.click(fakes.getByRole('button', { name: 'Delete' }));
    expect(publicKey().excludeCredentials).toEqual([]);
  });

  it('say in place why a length makes no ID, and that one over 4096 bytes is cut to it', async () => {
    renderForm();
    await ready();

    fireEvent.change(field('Fake credential ID length'), { target: { value: '0' } });
    await userEvent.click(screen.getByRole('button', { name: 'Generate fake credential ID' }));
    expect(field('Fake credential ID length')).toHaveAccessibleDescription('Please enter a valid fake credential ID length (at least 1 byte).');

    fireEvent.change(field('Fake credential ID length'), { target: { value: '5000' } });
    await userEvent.click(screen.getByRole('button', { name: 'Generate fake credential ID' }));
    expect(field('Fake credential ID length')).toHaveAccessibleDescription(
      'Credential IDs are limited to 4096 bytes. Generated value truncated to maximum length.',
    );
    expect(screen.getByText('4096 bytes')).toBeInTheDocument();
  });
});

describe('the info popups', () => {
  it('ADV-I: open beside their label in English, and give the 中文 text', async () => {
    renderForm();
    await ready();

    await userEvent.click(screen.getByRole('button', { name: 'About Resident Key' }));
    const popup = screen.getByRole('group', { name: 'About Resident Key' });
    expect(popup).toHaveTextContent('A resident key can be used for "username-less" authentication');
    await userEvent.click(within(popup).getByRole('button', { name: 'ENG, show in Chinese' }));
    expect(popup).toHaveTextContent('常驻密钥可用于“无用户名”身份验证');
  });
});

describe('the form\'s reset', () => {
  it('returns every field to its default, with new random values, and drops the fake IDs', async () => {
    renderForm();
    await ready();
    const userId = field('User ID (hex)').value;

    await userEvent.selectOptions(field('Attestation'), 'none');
    await userEvent.click(chip('ES512'));
    await userEvent.click(screen.getByRole('button', { name: 'Generate fake credential ID' }));
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: 'Reset the form' }));
    });

    expect(field('Attestation')).toHaveValue('direct');
    expect(chip('ES512')).toHaveAttribute('aria-pressed', 'false');
    expect(field('User ID (hex)').value).not.toBe(userId);
    expect(publicKey().excludeCredentials).toEqual([]);
  });
});
