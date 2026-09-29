// The Advanced tab's JSON editor (ADV-J in docs/ui-parity/advanced.md): the
// request the ceremony sends, as text, which the form and the editor both change.
// An edit applies as it parses (the owner's choice); one that does not says why
// and where, and the form keeps the last request it could read.
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { advancedAuthentications } from '@/test/logic/advanced/auth/advanced-answers.js';

import { authEditor, authPublicKey, editor, publicKey, renderAuthenticationForm, renderForm } from '@/test/advanced';
import { keepRecords, savedRecord } from '@/test/credentials';

const field = (name: string) => screen.getByLabelText(name) as HTMLInputElement;
const note = () => document.querySelector<HTMLElement>('[data-edit]');

async function ready() {
  await waitFor(() => expect(editor().value).toContain('"publicKey"'));
}

/** The editor's text with the request changed by `change`. */
function edited(change: (root: { publicKey: Record<string, unknown> } & Record<string, unknown>) => void) {
  const root = JSON.parse(editor().value);
  change(root);
  return JSON.stringify(root, null, 2);
}

describe('the editor', () => {
  it('ADV-J1, ADV-J2: is headed with the request it holds, keys sorted and indented by two, byte values as hex', async () => {
    renderForm();
    await ready();

    expect(screen.getByRole('heading', { level: 3, name: 'JSON Editor (CredentialCreationOptions)' })).toBeInTheDocument();
    expect(editor()).toHaveAttribute('placeholder', 'JSON representation will appear here automatically...');
    expect(editor()).toHaveAttribute('data-text-field');
    expect(editor().value.split('\n').slice(0, 3)).toEqual(['{', '  "publicKey": {', '    "attestation": "direct",']);
  });

  it('ADV-J4: gives the form what an edit asks for, as it parses, and keeps the text as typed', async () => {
    renderForm();
    await ready();
    const text = edited((root) => {
      root.publicKey.attestation = 'none';
      root.publicKey.user = { ...(root.publicKey.user as object), name: 'dave', displayName: 'Dave' };
      root.publicKey.extensions = { largeBlob: { support: 'required' } };
    }).replace('"attestation"', '"attestation"   ');

    fireEvent.change(editor(), { target: { value: text } });

    expect(field('Attestation')).toHaveValue('none');
    expect([field('User Name').value, field('Display Name').value]).toEqual(['dave', 'Dave']);
    expect(field('largeBlob')).toHaveValue('required');
    expect(screen.getByRole('switch', { name: 'credProps' })).toHaveAttribute('aria-checked', 'false');
    expect(editor()).toHaveValue(text);
    expect(note()).toBeNull();
  });

  it('ADV-J4: says why and where an edit does not parse, and the form keeps the last request', async () => {
    renderForm();
    await ready();
    const before = field('Attestation').value;

    fireEvent.change(editor(), { target: { value: '{\n  "publicKey": {\n    "attestation": "none",\n  }\n}' } });

    expect(note()).toHaveAttribute('role', 'alert');
    expect(note()).toHaveTextContent(/^JSON validation failed: /);
    expect(note()!.querySelector('[data-location]')).toHaveTextContent('Line 4, column 3');
    expect(editor()).toHaveAttribute('aria-invalid', 'true');
    expect(field('Attestation')).toHaveValue(before);
    await userEvent.click(screen.getByRole('button', { name: 'Go to line 4' }));
    expect(editor()).toHaveFocus();
    expect(editor().selectionStart).toBe(48);
  });

  it('ADV-J6: says which check an edit the form cannot follow fails, keeps it as what is sent, and the form as it was', async () => {
    renderForm();
    await ready();
    const text = edited((root) => {
      root.publicKey.timeout = -1;
    });

    fireEvent.change(editor(), { target: { value: text } });

    expect(note()).toHaveAttribute('role', 'status');
    expect(note()).toHaveTextContent('JSON validation failed: publicKey.timeout must be zero or greater.');
    expect(note()).toHaveTextContent('Create Credential sends this JSON as it is.');
    expect(field('Timeout (milliseconds)')).toHaveValue(90000);
    expect(editor()).toHaveValue(text);
  });

  it('keeps the keys an edit adds beside publicKey when the form changes, and rebuilds text that does not parse', async () => {
    renderForm();
    await ready();
    fireEvent.change(editor(), { target: { value: edited((root) => void (root.note = 'mine')) } });

    await userEvent.selectOptions(field('Attestation'), 'indirect');

    expect(JSON.parse(editor().value).note).toBe('mine');
    expect(publicKey().attestation).toBe('indirect');
    fireEvent.change(editor(), { target: { value: '{' } });
    await userEvent.selectOptions(field('Attestation'), 'direct');
    expect(note()).toBeNull();
    expect(JSON.parse(editor().value)).toMatchObject({ note: 'mine', publicKey: { attestation: 'direct' } });
  });

  it('ADV-J5: Reset rebuilds the text from the form, keeping the keys beside publicKey, and says so', async () => {
    renderForm();
    await ready();
    fireEvent.change(editor(), { target: { value: edited((root) => {
      root.extra = { b: 2 };
      root.publicKey.timeout = -1;
    }) } });

    await userEvent.click(screen.getByRole('button', { name: 'Reset' }));

    expect(await screen.findByText('JSON editor reset to current settings.')).toBeInTheDocument();
    expect(note()).toBeNull();
    expect(JSON.parse(editor().value)).toMatchObject({ extra: { b: 2 }, publicKey: { timeout: 90000 } });
  });
});

describe('a form change over an edit', () => {
  const OTHER = savedRecord('advanced-register-packed-x5c-everything', { userName: 'other@example.com' });
  const chip = (name: string) => screen.getByRole('button', { name });

  it('rewrites only what it changes: rp.id, transports, another user\'s credential, the order of hints and algorithms and a timeout of 0 stay as typed', async () => {
    renderForm([OTHER]);
    await ready();
    await userEvent.click(chip('Client-device'));
    await userEvent.click(chip('Security-key'));
    fireEvent.change(editor(), {
      target: {
        value: edited((root) => {
          root.publicKey.rp = { ...(root.publicKey.rp as object), id: 'example.com' };
          root.publicKey.excludeCredentials = [{ type: 'public-key', id: { $hex: OTHER.credentialIdHex }, transports: ['usb'] }];
          root.publicKey.hints = ['security-key', 'client-device'];
          root.publicKey.pubKeyCredParams = [...(root.publicKey.pubKeyCredParams as unknown[])].reverse();
          root.publicKey.timeout = 0;
        }),
      },
    });
    expect(field('Timeout (milliseconds)')).toHaveValue(0);

    await userEvent.click(screen.getByRole('switch', { name: 'credProps' }));

    expect(publicKey().extensions).not.toHaveProperty('credProps');
    expect(publicKey()).toMatchObject({
      rp: { id: 'example.com' },
      excludeCredentials: [{ type: 'public-key', id: { $hex: OTHER.credentialIdHex }, transports: ['usb'] }],
      hints: ['security-key', 'client-device'],
      timeout: 0,
    });
    expect(publicKey().pubKeyCredParams.map((param: { alg: number }) => param.alg)).toEqual([-257, -7, -8, -50, -49, -48]);

    // A hint put in goes where the form lists it before the others, which keep their typed order.
    await userEvent.click(chip('Hybrid'));
    expect(publicKey().hints).toEqual(['hybrid', 'security-key', 'client-device']);
    expect(publicKey().rp.id).toBe('example.com');
  });

  it('follows a change of the saved credentials over an edit, and leaves text that does not parse as it is', async () => {
    renderForm();
    await ready();
    const userId = field('User ID (hex)').value;
    fireEvent.change(editor(), { target: { value: edited((root) => void (root.publicKey.rp = { name: 'Mine', id: 'example.com' })) } });

    // Another tab saves a credential of this user.
    act(() => {
      keepRecords([{ ...OTHER, userHandleHex: userId, userHandle: undefined }]);
      window.dispatchEvent(new StorageEvent('storage', { key: null }));
    });
    await waitFor(() => expect(publicKey().excludeCredentials).toEqual([{ type: 'public-key', id: { $hex: OTHER.credentialIdHex } }]));
    expect(publicKey().rp).toEqual({ name: 'Mine', id: 'example.com' });

    fireEvent.change(editor(), { target: { value: '{ "publicKey": ' } });
    await act(async () => {
      keepRecords([]);
      window.dispatchEvent(new StorageEvent('storage', { key: null }));
    });
    expect(editor()).toHaveValue('{ "publicKey": ');
    // The person's next form change rebuilds it, from the list as it now is.
    await userEvent.click(screen.getByRole('switch', { name: 'credProps' }));
    expect(publicKey().excludeCredentials).toEqual([]);
  });
});

describe('the editor\'s keys', () => {
  it('ADV-J8: Tab and Shift+Tab indent and dedent, Enter keeps the indent, { wraps the selection', async () => {
    renderForm();
    await ready();
    fireEvent.change(editor(), { target: { value: '' } });
    await userEvent.click(editor());

    await userEvent.keyboard('{{');
    expect(editor()).toHaveValue('{}');
    await userEvent.keyboard('{Enter}');
    expect(editor()).toHaveValue('{\n  \n}');
    expect(editor().selectionStart).toBe(4);
    await userEvent.keyboard('{Tab}');
    expect(editor()).toHaveValue('{\n    \n}');
    await userEvent.keyboard('{Shift>}{Tab}{/Shift}');
    expect(editor()).toHaveValue('{\n  \n}');
  });

  it('lets Tab leave the editor after Escape', async () => {
    renderForm();
    await ready();
    await userEvent.click(editor());

    await userEvent.keyboard('{Escape}');
    await userEvent.tab();
    expect(editor()).not.toHaveFocus();
  });
});

describe('the authentication\'s editor', () => {
  const { records } = advancedAuthentications() as { records: Record<string, unknown>[] };
  const [CAPABLE, PLAIN] = records;
  const CAPABLE_ID = CAPABLE.credentialIdHex as string;

  async function authReady() {
    await waitFor(() => expect(authEditor().value).toContain('"publicKey"'));
  }

  function authEdited(change: (root: { publicKey: Record<string, unknown> } & Record<string, unknown>) => void) {
    const root = JSON.parse(authEditor().value);
    change(root);
    return JSON.stringify(root, null, 2);
  }

  it('ADV-J2, ADV-J4: gives the form what an edit asks for, as it parses', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await authReady();
    const text = authEdited((root) => {
      root.publicKey.userVerification = 'required';
      root.publicKey.allowCredentials = [{ type: 'public-key', id: { $hex: CAPABLE_ID } }, { type: 'public-key', id: { $hex: 'ffee' } }];
      root.publicKey.extensions = { largeBlob: { read: true }, prf: { eval: { first: { $hex: '11'.repeat(32) } } } };
      root.publicKey.hints = ['hybrid'];
    });

    fireEvent.change(authEditor(), { target: { value: text } });

    expect(field('User Verification')).toHaveValue('required');
    expect(field('Allow Credentials')).toHaveValue(CAPABLE_ID);
    expect(field('largeBlob')).toHaveValue('read');
    expect(field('prf eval first (hex)')).toHaveValue('11'.repeat(32));
    expect(screen.getByRole('button', { name: 'Hybrid' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('2 bytes')).toBeInTheDocument();
    expect(authEditor()).toHaveValue(text);
    expect(note()).toBeNull();
  });

  it('ADV-J4, ADV-J7: says where an edit does not parse, and which check refuses one, the form keeping the last request', async () => {
    renderAuthenticationForm([CAPABLE]);
    await authReady();
    const refused = authEdited((root) => {
      root.publicKey.rpId = '';
      root.publicKey.userVerification = 'required';
    });

    fireEvent.change(authEditor(), { target: { value: '{\n  "publicKey": [\n' } });
    expect(note()).toHaveAttribute('role', 'alert');
    expect(note()!.querySelector('[data-location]')).toHaveTextContent('Line 3, column 1');

    fireEvent.change(authEditor(), { target: { value: refused } });
    expect(note()).toHaveTextContent('JSON validation failed: publicKey.rpId must be a non-empty string when provided.');
    expect(note()).toHaveTextContent('Assert Credential sends this JSON as it is.');
    expect(field('User Verification')).toHaveValue('preferred');
  });

  it('keeps what an edit typed through a form change: rpId, transports, an ID no saved credential has, the order of hints, a timeout of 0', async () => {
    renderAuthenticationForm([CAPABLE, PLAIN]);
    await authReady();
    fireEvent.change(authEditor(), {
      target: {
        value: authEdited((root) => {
          root.publicKey.rpId = 'example.com';
          root.publicKey.allowCredentials = [
            { type: 'public-key', id: { $hex: CAPABLE_ID }, transports: ['usb'] },
            { type: 'public-key', id: { $hex: PLAIN.credentialIdHex } },
            { type: 'public-key', id: { $hex: 'ffee' } },
          ];
          root.publicKey.hints = ['security-key', 'hybrid'];
          root.publicKey.timeout = 0;
        }),
      },
    });
    expect(field('Timeout (milliseconds)')).toHaveValue(0);

    await userEvent.selectOptions(field('User Verification'), 'discouraged');

    expect(authPublicKey()).toMatchObject({
      userVerification: 'discouraged',
      rpId: 'example.com',
      allowCredentials: [
        { type: 'public-key', id: { $hex: CAPABLE_ID }, transports: ['usb'] },
        { type: 'public-key', id: { $hex: PLAIN.credentialIdHex } },
        { type: 'public-key', id: { $hex: 'ffee' } },
      ],
      hints: ['security-key', 'hybrid'],
      timeout: 0,
    });
  });
});
