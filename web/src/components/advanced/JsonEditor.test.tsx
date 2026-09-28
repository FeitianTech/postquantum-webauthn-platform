// The Advanced tab's JSON editor (ADV-J in docs/ui-parity/advanced.md): the
// request the ceremony sends, as text, which the form and the editor both change.
// An edit applies as it parses (the owner's choice); one that does not says why
// and where, and the form keeps the last request it could read.
import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { editor, publicKey, renderForm } from '@/test/advanced';

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

  it('keeps the keys an edit adds beside publicKey when the form changes, and a form change replaces the rest of the edit', async () => {
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

  it('ADV-J5: Reset rebuilds the text from the form, keeping the keys beside publicKey', async () => {
    renderForm();
    await ready();
    fireEvent.change(editor(), { target: { value: edited((root) => {
      root.extra = { b: 2 };
      root.publicKey.timeout = -1;
    }) } });

    await userEvent.click(screen.getByRole('button', { name: 'Reset' }));

    expect(note()).toBeNull();
    expect(JSON.parse(editor().value)).toMatchObject({ extra: { b: 2 }, publicKey: { timeout: 90000 } });
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
