import { beforeEach, describe, expect, it } from 'vitest';

import { renderPageBody } from '../../page-template.js';

// The current editor's Save over the real page (advanced/json-editor/
// editor-flow.js and form-sync.js): what the form holds survives, and what an
// edit asks of the form's own fields reaches them.

const SCRIPTS = '../../../../frontend/static/scripts';

async function page() {
  document.body.innerHTML = renderPageBody().markup;
  const { state } = await import(`${SCRIPTS}/shared/state.js`);
  state.currentSubTab = 'registration';
  state.storedCredentials = [];
  const editor = await import(`${SCRIPTS}/advanced/editor/index.js`);
  document.getElementById('user-id').value = 'abcd';
  document.getElementById('user-name').value = 'alice';
  document.getElementById('user-display-name').value = 'alice';
  document.getElementById('challenge-reg').value = '00112233445566778899aabbccddeeff';
  return editor;
}

const field = (id) => document.getElementById(id);
const text = () => JSON.parse(field('json-editor').value);

describe('Save', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('keeps an Unspecified attachment, which the request leaves out', async () => {
    const editor = await page();
    field('authenticator-attachment').value = 'unspecified';
    editor.updateJsonEditor();
    editor.saveJsonEditor();

    expect(field('advanced-status').textContent).toBe('JSON changes saved successfully!');
    expect(field('authenticator-attachment').value).toBe('unspecified');
    expect(text().publicKey.authenticatorSelection).not.toHaveProperty('authenticatorAttachment');
  });

  it('gives the form the largeBlob support and the prf evaluation an edit asks for', async () => {
    const editor = await page();
    editor.updateJsonEditor();
    const edit = text();
    edit.publicKey.extensions.largeBlob = { support: 'required' };
    edit.publicKey.extensions.prf = { eval: { first: { $hex: 'aa'.repeat(32) } } };
    field('json-editor').value = JSON.stringify(edit);
    editor.saveJsonEditor();

    expect([field('large-blob-reg').value, field('prf-reg').checked, field('prf-eval-first-reg').value]).toEqual(['required', true, 'aa'.repeat(32)]);
    expect(text().publicKey.extensions).toMatchObject({ largeBlob: { support: 'required' }, prf: { eval: { first: { $hex: 'aa'.repeat(32) } } } });
  });
});
