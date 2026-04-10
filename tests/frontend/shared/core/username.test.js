import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../../frontend/static/scripts/advanced/forms.js', () => ({
  randomizeUserId: vi.fn(),
}));

import { updateJsonEditor } from '../../../../frontend/static/scripts/advanced/json-editor.js';
import { randomizeUserId } from '../../../../frontend/static/scripts/advanced/forms.js';

async function loadUsernameModule() {
  vi.resetModules();
  return import('../../../../frontend/static/scripts/shared/username.js');
}

describe('username helpers', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <input id="user-name" />
      <input id="user-display-name" />
      <input id="simple-email" />
    `;
  });

  it('generates and randomizes usernames', async () => {
    const {
      generateRandom10DigitUsername,
      randomizeUsername,
      randomizeUserIdentity,
      initializeSimpleUsername,
      randomizeSimpleUsername,
    } = await loadUsernameModule();

    const generated = generateRandom10DigitUsername();
    expect(generated).toHaveLength(10);

    randomizeUsername();
    expect(document.getElementById('user-name').value).toHaveLength(10);
    expect(document.getElementById('user-display-name').value).toBe(document.getElementById('user-name').value);
    expect(updateJsonEditor).toHaveBeenCalled();

    randomizeUserIdentity();
    expect(randomizeUserId).toHaveBeenCalled();

    initializeSimpleUsername();
    const firstValue = document.getElementById('simple-email').value;
    initializeSimpleUsername();
    expect(document.getElementById('simple-email').value).toBe(firstValue);

    randomizeSimpleUsername();
    expect(document.getElementById('simple-email').value).toHaveLength(10);
  });
});
