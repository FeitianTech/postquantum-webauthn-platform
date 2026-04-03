import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/status.js', () => ({
  showStatus: vi.fn(),
}));

import { state } from '../../static/scripts/shared/state.js';
import { showStatus } from '../../static/scripts/shared/status.js';
import {
  clearFakeAllowCredentials,
  clearFakeExcludeCredentials,
  createFakeAllowCredential,
  createFakeExcludeCredential,
  getFakeAllowCredentials,
  getFakeExcludeCredentials,
  removeFakeAllowCredential,
  removeFakeExcludeCredential,
  renderFakeAllowCredentialList,
  renderFakeExcludeCredentialList,
  setFakeExcludeCredentials,
} from '../../static/scripts/advanced/exclude-credentials.js';

describe('exclude-credentials', () => {
  beforeEach(() => {
    state.generatedExcludeCredentials = [];
    state.generatedAllowCredentials = [];
    document.body.innerHTML = `
      <div id="fake-cred-generated-list"></div>
      <div id="fake-cred-auth-generated-list"></div>
    `;
  });

  it('renders empty and populated fake credential lists', () => {
    renderFakeExcludeCredentialList();
    expect(document.getElementById('fake-cred-generated-list').textContent).toContain('No fake credential IDs added.');

    setFakeExcludeCredentials(['AA11', 'bb22']);
    renderFakeExcludeCredentialList();
    expect(getFakeExcludeCredentials()).toEqual(['aa11', 'bb22']);
    expect(document.querySelectorAll('.fake-credential-item')).toHaveLength(2);
  });

  it('creates and removes fake exclude and allow credentials', () => {
    const exclude = createFakeExcludeCredential(4);
    const allow = createFakeAllowCredential(2);

    expect(exclude).toHaveLength(8);
    expect(allow).toHaveLength(4);
    expect(getFakeAllowCredentials()).toHaveLength(1);

    expect(removeFakeExcludeCredential(0)).toBe(true);
    expect(removeFakeAllowCredential(0)).toBe(true);

    clearFakeExcludeCredentials();
    clearFakeAllowCredentials();
    renderFakeAllowCredentialList();
    expect(document.getElementById('fake-cred-auth-generated-list').textContent).toContain('No fake allow credential IDs added.');
  });

  it('rejects invalid fake credential lengths', () => {
    expect(createFakeExcludeCredential(0)).toBeNull();
    expect(showStatus).toHaveBeenCalled();
  });
});
