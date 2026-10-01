import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CLEAR_ALL_CONFIRMATION,
  DELETE_TEXT,
  clearSavedCredentials,
  deleteConfirmation,
  deleteSavedCredential,
} from './delete-flow.js';

// Deleting a saved credential and clearing them all (advanced/credentials/delete-flow.js):
// what is asked, in what order, and what each outcome says.

const SIMPLE = { type: 'simple', credentialIdBase64Url: 'AQID', email: 'alice' };
const ADVANCED = { type: 'advanced', credentialId: 'BAUG', storageId: ' s-1 ', userName: 'bob' };

function deps(overrides = {}) {
  const calls = [];
  const record = (name, result) => vi.fn((...args) => {
    calls.push([name, ...args]);
    return result;
  });
  return {
    calls,
    isCredentialDeletionInProgress: record('inProgress?', false),
    confirm: record('confirm', true),
    setCredentialDeletionInProgress: record('busy'),
    dismissAllTransientMessages: record('dismiss'),
    showSharedCredentialProgress: record('progress'),
    hideSharedCredentialProgress: record('progress done'),
    showSharedCredentialStatus: record('status'),
    removeSimpleCredentialFromLocal: record('remove simple', true),
    removeAdvancedCredentialFromLocal: record('remove advanced', true),
    deleteCredentialArtifact: record('delete artifact', Promise.resolve({ status: 'deleted' })),
    loadSavedCredentials: record('reload', Promise.resolve()),
    getAllSimpleCredentials: record('simple', [SIMPLE]),
    getAllAdvancedCredentials: record('advanced', [ADVANCED]),
    clearLocalSimpleCredentials: record('clear simple'),
    ...overrides,
  };
}

const statusOf = (flow) => flow.showSharedCredentialStatus.mock.calls.at(-1);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the question before deleting', () => {
  it('names whose credential it is', () => {
    expect(deleteConfirmation({ userName: 'alice', username: 'a', email: 'e' })).toBe(
      'Are you sure you want to delete the credential for alice? This action cannot be undone.',
    );
    expect(deleteConfirmation({ username: 'a' })).toContain('for a?');
    expect(deleteConfirmation({ email: 'e' })).toContain('for e?');
    expect(deleteConfirmation({})).toContain('for this credential?');
    expect(CLEAR_ALL_CONFIRMATION).toBe('Are you sure you want to delete all saved credentials? This action cannot be undone.');
  });
});

describe('deleting one credential', () => {
  it('asks, then removes a simple one from this browser, reads the list again and says so', async () => {
    const flow = deps();
    await deleteSavedCredential(SIMPLE, flow);
    expect(flow.calls).toEqual([
      ['inProgress?'],
      ['confirm', deleteConfirmation(SIMPLE)],
      ['busy', true],
      ['dismiss'],
      ['progress', 'Deleting credential...'],
      ['remove simple', 'AQID', 'alice'],
      ['reload'],
      ['status', 'Deletion successful.', 'success'],
      ['progress done'],
      ['busy', false],
    ]);
  });

  it('removes a simple one by its credential id or id, for its account', async () => {
    const flow = deps();
    await deleteSavedCredential({ type: 'simple', credentialId: 'X', userName: 'u' }, flow);
    await deleteSavedCredential({ type: 'simple', id: 'Y', username: 'v' }, flow);
    expect(flow.removeSimpleCredentialFromLocal.mock.calls).toEqual([['X', 'u'], ['Y', 'v']]);
  });

  it('says when this browser kept a simple one', async () => {
    const flow = deps({ removeSimpleCredentialFromLocal: vi.fn(() => false) });
    await deleteSavedCredential(SIMPLE, flow);
    expect(statusOf(flow)).toEqual([DELETE_TEXT.notRemovedLocally, 'error']);
    expect(flow.loadSavedCredentials).not.toHaveBeenCalled();
  });

  it('deletes an advanced one on the server first, then here', async () => {
    const flow = deps();
    await deleteSavedCredential(ADVANCED, flow);
    expect(flow.deleteCredentialArtifact).toHaveBeenCalledWith(' s-1 ');
    expect(flow.removeAdvancedCredentialFromLocal).toHaveBeenCalledWith('BAUG', ' s-1 ');
    expect(statusOf(flow)).toEqual(['Deletion successful.', 'success']);
  });

  it('keeps an advanced one the server refused to delete, with the server\'s reason or a sentence', async () => {
    const refused = deps({ deleteCredentialArtifact: vi.fn(async () => ({ status: 'failed', error: 'Delete request failed.' })) });
    await deleteSavedCredential(ADVANCED, refused);
    expect(statusOf(refused)).toEqual(['Delete request failed.', 'error']);
    expect(refused.removeAdvancedCredentialFromLocal).not.toHaveBeenCalled();

    const silent = deps({ deleteCredentialArtifact: vi.fn(async () => ({ status: 'failed' })) });
    await deleteSavedCredential(ADVANCED, silent);
    expect(statusOf(silent)).toEqual([DELETE_TEXT.serverRefused, 'error']);
  });

  it('says when the server deleted an advanced one but this browser kept it', async () => {
    const flow = deps({ removeAdvancedCredentialFromLocal: vi.fn(() => false) });
    await deleteSavedCredential(ADVANCED, flow);
    expect(statusOf(flow)).toEqual([DELETE_TEXT.removedFromServerOnly, 'error']);
  });

  it('warns when the server no longer had an advanced one', async () => {
    const flow = deps({ deleteCredentialArtifact: vi.fn(async () => ({ status: 'absent' })) });
    await deleteSavedCredential({ ...ADVANCED, storageId: null, localStorageId: 'l-1' }, flow);
    expect(flow.deleteCredentialArtifact).toHaveBeenCalledWith('l-1');
    expect(statusOf(flow)).toEqual([DELETE_TEXT.alreadyAbsent, 'warning']);
  });

  it('removes an advanced one the server never held from this browser only', async () => {
    const flow = deps();
    await deleteSavedCredential({ type: 'advanced', id: 'CAkK' }, flow);
    expect(flow.deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(flow.removeAdvancedCredentialFromLocal).toHaveBeenCalledWith('CAkK', null);
    expect(statusOf(flow)).toEqual(['Deletion successful.', 'success']);

    const kept = deps({ removeAdvancedCredentialFromLocal: vi.fn(() => false) });
    await deleteSavedCredential({ type: 'advanced', id: 'CAkK' }, kept);
    expect(statusOf(kept)).toEqual([DELETE_TEXT.notRemovedLocally, 'error']);
  });

  it('does nothing while another deletion runs, for no credential, or when the person says no', async () => {
    const busy = deps({ isCredentialDeletionInProgress: vi.fn(() => true) });
    await deleteSavedCredential(SIMPLE, busy);
    expect(busy.calls).toEqual([['status', DELETE_TEXT.inProgress, 'info']]);

    const none = deps();
    await deleteSavedCredential(undefined, none);
    expect(none.confirm).not.toHaveBeenCalled();

    const declined = deps({ confirm: vi.fn(() => false) });
    await deleteSavedCredential(SIMPLE, declined);
    expect(declined.setCredentialDeletionInProgress).not.toHaveBeenCalled();
  });
});

describe('clearing every credential', () => {
  it('asks, clears the simple ones, deletes each advanced one, reads the list again and says so', async () => {
    const flow = deps();
    await clearSavedCredentials(flow);
    expect(flow.calls.map(([name]) => name)).toEqual([
      'inProgress?', 'simple', 'advanced', 'confirm', 'busy', 'dismiss', 'progress', 'clear simple',
      'delete artifact', 'remove advanced', 'reload', 'status', 'progress done', 'busy',
    ]);
    expect(flow.confirm).toHaveBeenCalledWith(CLEAR_ALL_CONFIRMATION);
    expect(flow.showSharedCredentialProgress).toHaveBeenCalledWith('Clearing all credentials...');
    expect(flow.deleteCredentialArtifact).toHaveBeenCalledWith('s-1');
    expect(flow.removeAdvancedCredentialFromLocal).toHaveBeenCalledWith('BAUG', 's-1');
    expect(statusOf(flow)).toEqual(['Deletion successful.', 'success']);
  });

  it('says there is nothing to clear, and asks nothing', async () => {
    const flow = deps({ getAllSimpleCredentials: vi.fn(() => []), getAllAdvancedCredentials: vi.fn(() => []) });
    await clearSavedCredentials(flow);
    expect(statusOf(flow)).toEqual([DELETE_TEXT.nothingToClear, 'info']);
    expect(flow.confirm).not.toHaveBeenCalled();
  });

  it('does nothing while a deletion runs, or when the person says no', async () => {
    const busy = deps({ isCredentialDeletionInProgress: vi.fn(() => true) });
    await clearSavedCredentials(busy);
    expect(statusOf(busy)).toEqual([DELETE_TEXT.inProgress, 'info']);

    const declined = deps({ confirm: vi.fn(() => false) });
    await clearSavedCredentials(declined);
    expect(declined.clearLocalSimpleCredentials).not.toHaveBeenCalled();
  });

  it('removes an advanced one the server never held from this browser only', async () => {
    const flow = deps({
      getAllSimpleCredentials: vi.fn(() => []),
      getAllAdvancedCredentials: vi.fn(() => [{ id: 'CAkK', storageId: '  ' }, { credentialIdBase64Url: 'DAsM' }, null]),
      removeAdvancedCredentialFromLocal: vi.fn((id) => id === 'CAkK'),
    });
    await clearSavedCredentials(flow);
    expect(flow.deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(flow.removeAdvancedCredentialFromLocal.mock.calls).toEqual([['CAkK', null], ['DAsM', null], [undefined, null]]);
    expect(statusOf(flow)).toEqual([
      'Clearing completed with issues: 2 credentials could not be deleted from server storage and were kept.',
      'error',
    ]);
  });

  it('counts one the server refused or this browser kept as kept', async () => {
    const refused = deps({
      getAllSimpleCredentials: vi.fn(() => []),
      deleteCredentialArtifact: vi.fn(async () => ({ status: 'failed' })),
    });
    await clearSavedCredentials(refused);
    expect(statusOf(refused)).toEqual([
      'Clearing completed with issues: 1 credential could not be deleted from server storage and was kept.',
      'error',
    ]);

    const kept = deps({ getAllSimpleCredentials: vi.fn(() => []), removeAdvancedCredentialFromLocal: vi.fn(() => false) });
    await clearSavedCredentials(kept);
    expect(statusOf(kept)[1]).toBe('error');
  });

  it('warns of the ones the server no longer had', async () => {
    const one = deps({ deleteCredentialArtifact: vi.fn(async () => ({ status: 'absent' })) });
    await clearSavedCredentials(one);
    expect(statusOf(one)).toEqual(['Clearing complete. 1 credential was already absent from server storage.', 'warning']);

    const two = deps({
      getAllAdvancedCredentials: vi.fn(() => [ADVANCED, { ...ADVANCED, credentialId: 'CAkK', storageId: 's-2' }]),
      deleteCredentialArtifact: vi.fn(async () => ({ status: 'absent' })),
    });
    await clearSavedCredentials(two);
    expect(statusOf(two)).toEqual(['Clearing complete. 2 credentials were already absent from server storage.', 'warning']);
  });

  it('counts an answer that is neither deleted nor absent as kept', async () => {
    const flow = deps({
      getAllSimpleCredentials: vi.fn(() => []),
      deleteCredentialArtifact: vi.fn(async () => ({ status: 'unknown' })),
    });
    await clearSavedCredentials(flow);
    expect(statusOf(flow)).toEqual([
      'Clearing completed with issues: 1 credential could not be deleted from server storage and was kept.',
      'error',
    ]);
  });

  it('says clearing failed when a step throws, and lets the list be used again', async () => {
    const flow = deps({ loadSavedCredentials: vi.fn(async () => { throw new Error('storage gone'); }) });
    await clearSavedCredentials(flow);
    expect(statusOf(flow)).toEqual([DELETE_TEXT.clearFailed, 'error']);
    expect(flow.setCredentialDeletionInProgress).toHaveBeenLastCalledWith(false);
  });
});
