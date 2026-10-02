import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CLEAR_ALL_CONFIRMATION,
  DELETE_TEXT,
  clearSavedCredentials,
  deleteConfirmation,
  deleteSavedCredential,
} from './delete-flow.js';
import { deleteCredentialArtifact } from './storage/artifacts-client.js';
import { getAllAdvancedCredentials, removeAdvancedCredential } from './storage/local/advanced-credentials.js';
import { clearSimpleCredentials, getAllSimpleCredentials, removeSimpleCredential } from './storage/local/simple-credentials.js';

// Deleting a saved credential and clearing them all (credentials/delete-flow.js):
// in what order, and what each outcome says. The storage and the server answer
// as each test says.

vi.mock('./storage/artifacts-client.js', () => ({ deleteCredentialArtifact: vi.fn() }));
vi.mock('./storage/local/advanced-credentials.js', () => ({
  getAllAdvancedCredentials: vi.fn(),
  removeAdvancedCredential: vi.fn(),
}));
vi.mock('./storage/local/simple-credentials.js', () => ({
  clearSimpleCredentials: vi.fn(),
  getAllSimpleCredentials: vi.fn(),
  removeSimpleCredential: vi.fn(),
}));

const SIMPLE = { type: 'simple', credentialIdBase64Url: 'AQID', email: 'alice' };
const ADVANCED = { type: 'advanced', credentialId: 'BAUG', storageId: ' s-1 ', userName: 'bob' };

// The storage, the server and the list's report, each call written down in order.
function flow({
  running = false,
  simple = [SIMPLE],
  advanced = [ADVANCED],
  removeSimple = true,
  removeAdvanced = true,
  artifact = { status: 'deleted' },
  reload = async () => {},
} = {}) {
  const calls = [];
  const record = (name, result) => (...args) => {
    calls.push([name, ...args]);
    return typeof result === 'function' ? result(...args) : result;
  };
  vi.mocked(getAllSimpleCredentials).mockImplementation(record('simple', simple));
  vi.mocked(getAllAdvancedCredentials).mockImplementation(record('advanced', advanced));
  vi.mocked(removeSimpleCredential).mockImplementation(record('remove simple', removeSimple));
  vi.mocked(removeAdvancedCredential).mockImplementation(record('remove advanced', removeAdvanced));
  vi.mocked(clearSimpleCredentials).mockImplementation(record('clear simple'));
  vi.mocked(deleteCredentialArtifact).mockImplementation(record('delete artifact', async () => artifact));
  const report = {
    isRunning: vi.fn(record('running?', running)),
    setRunning: vi.fn(record('busy')),
    dismiss: vi.fn(record('dismiss')),
    progress: vi.fn(record('progress')),
    status: vi.fn(record('status')),
    reload: vi.fn(record('reload', reload)),
  };
  return { calls, report };
}

const statusOf = (report) => report.status.mock.calls.at(-1);

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
  it('removes a simple one from this browser, reads the list again and says so', async () => {
    const { calls, report } = flow();
    await deleteSavedCredential(SIMPLE, report);
    expect(calls).toEqual([
      ['running?'],
      ['busy', true],
      ['dismiss'],
      ['progress', 'Deleting credential...'],
      ['remove simple', 'AQID', 'alice'],
      ['reload'],
      ['status', 'Deletion successful.', 'success'],
      ['progress', null],
      ['busy', false],
    ]);
  });

  it('removes a simple one by its credential id or id, for its account', async () => {
    const { report } = flow();
    await deleteSavedCredential({ type: 'simple', credentialId: 'X', userName: 'u' }, report);
    await deleteSavedCredential({ type: 'simple', id: 'Y', username: 'v' }, report);
    expect(vi.mocked(removeSimpleCredential).mock.calls).toEqual([['X', 'u'], ['Y', 'v']]);
  });

  it('says when this browser kept a simple one', async () => {
    const { report } = flow({ removeSimple: false });
    await deleteSavedCredential(SIMPLE, report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.notRemovedLocally, 'error']);
    expect(report.reload).not.toHaveBeenCalled();
  });

  it('deletes an advanced one on the server first, then here', async () => {
    const { report } = flow();
    await deleteSavedCredential(ADVANCED, report);
    expect(deleteCredentialArtifact).toHaveBeenCalledWith(' s-1 ');
    expect(removeAdvancedCredential).toHaveBeenCalledWith('BAUG', ' s-1 ');
    expect(statusOf(report)).toEqual(['Deletion successful.', 'success']);
  });

  it('keeps an advanced one the server refused to delete, with the server\'s reason or a sentence', async () => {
    const refused = flow({ artifact: { status: 'failed', error: 'Delete request failed.' } });
    await deleteSavedCredential(ADVANCED, refused.report);
    expect(statusOf(refused.report)).toEqual(['Delete request failed.', 'error']);
    expect(removeAdvancedCredential).not.toHaveBeenCalled();

    const silent = flow({ artifact: { status: 'failed' } });
    await deleteSavedCredential(ADVANCED, silent.report);
    expect(statusOf(silent.report)).toEqual([DELETE_TEXT.serverRefused, 'error']);
  });

  it('says when the server deleted an advanced one but this browser kept it', async () => {
    const { report } = flow({ removeAdvanced: false });
    await deleteSavedCredential(ADVANCED, report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.removedFromServerOnly, 'error']);
  });

  it('warns when the server no longer had an advanced one', async () => {
    const { report } = flow({ artifact: { status: 'absent' } });
    await deleteSavedCredential({ ...ADVANCED, storageId: null, localStorageId: 'l-1' }, report);
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('l-1');
    expect(statusOf(report)).toEqual([DELETE_TEXT.alreadyAbsent, 'warning']);
  });

  it('removes an advanced one the server never held from this browser only', async () => {
    const removed = flow();
    await deleteSavedCredential({ type: 'advanced', id: 'CAkK' }, removed.report);
    expect(deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(removeAdvancedCredential).toHaveBeenCalledWith('CAkK', null);
    expect(statusOf(removed.report)).toEqual(['Deletion successful.', 'success']);

    const kept = flow({ removeAdvanced: false });
    await deleteSavedCredential({ type: 'advanced', id: 'CAkK' }, kept.report);
    expect(statusOf(kept.report)).toEqual([DELETE_TEXT.notRemovedLocally, 'error']);
  });

  it('does nothing while another deletion runs, or for no credential', async () => {
    const busy = flow({ running: true });
    await deleteSavedCredential(SIMPLE, busy.report);
    expect(busy.calls).toEqual([['running?'], ['status', DELETE_TEXT.inProgress, 'info']]);

    const none = flow();
    await deleteSavedCredential(undefined, none.report);
    expect(none.report.setRunning).not.toHaveBeenCalled();
  });
});

describe('clearing every credential', () => {
  it('clears the simple ones, deletes each advanced one, reads the list again and says so', async () => {
    const { calls, report } = flow();
    await clearSavedCredentials(report);
    expect(calls.map(([name]) => name)).toEqual([
      'running?', 'simple', 'advanced', 'busy', 'dismiss', 'progress', 'clear simple',
      'delete artifact', 'remove advanced', 'reload', 'status', 'progress', 'busy',
    ]);
    expect(report.progress).toHaveBeenCalledWith('Clearing all credentials...');
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('s-1');
    expect(removeAdvancedCredential).toHaveBeenCalledWith('BAUG', 's-1');
    expect(statusOf(report)).toEqual(['Deletion successful.', 'success']);
  });

  it('says there is nothing to clear', async () => {
    const { report } = flow({ simple: [], advanced: [] });
    await clearSavedCredentials(report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.nothingToClear, 'info']);
    expect(report.setRunning).not.toHaveBeenCalled();
  });

  it('does nothing while a deletion runs', async () => {
    const { report } = flow({ running: true });
    await clearSavedCredentials(report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.inProgress, 'info']);
    expect(clearSimpleCredentials).not.toHaveBeenCalled();
  });

  it('removes an advanced one the server never held from this browser only', async () => {
    const { report } = flow({
      simple: [],
      advanced: [{ id: 'CAkK', storageId: '  ' }, { credentialIdBase64Url: 'DAsM' }, null],
      removeAdvanced: (id) => id === 'CAkK',
    });
    await clearSavedCredentials(report);
    expect(deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(vi.mocked(removeAdvancedCredential).mock.calls).toEqual([['CAkK', null], ['DAsM', null], [undefined, null]]);
    expect(statusOf(report)).toEqual([
      'Clearing completed with issues: 2 credentials could not be deleted from server storage and were kept.',
      'error',
    ]);
  });

  it('counts one the server refused or this browser kept as kept', async () => {
    const refused = flow({ simple: [], artifact: { status: 'failed' } });
    await clearSavedCredentials(refused.report);
    expect(statusOf(refused.report)).toEqual([
      'Clearing completed with issues: 1 credential could not be deleted from server storage and was kept.',
      'error',
    ]);

    const kept = flow({ simple: [], removeAdvanced: false });
    await clearSavedCredentials(kept.report);
    expect(statusOf(kept.report)[1]).toBe('error');
  });

  it('warns of the ones the server no longer had', async () => {
    const one = flow({ artifact: { status: 'absent' } });
    await clearSavedCredentials(one.report);
    expect(statusOf(one.report)).toEqual(['Clearing complete. 1 credential was already absent from server storage.', 'warning']);

    const two = flow({
      advanced: [ADVANCED, { ...ADVANCED, credentialId: 'CAkK', storageId: 's-2' }],
      artifact: { status: 'absent' },
    });
    await clearSavedCredentials(two.report);
    expect(statusOf(two.report)).toEqual(['Clearing complete. 2 credentials were already absent from server storage.', 'warning']);
  });

  it('counts an answer that is neither deleted nor absent as kept', async () => {
    const { report } = flow({ simple: [], artifact: { status: 'unknown' } });
    await clearSavedCredentials(report);
    expect(statusOf(report)).toEqual([
      'Clearing completed with issues: 1 credential could not be deleted from server storage and was kept.',
      'error',
    ]);
  });

  it('says clearing failed when a step throws, and lets the list be used again', async () => {
    const { report } = flow({
      reload: async () => {
        throw new Error('storage gone');
      },
    });
    await clearSavedCredentials(report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.clearFailed, 'error']);
    expect(report.setRunning).toHaveBeenLastCalledWith(false);
  });
});
