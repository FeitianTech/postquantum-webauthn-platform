import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CLEAR_ALL_CONFIRMATION,
  DELETE_TEXT,
  clearAllConfirmation,
  clearSavedCredentials,
  deleteConfirmation,
  deleteSavedCredential,
} from './delete-flow.js';
import { SIGNAL_TEXT, signalDeletedCredential } from './deletion-signal.js';
import { deleteCredentialArtifact } from './storage/artifacts-client.js';
import { getAllAdvancedCredentials, removeAdvancedCredential } from './storage/local/advanced-credentials.js';
import { getAllSimpleCredentials, removeSimpleCredential } from './storage/local/simple-credentials.js';
import { deleteSimpleCredentialRecord } from './storage/simple-records-client.js';

// Deleting a saved credential and clearing them all (credentials/delete-flow.js):
// in what order, and what each outcome says. The storage and the server answer
// as each test says.

vi.mock('./storage/artifacts-client.js', () => ({ deleteCredentialArtifact: vi.fn() }));
vi.mock('./deletion-signal.js', async (importOriginal) => ({ ...(await importOriginal()), signalDeletedCredential: vi.fn() }));
vi.mock('./storage/simple-records-client.js', () => ({ deleteSimpleCredentialRecord: vi.fn() }));
vi.mock('./storage/local/advanced-credentials.js', () => ({
  getAllAdvancedCredentials: vi.fn(),
  removeAdvancedCredential: vi.fn(),
}));
vi.mock('./storage/local/simple-credentials.js', async (importOriginal) => ({
  ...(await importOriginal()),
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
  record: simpleRecord = { status: 'deleted' },
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
  vi.mocked(deleteCredentialArtifact).mockImplementation(record('delete artifact', async () => artifact));
  vi.mocked(deleteSimpleCredentialRecord).mockImplementation(record('delete record', async () => simpleRecord));
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

  it('says the browser will be told, where it can be', () => {
    const signals = { PublicKeyCredential: { signalUnknownCredential: () => {} } };
    expect(deleteConfirmation({ userName: 'alice' }, signals)).toBe(
      `Are you sure you want to delete the credential for alice? This action cannot be undone. ${SIGNAL_TEXT.one}`,
    );
    expect(clearAllConfirmation(signals)).toBe(`${CLEAR_ALL_CONFIRMATION} ${SIGNAL_TEXT.all}`);
    expect(deleteConfirmation({ userName: 'alice' }, {})).not.toContain(SIGNAL_TEXT.one);
    expect(clearAllConfirmation({})).toBe(CLEAR_ALL_CONFIRMATION);
    expect(clearAllConfirmation()).toBe(CLEAR_ALL_CONFIRMATION);
  });
});

describe('telling the browser a deleted credential is gone', () => {
  const PAGE = { location: { hostname: 'localhost' } };
  const told = () => vi.mocked(signalDeletedCredential).mock.calls;

  it('tells it once one is gone, with the page\'s global, and not one the server or this browser kept', async () => {
    await deleteSavedCredential(SIMPLE, flow().report, PAGE);
    await deleteSavedCredential(ADVANCED, flow({ artifact: { status: 'absent' } }).report, PAGE);
    expect(told()).toEqual([[SIMPLE, PAGE], [ADVANCED, PAGE]]);

    vi.mocked(signalDeletedCredential).mockClear();
    await deleteSavedCredential(SIMPLE, flow({ record: { status: 'failed' } }).report, PAGE);
    await deleteSavedCredential(ADVANCED, flow({ removeAdvanced: false }).report, PAGE);
    await deleteSavedCredential({ type: 'simple', credentialId: 'EEEE' }, flow({ removeSimple: false }).report, PAGE);
    expect(told()).toEqual([]);
  });

  it('tells it each one Clear All removed, and none it reports as kept', async () => {
    const kept = { ...ADVANCED, storageId: 's-2' };
    const { report } = flow({ advanced: [ADVANCED, kept] });
    vi.mocked(deleteCredentialArtifact).mockImplementation(async (id) => ({ status: id === 's-2' ? 'unknown' : 'absent' }));
    await clearSavedCredentials(report, PAGE);
    expect(told()).toEqual([[SIMPLE, PAGE], [ADVANCED, PAGE]]);
  });

  it('tells it through the page\'s own global by default', async () => {
    await deleteSavedCredential(SIMPLE, flow().report);
    await clearSavedCredentials(flow({ simple: [] }).report);
    expect(told()).toEqual([[SIMPLE, globalThis], [ADVANCED, globalThis]]);
  });
});

describe('deleting one credential', () => {
  it('deletes a simple one on the server first, then here, reads the list again and says so', async () => {
    const { calls, report } = flow();
    await deleteSavedCredential(SIMPLE, report);
    expect(calls).toEqual([
      ['running?'],
      ['busy', true],
      ['dismiss'],
      ['progress', 'Deleting credential...'],
      ['delete record', 'AQID', 'alice'],
      ['remove simple', 'AQID', 'alice'],
      ['reload'],
      ['status', 'Deletion successful.', 'success'],
      ['progress', null],
      ['busy', false],
    ]);
  });

  it('deletes a simple one by its credential id or id, for its account', async () => {
    const { report } = flow();
    await deleteSavedCredential({ type: 'simple', credentialId: 'X', userName: 'u' }, report);
    await deleteSavedCredential({ type: 'simple', id: 'Y', username: 'v' }, report);
    expect(vi.mocked(deleteSimpleCredentialRecord).mock.calls).toEqual([['X', 'u'], ['Y', 'v']]);
    expect(vi.mocked(removeSimpleCredential).mock.calls).toEqual([['X', 'u'], ['Y', 'v']]);
  });

  it('keeps a simple one the server refused to delete, with the server\'s reason or a sentence', async () => {
    const refused = flow({ record: { status: 'failed', error: 'The stored credentials could not be read. Please try again.' } });
    await deleteSavedCredential(SIMPLE, refused.report);
    expect(statusOf(refused.report)).toEqual(['The stored credentials could not be read. Please try again.', 'error']);
    expect(removeSimpleCredential).not.toHaveBeenCalled();

    const silent = flow({ record: { status: 'failed' } });
    await deleteSavedCredential(SIMPLE, silent.report);
    expect(statusOf(silent.report)).toEqual([DELETE_TEXT.serverRefused, 'error']);
  });

  it('warns when the server no longer had a simple one, and removes it here', async () => {
    const { report } = flow({ record: { status: 'absent' } });
    await deleteSavedCredential(SIMPLE, report);
    expect(removeSimpleCredential).toHaveBeenCalledWith('AQID', 'alice');
    expect(statusOf(report)).toEqual([DELETE_TEXT.alreadyAbsent, 'warning']);
  });

  it('says when the server deleted a simple one but this browser kept it', async () => {
    const { report } = flow({ removeSimple: false });
    await deleteSavedCredential(SIMPLE, report);
    expect(statusOf(report)).toEqual([DELETE_TEXT.removedFromServerOnly, 'error']);
    expect(report.reload).not.toHaveBeenCalled();
  });

  it('removes a simple one that names no account or no id from this browser only', async () => {
    const removed = flow();
    await deleteSavedCredential({ type: 'simple', credentialId: 'X', email: '  ' }, removed.report);
    await deleteSavedCredential({ type: 'simple', email: 'alice' }, removed.report);
    expect(deleteSimpleCredentialRecord).not.toHaveBeenCalled();
    expect(vi.mocked(removeSimpleCredential).mock.calls).toEqual([['X', '  '], [undefined, 'alice']]);
    expect(statusOf(removed.report)).toEqual(['Deletion successful.', 'success']);

    const kept = flow({ removeSimple: false });
    await deleteSavedCredential({ type: 'simple', credentialId: 'X' }, kept.report);
    expect(statusOf(kept.report)).toEqual([DELETE_TEXT.notRemovedLocally, 'error']);
  });

  it('deletes an advanced one on the server first, then here', async () => {
    const { report } = flow();
    await deleteSavedCredential(ADVANCED, report);
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('s-1');
    expect(removeAdvancedCredential).toHaveBeenCalledWith('BAUG', 's-1');
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
    await deleteSavedCredential({ type: 'advanced', id: 'DAsM', storageId: '  ' }, removed.report);
    expect(deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(vi.mocked(removeAdvancedCredential).mock.calls).toEqual([['CAkK', null], ['DAsM', null]]);
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
  it('deletes each one on the server first, then here, reads the list again and says so', async () => {
    const { calls, report } = flow();
    await clearSavedCredentials(report);
    expect(calls.slice(0, 6).map(([name]) => name)).toEqual(['running?', 'simple', 'advanced', 'busy', 'dismiss', 'progress']);
    expect(calls.slice(-4).map(([name]) => name)).toEqual(['reload', 'status', 'progress', 'busy']);
    expect(report.progress).toHaveBeenCalledWith('Clearing all credentials...');
    expect(deleteSimpleCredentialRecord).toHaveBeenCalledWith('AQID', 'alice');
    expect(removeSimpleCredential).toHaveBeenCalledWith('AQID', 'alice');
    expect(deleteCredentialArtifact).toHaveBeenCalledWith('s-1');
    expect(removeAdvancedCredential).toHaveBeenCalledWith('BAUG', 's-1');
    expect(statusOf(report)).toEqual(['Deletion successful.', 'success']);
  });

  it('deletes one username\'s simple ones one at a time, and other usernames\' meanwhile', async () => {
    const held = [];
    const { calls, report } = flow({
      simple: [SIMPLE, { ...SIMPLE, credentialIdBase64Url: 'BBBB' }, { ...SIMPLE, credentialIdBase64Url: 'CCCC', email: 'Alice' }],
      advanced: [],
    });
    vi.mocked(deleteSimpleCredentialRecord).mockImplementation((id, username) => {
      calls.push(['delete record', id, username]);
      return new Promise(resolve => held.push(() => resolve({ status: 'deleted' })));
    });

    const clearing = clearSavedCredentials(report);
    await vi.waitFor(() => expect(held).toHaveLength(2));
    // alice's first and Alice's: another account, another list on the server.
    expect(calls.filter(([name]) => name === 'delete record')).toEqual([
      ['delete record', 'AQID', 'alice'],
      ['delete record', 'CCCC', 'Alice'],
    ]);
    held.shift()();
    await vi.waitFor(() => expect(held).toHaveLength(2));
    expect(calls.filter(([name]) => name === 'delete record').at(-1)).toEqual(['delete record', 'BBBB', 'alice']);
    held.forEach(release => release());
    await clearing;
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
    expect(deleteSimpleCredentialRecord).not.toHaveBeenCalled();
  });

  it('removes one the server never held from this browser only', async () => {
    const { report } = flow({
      simple: [{ type: 'simple', credentialId: 'EEEE' }],
      advanced: [{ id: 'CAkK', storageId: '  ' }, { credentialIdBase64Url: 'DAsM' }, null],
      removeAdvanced: (id) => id === 'CAkK',
    });
    await clearSavedCredentials(report);
    expect(deleteCredentialArtifact).not.toHaveBeenCalled();
    expect(deleteSimpleCredentialRecord).not.toHaveBeenCalled();
    expect(vi.mocked(removeSimpleCredential).mock.calls).toEqual([['EEEE', undefined]]);
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

    const simpleRefused = flow({ advanced: [], record: { status: 'failed', error: 'Unable to delete credential from server storage.' } });
    await clearSavedCredentials(simpleRefused.report);
    expect(statusOf(simpleRefused.report)[1]).toBe('error');
    expect(removeSimpleCredential).not.toHaveBeenCalled();

    const kept = flow({ simple: [], removeAdvanced: false });
    await clearSavedCredentials(kept.report);
    expect(statusOf(kept.report)[1]).toBe('error');
  });

  it('warns of the ones the server no longer had', async () => {
    const one = flow({ artifact: { status: 'absent' } });
    await clearSavedCredentials(one.report);
    expect(statusOf(one.report)).toEqual(['Clearing complete. 1 credential was already absent from server storage.', 'warning']);

    const two = flow({ record: { status: 'absent' }, artifact: { status: 'absent' } });
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
