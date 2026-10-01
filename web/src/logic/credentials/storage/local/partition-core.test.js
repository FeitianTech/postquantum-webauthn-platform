import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it } from 'vitest';

import {
  partitionRecords,
  persistCredentialPartitions,
} from './partition-core.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import { repoFile } from '@/test/logic/repo-file.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

// The storedCredential register-complete answers (characterization goldens).
function registered(scenario) {
  const path = `tests/app/characterization/golden/routes/${scenario}.json`;
  return JSON.parse(readFileSync(repoFile(path), 'utf8')).requests[1].body.storedCredential;
}

const SIMPLE = registered('simple-register-es256');
const ADVANCED = registered('advanced-register-none-es256');

function store(records) {
  window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
}

function stored() {
  return JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
}

describe('credential partitions', () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords(null);
  });

  it('find no records in something that is not a list', () => {
    expect(partitionRecords(null)).toEqual({ simple: [], advanced: [] });
  });

  it('leave out entries that are not records', () => {
    const { simple, advanced } = partitionRecords([null, 'record', SIMPLE, ADVANCED]);

    expect(simple.map(record => record.credentialId)).toEqual([SIMPLE.credentialId]);
    expect(advanced.map(record => record.credentialId)).toEqual([ADVANCED.credentialId]);
  });

  it('drop the stored simple records when no simple list is given', () => {
    store([SIMPLE, ADVANCED]);

    expect(persistCredentialPartitions(undefined, [ADVANCED])).toBe(true);

    expect(stored().map(record => record.type)).toEqual(['advanced']);
  });

  it('drop the stored advanced records when no advanced list is given', () => {
    store([SIMPLE, ADVANCED]);

    expect(persistCredentialPartitions([SIMPLE], null)).toBe(true);

    expect(stored().map(record => record.type)).toEqual(['simple']);
  });

  it('store advanced records whole, typed advanced, when no preparer is given', () => {
    const { type, ...untyped } = ADVANCED;
    const record = { ...untyped, attestationObject: 'o2NmbXRkbm9uZQ' };

    persistCredentialPartitions([], [record]);

    expect(stored()).toEqual([{ ...record, type: 'advanced' }]);
  });

  it('leave out what the advanced preparer gives back when it is not a record', () => {
    const prepareAdvancedCredentialForStorage = () => 'not a record';

    persistCredentialPartitions([], [ADVANCED], { prepareAdvancedCredentialForStorage });

    expect(stored()).toEqual([]);
  });
});
