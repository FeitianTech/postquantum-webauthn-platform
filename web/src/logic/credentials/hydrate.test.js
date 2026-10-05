import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  HYDRATE_TEXT,
  hydrateCredentialFromServer,
} from './hydrate.js';
import { needsArtifact } from './detail/compose.js';
import { composeRegistration, registrationSnapshotPayload } from './registration/view.js';
import { createRegistrationState } from './registration/state.js';
import { fetchCredentialArtifact } from './storage/artifacts-client.js';
import { updateAdvancedCredentialRegistrationSnapshot } from './storage/local/advanced-snapshot-update.js';
import { sanitiseRegistrationDetailSnapshot } from './storage/local/snapshot-sanitize.js';
import { advancedArtifact, advancedRecord, recordedDecoder, simpleRecord } from '@/test/logic/credentials/registration-detail-answers.js';

// A saved advanced credential completed from its server artifact (credentials/hydrate.js).

// The artifact the server answers, and the record this browser keeps the snapshot in.
vi.mock('./storage/artifacts-client.js', () => ({ fetchCredentialArtifact: vi.fn() }));
vi.mock('./storage/local/advanced-snapshot-update.js', () => ({ updateAdvancedCredentialRegistrationSnapshot: vi.fn() }));

afterEach(() => {
  vi.restoreAllMocks();
});

/** The artifact the server answers, whether the snapshot is kept, and what is told once it is. */
function steps(artifact = advancedArtifact(), kept = true) {
  vi.mocked(fetchCredentialArtifact).mockImplementation(async () => artifact);
  vi.mocked(updateAdvancedCredentialRegistrationSnapshot).mockImplementation(async () => kept);
  return {
    fetchCredentialArtifact,
    saveSnapshot: updateAdvancedCredentialRegistrationSnapshot,
    onSaved: vi.fn(),
  };
}

/** A registration's snapshot as the view saves one (schemaVersion 2), before the sanitiser. */
async function registrationSnapshot() {
  const record = simpleRecord('es256');
  const composed = await composeRegistration({
    credentialJson: record.registrationResponse,
    relyingPartyInfo: record.relyingParty,
    attestationObjectValue: record.attestationObject,
  }, { state: createRegistrationState(), decode: recordedDecoder() });
  return registrationSnapshotPayload({
    stateSnapshot: composed.stateSnapshot,
    credentialJson: record.registrationResponse,
    relyingPartyCopy: composed.relyingPartyCopy,
  }, '2026-09-21T14:13:20.000Z');
}

describe('hydrateCredentialFromServer', () => {
  it('completes an advanced record with its artifact\'s fields and gives the artifact\'s record', async () => {
    const record = advancedRecord();
    const { storageId } = record;
    const artifact = advancedArtifact();
    const given = steps();

    const stored = await hydrateCredentialFromServer(record, given.onSaved);

    expect(given.fetchCredentialArtifact).toHaveBeenCalledWith(storageId);
    expect(stored).toEqual(artifact.storedCredential);
    expect(record.attestationObject).toBe(artifact.storedCredential.attestationObject);
    expect(record.registrationResponse).toEqual(artifact.storedCredential.registrationResponse);
    expect(record.storageId).toBe(storageId);
    expect(record.__artifactHydrated).toBe(storageId);
    expect(given.saveSnapshot).not.toHaveBeenCalled();
  });

  it('asks for the artifact once per storage id', async () => {
    const record = advancedRecord();
    const given = steps();
    await hydrateCredentialFromServer(record, given.onSaved);
    await expect(hydrateCredentialFromServer(record, given.onSaved)).resolves.toBe(record);
    expect(given.fetchCredentialArtifact).toHaveBeenCalledTimes(1);
  });

  it('finds the storage id under the record\'s local name', async () => {
    const record = advancedRecord();
    const localStorageId = record.storageId;
    delete record.storageId;
    const given = steps();
    await hydrateCredentialFromServer(record, given.onSaved);
    expect(given.fetchCredentialArtifact).toHaveBeenCalledWith(localStorageId);
    expect(record.__artifactHydrated).toBe(localStorageId);
  });

  it('marks a record without a storage id as missing its artifact, and asks for nothing', async () => {
    const given = steps();
    const records = [{}, { storageId: '   ' }, { storageId: 42 }];
    for (const record of records) {
      await expect(hydrateCredentialFromServer(record, given.onSaved)).resolves.toBeNull();
      expect(record.__artifactHydrated).toBe('missing');
    }
    expect(given.fetchCredentialArtifact).not.toHaveBeenCalled();
  });

  it('does nothing for something that is not a record', async () => {
    const given = steps();
    await expect(hydrateCredentialFromServer(null, given.onSaved)).resolves.toBeNull();
    await expect(hydrateCredentialFromServer('record', given.onSaved)).resolves.toBeNull();
    expect(given.fetchCredentialArtifact).not.toHaveBeenCalled();
  });

  it('marks the record as missing its artifact when the server has none', async () => {
    for (const answer of [null, 'not an artifact']) {
      const record = advancedRecord();
      await expect(hydrateCredentialFromServer(record, steps(answer).onSaved)).resolves.toBeNull();
      expect(record.__artifactHydrated).toBe('missing');
      expect(record).not.toHaveProperty('attestationObject');
    }
  });

  it('reads an artifact that is the record itself', async () => {
    const { storedCredential } = advancedArtifact();
    const record = advancedRecord();
    await expect(hydrateCredentialFromServer(record, steps(storedCredential).onSaved)).resolves.toEqual(storedCredential);
    expect(record.attestationObject).toBe(storedCredential.attestationObject);
  });

  it('reads an artifact saved before base64url the way saved records are read', async () => {
    const { storedCredential } = advancedArtifact();
    const bytes = Uint8Array.from(Buffer.from(storedCredential.credentialId, 'base64url'));
    const oldArtifact = { storedCredential: { ...storedCredential, credentialId: Buffer.from(bytes).toString('base64') } };
    expect(oldArtifact.storedCredential.credentialId).toMatch(/[+/=]/);

    const record = advancedRecord();
    const stored = await hydrateCredentialFromServer(record, steps(oldArtifact).onSaved);
    expect(stored.credentialId).toBe(storedCredential.credentialId);
    expect(record.credentialId).toBe(storedCredential.credentialId);
  });

  it('keeps the artifact\'s snapshot as far as the sanitiser allows, and saves it', async () => {
    const snapshot = { ...(await registrationSnapshot()), html: '<p>markup</p>' };
    const record = advancedRecord();
    const given = steps({ ...advancedArtifact(), registrationDetailSnapshot: snapshot });

    await hydrateCredentialFromServer(record, given.onSaved);

    const kept = sanitiseRegistrationDetailSnapshot(snapshot);
    expect(record.registrationDetailSnapshot).toEqual(kept);
    expect(record.registrationDetailSnapshot).not.toHaveProperty('html');
    expect(given.saveSnapshot).toHaveBeenCalledWith(record.storageId, kept);
    expect(needsArtifact(record)).toBe(false);
    await vi.waitFor(() => expect(given.onSaved).toHaveBeenCalledTimes(1));
  });

  it('tells nothing when the snapshot could not be kept', async () => {
    const snapshot = await registrationSnapshot();
    const given = steps({ ...advancedArtifact(), registrationDetailSnapshot: snapshot }, false);
    await hydrateCredentialFromServer(advancedRecord(), given.onSaved);
    await vi.waitFor(() => expect(given.saveSnapshot).toHaveBeenCalledTimes(1));
    await Promise.resolve();
    expect(given.onSaved).not.toHaveBeenCalled();
  });

  it('takes the snapshot the artifact\'s record keeps, and copies only its sanitised form', async () => {
    const snapshot = await registrationSnapshot();
    const artifact = advancedArtifact();
    artifact.storedCredential.registrationDetailSnapshot = snapshot;
    const record = advancedRecord();
    const given = steps(artifact);

    await hydrateCredentialFromServer(record, given.onSaved);

    expect(record.registrationDetailSnapshot).toEqual(sanitiseRegistrationDetailSnapshot(snapshot));
    expect(given.saveSnapshot).toHaveBeenCalledTimes(1);
  });

  it('keeps no snapshot that holds nothing once sanitised', async () => {
    const record = advancedRecord();
    const given = steps({ ...advancedArtifact(), registrationDetailSnapshot: { schemaVersion: 1, html: '<p>markup</p>' } });
    await hydrateCredentialFromServer(record, given.onSaved);
    expect(record).not.toHaveProperty('registrationDetailSnapshot');
    expect(given.saveSnapshot).not.toHaveBeenCalled();
    expect(record.__artifactHydrated).toBe(record.storageId);
  });

  it('marks the record when the artifact cannot be fetched, and changes nothing else', async () => {
    const failure = new Error('Request failed with status 500');
    const record = advancedRecord();
    const before = structuredClone(record);

    vi.mocked(fetchCredentialArtifact).mockImplementation(async () => {
      throw failure;
    });
    const stored = await hydrateCredentialFromServer(record, vi.fn());

    expect(stored).toBeNull();
    expect(record).toEqual({ ...before, __artifactHydrated: 'error' });
  });
});
