import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  composeCredentialDetail,
  needsArtifact,
} from './compose.js';
import {
  REGISTRATION_TEXT,
  composeRegistration,
  describeAttestationCertificate,
  registrationSnapshotPayload,
} from '../registration/view.js';
import { createRegistrationState } from '../registration/state.js';
import { hydrateCredentialFromServer } from '../hydrate.js';
import {
  describeCoseAlgorithm,
  describeCoseKeyType,
  describeMldsaParameterSet,
} from '../cose-labels.js';
import { sanitiseRegistrationDetailSnapshot } from '../storage/local/snapshot-sanitize.js';
import {
  advancedArtifact,
  advancedRecord,
  recordedDecoder,
  simpleRecord,
} from '@/test/logic/credentials/registration-detail-answers.js';

// A saved credential's details, as data (credentials/detail/compose.js).

const AAGUID_GUID = '00112233-4455-6677-8899-aabbccddeeff';
const DESCRIBERS = { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet };

afterEach(() => {
  vi.restoreAllMocks();
});

async function detailOf(cred, decode = recordedDecoder()) {
  const state = createRegistrationState();
  const detail = await composeCredentialDetail(cred, { state, decode, describers: DESCRIBERS });
  return { state, decode, detail };
}

/** A record with the snapshot the app saves of its registration (schemaVersion 2, sanitised). */
async function withSavedSnapshot(record) {
  const { detail } = await detailOf(record);
  const snapshot = sanitiseRegistrationDetailSnapshot(registrationSnapshotPayload({
    stateSnapshot: detail.registration.stateSnapshot,
    credentialJson: record.registrationResponse,
    relyingPartyCopy: detail.registration.relyingPartyCopy,
  }, '2026-09-21T14:13:20.000Z'));
  return { ...record, registrationDetailSnapshot: snapshot };
}

describe('needsArtifact', () => {
  it('never asks for a Simple record\'s artifact', () => {
    expect(needsArtifact(simpleRecord('es256'))).toBe(false);
  });

  it('asks for an advanced record\'s artifact until its snapshot holds the registration as data', async () => {
    const record = advancedRecord();
    expect(needsArtifact(record)).toBe(true);
    expect(needsArtifact({ ...record, registrationDetailSnapshot: { schemaVersion: 1, state: {} } })).toBe(true);
    const saved = await withSavedSnapshot({ ...simpleRecord('es256'), type: 'advanced' });
    expect(needsArtifact(saved)).toBe(false);
  });
});

describe('composeCredentialDetail', () => {
  it('gives every section of a Simple registration\'s details, in order', async () => {
    const { detail } = await detailOf(simpleRecord('es256'));
    expect(Object.keys(detail)).toEqual([
      'properties',
      'userInfo',
      'aaguid',
      'attestationFormat',
      'authenticatorData',
      'extensions',
      'publicKey',
      'registration',
    ]);
    expect(detail.properties.checks.map(({ value }) => value)).toEqual([null, null, true, null]);
    expect(detail.userInfo.name).toBe('user@example.com');
    expect(detail.aaguid.values.find(({ label }) => label === 'guid').value).toBe(AAGUID_GUID);
    expect(detail.attestationFormat).toEqual({ title: 'Attestation Format', value: 'none' });
    expect(detail.authenticatorData).toBeNull();
    expect(detail.extensions).toBeNull();
    expect(detail.publicKey.lines[0]).toEqual({ label: 'Algorithm:', value: describeCoseAlgorithm(-7) });
  });

  it('decodes the registration once and shows the browser\'s response the record kept', async () => {
    const record = simpleRecord('es256');
    const { decode, detail, state } = await detailOf(record);
    expect(decode).toHaveBeenCalledTimes(1);
    expect(decode).toHaveBeenCalledWith(record.attestationObject);
    const credential = JSON.parse(detail.registration.response.credential);
    expect(credential.id).toBe(record.registrationResponse.id);
    expect(credential.response.authenticatorData).toBe(record.authenticatorData);
    expect(JSON.parse(detail.registration.response.clientData)).toMatchObject({ type: 'webauthn.create' });
    expect(detail.registration.attestation.hasAuthenticatorData).toBe(true);
    expect(state.authenticatorData.base64url).toBe(record.authenticatorData);
    expect(state.authenticatorData.raw).toBe(record.authenticatorDataHex);
  });

  it('lists a packed registration\'s certificate and shows its extension outputs', async () => {
    const record = simpleRecord('packedX5c');
    const { detail, state } = await detailOf(record);
    expect(detail.attestationFormat.value).toBe('packed');
    expect(detail.extensions.text).toBe(JSON.stringify(record.clientExtensionOutputs, null, 2));
    expect(detail.properties.checks.map(({ value }) => value)).toEqual([true, null, true, true]);
    expect(detail.registration.attestation.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(describeAttestationCertificate(state, 0).text).toContain('Issuer: CN=Characterization Test CA');
  });

  it('gives an ML-DSA key\'s parameter set', async () => {
    const { detail } = await detailOf(simpleRecord('mldsa65'));
    expect(detail.publicKey.lines.at(-1)).toEqual({ label: 'ML-DSA parameter set:', value: 'ML-DSA-65' });
  });

  it('empties the state it is given before composing', async () => {
    const state = createRegistrationState();
    state.attestationCertificates = [{ parsedX5c: { summary: 'left over' } }];
    state.visibleAttestationCertificateIndices = [0];
    await composeCredentialDetail(simpleRecord('es256'), { state, decode: recordedDecoder(), describers: DESCRIBERS });
    expect(state.attestationCertificates).toEqual([]);
  });

  it('shows a saved snapshot as it is, without asking the decoder', async () => {
    const saved = await withSavedSnapshot(simpleRecord('packedX5c'));
    const { decode, detail, state } = await detailOf(saved, vi.fn());
    expect(decode).not.toHaveBeenCalled();
    expect(JSON.parse(detail.registration.response.credential)).toEqual(saved.registrationResponse);
    expect(JSON.parse(detail.registration.response.relyingParty)).toEqual(saved.registrationDetailSnapshot.response.relyingParty);
    expect(detail.registration.attestation.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(describeAttestationCertificate(state, 0).text).toContain('Issuer: CN=Characterization Test CA');
  });

  it('takes the credential or the relying party from the record when the snapshot holds only the other', async () => {
    const saved = await withSavedSnapshot(simpleRecord('es256'));
    const relyingPartyOnly = structuredClone(saved);
    delete relyingPartyOnly.registrationDetailSnapshot.response.credential;
    const credentialOnly = structuredClone(saved);
    delete credentialOnly.registrationDetailSnapshot.response.relyingParty;

    const fromRecord = (await detailOf(relyingPartyOnly, vi.fn())).detail.registration.response;
    expect(JSON.parse(fromRecord.credential).response.authenticatorData).toBe(saved.authenticatorData);

    const relyingParty = JSON.parse((await detailOf(credentialOnly, vi.fn())).detail.registration.response.relyingParty);
    expect(relyingParty.aaguid).toEqual(saved.relyingParty.aaguid);
  });

  it('decodes again a record whose snapshot does not hold the registration as data', async () => {
    const record = { ...simpleRecord('es256'), registrationDetailSnapshot: { schemaVersion: 1, state: {} } };
    const { decode, detail } = await detailOf(record);
    expect(decode).toHaveBeenCalledWith(record.attestationObject);
    expect(detail.registration.attestation.body.kind).toBe('json');
  });

  it('completes an advanced record from its artifact, then lists the relying party\'s certificate', async () => {
    const record = advancedRecord();
    const { storedCredential } = advancedArtifact();
    await hydrateCredentialFromServer(record, {
      fetchCredentialArtifact: async () => advancedArtifact(),
      saveSnapshot: vi.fn(),
    });

    const { decode, detail } = await detailOf(record);
    expect(decode).toHaveBeenCalledWith(storedCredential.attestationObject);
    expect(detail.attestationFormat.value).toBe('packed');
    expect(detail.properties).toMatchObject({ discoverable: false, largeBlob: true, minPinLength: 6 });
    expect(detail.registration.attestation.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(JSON.parse(detail.registration.response.credential).id).toBe(storedCredential.registrationResponse.id);
  });

  it('names the attestation format from the first place that has one, else none', async () => {
    const bare = { credentialId: 'AQID' };
    const formats = await Promise.all([
      { ...bare, attestationFormat: 'packed' },
      { ...bare, attestationFmt: 'tpm' },
      { ...bare, relyingParty: { attestationFmt: 'apple' } },
      { ...bare, attestationObjectDecoded: { fmt: 'android-key' } },
      { ...bare, attestationObjectDecoded: { fmt: 7 } },
      bare,
    ].map(async (cred) => (await detailOf(cred)).detail.attestationFormat.value));
    expect(formats).toEqual(['packed', 'tpm', 'apple', 'android-key', 'none', 'none']);
  });

  it('says why when the decoder refuses the registration\'s attestation object', async () => {
    const { detail } = await detailOf({ attestationObject: 'o2NmbXRk' });
    expect(detail.registration.attestation.body).toEqual({ kind: 'error', text: 'The payload is not valid CBOR.' });
    expect(detail.registration.attestation.certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('gives the same registration view composeRegistration gives for the record\'s values', async () => {
    const record = simpleRecord('eddsa');
    const { detail } = await detailOf(record);
    const direct = await composeRegistration({
      credentialJson: detail.registration.response.credential ? JSON.parse(detail.registration.response.credential) : null,
      relyingPartyInfo: record.relyingParty,
      attestationObjectValue: record.attestationObject,
      authenticatorDataValue: record.authenticatorData,
      authenticatorDataHex: record.authenticatorDataHex,
      fallbackClientData: record.clientDataJSON,
    }, { state: createRegistrationState(), decode: recordedDecoder() });
    expect(detail.registration).toEqual(direct);
  });
});
