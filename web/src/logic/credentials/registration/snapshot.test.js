// What a registration's result keeps (credentials/registration/snapshot.js), over the recorded advanced registrations and the decoder's answers.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { updateAdvancedCredentialRegistrationSnapshot } from '../storage/local/advanced-snapshot-update.js';
import { decodePayloadThroughApi } from './decode-payload.js';
import { keepRegistrationSnapshot } from './snapshot.js';
import { createRegistrationState } from './state.js';
import { composeRegistration, registrationResultInput } from './view.js';
import { credentialToJSON } from '@/test/logic/simple/ceremony-answers.js';
import { advancedDecodeAnswer, advancedRegistrations, recordedCredential } from '@/test/logic/advanced/advanced-answers.js';

// The server's decoder (POST /api/codec), and the record the snapshot is saved into.
vi.mock('./decode-payload.js', () => ({ decodePayloadThroughApi: vi.fn() }));
vi.mock('../storage/local/advanced-snapshot-update.js', () => ({ updateAdvancedCredentialRegistrationSnapshot: vi.fn() }));

// The three recorded registrations: a none attestation (ES256), a packed one
// with a certificate and every extension, and an ML-DSA-44 one.
const REGISTRATIONS = advancedRegistrations();
const [, EVERYTHING] = REGISTRATIONS;
const CAPTURED_AT = '2026-09-21T14:13:20.000Z';

/** The decoder's recorded answer, else its refusal thrown. */
async function recordedDecode(payload) {
  const { status, body } = advancedDecodeAnswer(payload);
  if (status !== 200) {
    throw new Error(body.error);
  }
  return body;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(CAPTURED_AT));
  vi.mocked(decodePayloadThroughApi).mockImplementation(recordedDecode);
  vi.mocked(updateAdvancedCredentialRegistrationSnapshot).mockImplementation(async () => true);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** The credential's JSON as the browser writes it for a recorded registration's credential. */
function credentialJsonOf(registration) {
  return credentialToJSON(recordedCredential(registration));
}

/** What the result is given for a recorded registration: the credential's JSON, the relying party's view, the saved record's storage ID. */
async function resultOf(registration, storageId = registration.complete.body.storedCredential.storageId) {
  return {
    credentialJson: credentialJsonOf(registration),
    relyingPartyInfo: registration.complete.body.relyingParty,
    storageId,
  };
}

/** The snapshot saved, as the record's storage was given it. */
function savedPayload() {
  return vi.mocked(updateAdvancedCredentialRegistrationSnapshot).mock.calls[0][1];
}

describe('keepRegistrationSnapshot', () => {
  it('composes the registration from the credential, the relying party and what the result reads from them', async () => {
    const input = await resultOf(EVERYTHING);
    const kept = await keepRegistrationSnapshot(input);

    const relyingParty = EVERYTHING.complete.body.relyingParty;
    expect(registrationResultInput(input.credentialJson, relyingParty)).toEqual({
      attestationObjectValue: relyingParty.attestationObject,
      authenticatorDataValue: '',
      fallbackCertificates: [relyingParty.attestationCertificate, ...relyingParty.attestationCertificates],
    });
    expect(decodePayloadThroughApi).toHaveBeenCalledTimes(1);
    expect(decodePayloadThroughApi).toHaveBeenCalledWith(relyingParty.attestationObject);
    expect(kept.composed).toEqual(await composeRegistration({
      credentialJson: input.credentialJson,
      relyingPartyInfo: relyingParty,
      ...registrationResultInput(input.credentialJson, relyingParty),
    }, { state: createRegistrationState(), decode: recordedDecode }));
  });

  it('saves a saved record\'s snapshot: the registration as data, captured now', async () => {
    const input = await resultOf(EVERYTHING);
    const kept = await keepRegistrationSnapshot(input);

    expect(updateAdvancedCredentialRegistrationSnapshot).toHaveBeenCalledTimes(1);
    expect(updateAdvancedCredentialRegistrationSnapshot).toHaveBeenCalledWith(EVERYTHING.complete.body.storedCredential.storageId, {
      schemaVersion: 2,
      capturedAt: CAPTURED_AT,
      state: kept.composed.stateSnapshot,
      response: { credential: input.credentialJson, relyingParty: kept.composed.relyingPartyCopy },
    });
    expect(kept.saved).toBe(true);
  });

  it('keeps the decoded attestation object, its certificates and the relying party\'s view in the snapshot', async () => {
    const input = await resultOf(EVERYTHING);
    await keepRegistrationSnapshot(input);

    const payload = savedPayload();
    const relyingParty = EVERYTHING.complete.body.relyingParty;
    expect(payload.state.attestationObject.fmt).toBe('packed');
    expect(payload.state.attestationCertificates.map(({ parsedX5c }) => parsedX5c.derBase64)).toEqual([
      relyingParty.attestationCertificate.derBase64,
    ]);
    expect(payload.state.detailPreparation).toEqual({
      attestationObjectValue: relyingParty.attestationObject,
      attestationDecodeError: '',
      authenticatorDataValue: '',
      authenticatorDecodeError: '',
    });
    expect(payload.response.relyingParty.aaguid).toEqual(relyingParty.aaguid);
  });

  it('keeps each recorded registration\'s attestation format as the decoder read it', async () => {
    const formats = [];
    for (const registration of REGISTRATIONS) {
      vi.mocked(updateAdvancedCredentialRegistrationSnapshot).mockClear();
      await keepRegistrationSnapshot(await resultOf(registration));
      formats.push(savedPayload().state.attestationObject.fmt);
    }
    expect(formats).toEqual(REGISTRATIONS.map(({ complete }) => complete.body.attestationFormat));
    expect(formats).toEqual(['none', 'packed', 'packed']);
  });

  it('keeps the decoder\'s refusal when the attestation object does not decode', async () => {
    const input = await resultOf(EVERYTHING);
    input.credentialJson.response.attestationObject = 'oA';
    await keepRegistrationSnapshot(input);

    const payload = savedPayload();
    expect(payload.state.detailPreparation.attestationDecodeError).toBe('The payload is not valid CBOR.');
    expect(payload.state.attestationObject).toBeNull();
  });

  it('says the snapshot changed nothing when saving it changed nothing', async () => {
    const input = await resultOf(EVERYTHING);
    vi.mocked(updateAdvancedCredentialRegistrationSnapshot).mockImplementation(async () => false);
    const unchanged = await keepRegistrationSnapshot(input);

    expect(unchanged.saved).toBe(false);
  });

  it('saves nothing for a registration the browser did not save, and still gives the composition', async () => {
    const { storageId, ...unsaved } = await resultOf(EVERYTHING);
    const kept = await keepRegistrationSnapshot(unsaved);
    const keptNull = await keepRegistrationSnapshot({ ...unsaved, storageId: null });

    expect(updateAdvancedCredentialRegistrationSnapshot).not.toHaveBeenCalled();
    expect(kept.saved).toBe(false);
    expect(keptNull.saved).toBe(false);
    expect(kept.composed.attestation.body.kind).toBe('json');
  });

  it('captures the snapshot at the present time', async () => {
    const input = await resultOf(EVERYTHING);
    vi.setSystemTime(new Date('2026-09-28T08:30:00Z'));
    await keepRegistrationSnapshot(input);

    expect(savedPayload().capturedAt).toBe('2026-09-28T08:30:00.000Z');
  });
});
