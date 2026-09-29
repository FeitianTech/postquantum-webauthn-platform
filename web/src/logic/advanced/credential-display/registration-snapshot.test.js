// What a registration's result keeps (advanced/credential-display/registration-snapshot.js), over the recorded advanced registrations and the decoder's answers.
import { afterEach, describe, expect, it, vi } from 'vitest';

import { keepRegistrationSnapshot } from './registration-snapshot.js';
import { createRegistrationState } from './registration-state.js';
import { composeRegistration } from './registration-view.js';
import { create } from '../../shared/webauthn/json-ponyfill.js';
import { installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';
import { advancedDecodeAnswer, advancedRegistrations, recordedCredential } from '@/test/logic/advanced/auth/advanced-answers.js';

// The three recorded registrations: a none attestation (ES256), a packed one
// with a certificate and every extension, and an ML-DSA-44 one.
const REGISTRATIONS = advancedRegistrations();
const [, EVERYTHING] = REGISTRATIONS;
const CAPTURED_AT = '2026-09-21T14:13:20.000Z';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** The decoder as the view calls it (POST /api/decode): its recorded answer, else its refusal thrown. */
function recordedDecoder() {
  return vi.fn(async (payload) => {
    const { status, body } = advancedDecodeAnswer(payload);
    if (status !== 200) {
      throw new Error(body.error);
    }
    return body;
  });
}

/** The composition the result runs: the registration view, into a state of its own. */
function composer(decode = recordedDecoder()) {
  return vi.fn((options) => composeRegistration(options, { state: createRegistrationState(), decode }));
}

/** The credential's JSON as the WebAuthn ponyfill writes it for a recorded registration's credential. */
async function credentialJsonOf(registration) {
  const authenticator = installAuthenticator(vi, { create: recordedCredential(registration) });
  try {
    return (await create({ publicKey: {} })).toJSON();
  } finally {
    authenticator.remove();
  }
}

/** What the result is given for a recorded registration: the credential's JSON, the relying party's view, the saved record's storage ID. */
async function resultOf(registration, storageId = registration.complete.body.storedCredential.storageId) {
  return {
    credentialJson: await credentialJsonOf(registration),
    relyingPartyInfo: registration.complete.body.relyingParty,
    storageId,
  };
}

describe('keepRegistrationSnapshot', () => {
  it('composes the registration from the credential, the relying party and what the result reads from them', async () => {
    const input = await resultOf(EVERYTHING);
    const decode = recordedDecoder();
    const compose = composer(decode);
    const kept = await keepRegistrationSnapshot(input, { compose, saveSnapshot: vi.fn(async () => true), now: () => CAPTURED_AT });

    const relyingParty = EVERYTHING.complete.body.relyingParty;
    expect(compose).toHaveBeenCalledTimes(1);
    expect(compose).toHaveBeenCalledWith({
      credentialJson: input.credentialJson,
      relyingPartyInfo: relyingParty,
      attestationObjectValue: relyingParty.attestationObject,
      authenticatorDataValue: '',
      fallbackCertificates: [relyingParty.attestationCertificate, ...relyingParty.attestationCertificates],
    });
    expect(decode).toHaveBeenCalledTimes(1);
    expect(decode).toHaveBeenCalledWith(relyingParty.attestationObject);
    expect(kept.composed).toBe(await compose.mock.results[0].value);
  });

  it('saves a saved record\'s snapshot: the registration as data, captured when the clock says', async () => {
    const input = await resultOf(EVERYTHING);
    const saveSnapshot = vi.fn(async () => true);
    const kept = await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot, now: () => CAPTURED_AT });

    expect(saveSnapshot).toHaveBeenCalledTimes(1);
    expect(saveSnapshot).toHaveBeenCalledWith(EVERYTHING.complete.body.storedCredential.storageId, {
      schemaVersion: 2,
      capturedAt: CAPTURED_AT,
      state: kept.composed.stateSnapshot,
      response: { credential: input.credentialJson, relyingParty: kept.composed.relyingPartyCopy },
    });
    expect(kept.saved).toBe(true);
  });

  it('keeps the decoded attestation object, its certificates and the relying party\'s view in the snapshot', async () => {
    const input = await resultOf(EVERYTHING);
    const saveSnapshot = vi.fn(async () => true);
    await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot, now: () => CAPTURED_AT });

    const [, payload] = saveSnapshot.mock.calls[0];
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
      const saveSnapshot = vi.fn(async () => true);
      await keepRegistrationSnapshot(await resultOf(registration), { compose: composer(), saveSnapshot, now: () => CAPTURED_AT });
      formats.push(saveSnapshot.mock.calls[0][1].state.attestationObject.fmt);
    }
    expect(formats).toEqual(REGISTRATIONS.map(({ complete }) => complete.body.attestationFormat));
    expect(formats).toEqual(['none', 'packed', 'packed']);
  });

  it('keeps the decoder\'s refusal when the attestation object does not decode', async () => {
    const input = await resultOf(EVERYTHING);
    input.credentialJson.response.attestationObject = 'oA';
    const saveSnapshot = vi.fn(async () => true);
    await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot, now: () => CAPTURED_AT });

    const [, payload] = saveSnapshot.mock.calls[0];
    expect(payload.state.detailPreparation.attestationDecodeError).toBe('The payload is not valid CBOR.');
    expect(payload.state.attestationObject).toBeNull();
  });

  it('says the snapshot changed nothing when saving it changed nothing', async () => {
    const input = await resultOf(EVERYTHING);
    const unchanged = await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot: vi.fn(async () => false), now: () => CAPTURED_AT });
    const unanswered = await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot: vi.fn(async () => undefined), now: () => CAPTURED_AT });

    expect([unchanged.saved, unanswered.saved]).toEqual([false, false]);
  });

  it('saves nothing for a registration the browser did not save, and still gives the composition', async () => {
    const { storageId, ...unsaved } = await resultOf(EVERYTHING);
    const compose = composer();
    const saveSnapshot = vi.fn(async () => true);
    const kept = await keepRegistrationSnapshot(unsaved, { compose, saveSnapshot, now: () => CAPTURED_AT });
    const keptNull = await keepRegistrationSnapshot({ ...unsaved, storageId: null }, { compose, saveSnapshot, now: () => CAPTURED_AT });

    expect(saveSnapshot).not.toHaveBeenCalled();
    expect(kept).toEqual({ composed: await compose.mock.results[0].value, saved: false });
    expect(keptNull.saved).toBe(false);
    expect(kept.composed.attestation.body.kind).toBe('json');
  });

  it('captures the snapshot at the present time when given no clock', async () => {
    const input = await resultOf(EVERYTHING);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-28T08:30:00Z'));
    const saveSnapshot = vi.fn(async () => true);
    await keepRegistrationSnapshot(input, { compose: composer(), saveSnapshot });

    expect(saveSnapshot.mock.calls[0][1].capturedAt).toBe('2026-09-28T08:30:00.000Z');
  });
});
