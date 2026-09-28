import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  EMPTY_DETAIL_PREPARATION,
  addStateCertificate,
  addStateCertificates,
  applyRegistrationSnapshot,
  captureRegistrationState,
  createRegistrationState,
  hashAuthenticatorData,
  normaliseDetailPreparationSnapshot,
  prepareRegistrationState,
  resetRegistrationState,
  visibleStateCertificates,
} from '../../../../frontend/static/scripts/advanced/credential-display/registration-state.js';
import { advancedComplete, goldenDecode, registration } from './registration-detail-answers.js';

// What the registration view is built from (advanced/credential-display/registration-state.js),
// over the server's recorded answers.

const EMPTY_STATE = {
  attestationObject: null,
  attestationCertificates: [],
  visibleAttestationCertificateIndices: [],
  authenticatorData: null,
  authenticatorDataHash: '',
  authenticatorDataHex: '',
};

/** The attestation certificate as the decoder answers it: { parsedX5c, pem, raw }. */
const decodedCertificate = () => registration('packedX5c').attestationDecode.data.attestationObject.attStmt.x5c[0];

/** The same certificate as register-complete describes it (derBase64, pem, summary, ...). */
const describedCertificate = () => advancedComplete().relyingParty.attestationCertificate;

/** A certificate the server could not parse, as it describes one. */
const unparsed = (raw) => ({ raw, parsedX5c: { parseError: 'error parsing asn1 value' } });

/** A state holding a registration: its attestation object and authenticator data, decoded. */
async function preparedState(name = 'packedX5c') {
  const entry = registration(name);
  const state = createRegistrationState();
  const preparation = await prepareRegistrationState(state, {
    attestationObjectValue: entry.attestationObject,
    authenticatorDataValue: entry.authenticatorData,
  }, { decode: goldenDecode(entry) });
  return { state, preparation };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createRegistrationState and resetRegistrationState', () => {
  it('starts with nothing decoded', () => {
    expect(createRegistrationState()).toEqual(EMPTY_STATE);
  });

  it('empties a state in place', async () => {
    const { state } = await preparedState();
    const same = state;
    resetRegistrationState(state);
    expect(state).toBe(same);
    expect(state).toEqual(EMPTY_STATE);
  });
});

describe('addStateCertificate', () => {
  it('keeps a certificate as the view shows it', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toEqual([
      { parsedX5c: certificate.parsedX5c, pem: certificate.pem, raw: certificate.raw },
    ]);
  });

  it('skips an entry that is not a certificate', () => {
    const state = createRegistrationState();
    addStateCertificate(state, null);
    addStateCertificate(state, 'MIIBtDCCAWagAwIBAgICHq8w');
    expect(state.attestationCertificates).toEqual([]);
  });

  it("keeps one copy of a certificate the decoder and the relying party both describe", () => {
    const state = createRegistrationState();
    addStateCertificate(state, decodedCertificate());
    addStateCertificate(state, describedCertificate());
    expect(state.attestationCertificates).toHaveLength(1);
    expect(state.attestationCertificates[0].parsedX5c).toEqual(decodedCertificate().parsedX5c);
  });

  it('replaces a copy that failed to parse with one that parsed', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, unparsed(certificate.raw));
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toHaveLength(1);
    expect(state.attestationCertificates[0].parsedX5c).toEqual(certificate.parsedX5c);
  });

  it('keeps the parsed copy when a copy that failed follows it', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, certificate);
    addStateCertificate(state, unparsed(certificate.raw));
    expect(state.attestationCertificates[0].parsedX5c).toEqual(certificate.parsedX5c);
  });

  it('keeps a copy the state holds without details', () => {
    const certificate = decodedCertificate();
    const state = { ...createRegistrationState(), attestationCertificates: [{ raw: certificate.raw }] };
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toEqual([{ raw: certificate.raw }]);
  });

  it('keeps each certificate it has nothing to tell apart by', () => {
    const state = createRegistrationState();
    addStateCertificate(state, decodedCertificate());
    addStateCertificate(state, { parsedX5c: { subject: 'CN=Leaf' } });
    addStateCertificate(state, { parsedX5c: { subject: 'CN=Leaf' } });
    expect(state.attestationCertificates).toHaveLength(3);
  });

  it('keeps one copy of a PEM that holds no certificate', () => {
    const state = createRegistrationState();
    const pem = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----';
    addStateCertificate(state, { pem });
    addStateCertificate(state, { pem });
    expect(state.attestationCertificates).toEqual([{ parsedX5c: { pem }, pem }]);
  });
});

describe('addStateCertificates', () => {
  it('adds each certificate of a list', () => {
    const state = createRegistrationState();
    addStateCertificates(state, [decodedCertificate(), null, { parsedX5c: { subject: 'CN=Leaf' } }]);
    expect(state.attestationCertificates).toHaveLength(2);
  });

  it('adds a single certificate', () => {
    const state = createRegistrationState();
    addStateCertificates(state, decodedCertificate());
    expect(state.attestationCertificates).toHaveLength(1);
  });

  it('adds nothing for no certificates', () => {
    const state = createRegistrationState();
    addStateCertificates(state, null);
    expect(state.attestationCertificates).toEqual([]);
  });
});

describe('visibleStateCertificates', () => {
  const first = { parsedX5c: { subject: 'CN=Leaf' } };
  const second = { parsedX5c: { subject: 'CN=CA' } };

  it('gives the certificates the view lists, in its order', () => {
    const state = { attestationCertificates: [first, second], visibleAttestationCertificateIndices: [1, 0] };
    expect(visibleStateCertificates(state)).toEqual([second, first]);
  });

  it('skips a place that holds no certificate', () => {
    const state = { attestationCertificates: [first, 'x'], visibleAttestationCertificateIndices: [0, 1, 5] };
    expect(visibleStateCertificates(state)).toEqual([first]);
  });

  it('lists none when the state names none', () => {
    expect(visibleStateCertificates({ attestationCertificates: [first], visibleAttestationCertificateIndices: null })).toEqual([]);
  });
});

describe('hashAuthenticatorData', () => {
  const es256 = () => registration('es256');
  const hexOf = (entry) => entry.storedCredential.authenticatorDataHex;
  const hashOf = (entry) => entry.storedCredential.authenticatorDataHash;
  const base64Of = (entry) => Buffer.from(hexOf(entry), 'hex').toString('base64');

  async function hashed(authenticatorData) {
    const state = { ...createRegistrationState(), authenticatorData };
    const answer = await hashAuthenticatorData(state);
    return { answer, hex: state.authenticatorDataHex, hash: state.authenticatorDataHash };
  }

  it('hashes the authenticator data the decoder read', async () => {
    const entry = es256();
    expect(await hashed(entry.authenticatorDataDecode.data)).toEqual({
      answer: hashOf(entry), hex: hexOf(entry), hash: hashOf(entry),
    });
  });

  it('reads the bytes from base64url when there is no hex', async () => {
    const entry = es256();
    expect(await hashed({ base64url: entry.authenticatorData })).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('reads the bytes from standard base64 under a base64 key', async () => {
    const entry = es256();
    expect(await hashed({ base64: base64Of(entry) })).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('reads authenticator data given as hex text', async () => {
    const entry = es256();
    expect(await hashed(` ${hexOf(entry).toUpperCase()} `)).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('reads authenticator data given as base64url text as base64url, not as the hex digits among it', async () => {
    const entry = es256();
    expect(await hashed(entry.authenticatorData)).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('reads hex text with spaces or colons between its bytes', async () => {
    const entry = es256();
    const spaced = hexOf(entry).match(/../g).join(': ');
    expect(await hashed({ raw: spaced })).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('passes over hex that is odd or has no digits, and a spelling that does not decode', async () => {
    const entry = es256();
    const data = { raw: 'abc', hex: 'zz', base64url: '@@@@', base64: base64Of(entry) };
    expect(await hashed(data)).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('passes over spellings that are blank or not text', async () => {
    const entry = es256();
    const data = { raw: '  ', hex: 5, base64url: entry.authenticatorData };
    expect(await hashed(data)).toMatchObject({ hex: hexOf(entry), hash: hashOf(entry) });
  });

  it('forgets an earlier hash, and has none without authenticator data', async () => {
    const state = { ...createRegistrationState(), authenticatorDataHash: 'e65a', authenticatorDataHex: '4996' };
    expect(await hashAuthenticatorData(state)).toBe('');
    expect([state.authenticatorDataHex, state.authenticatorDataHash]).toEqual(['', '']);
  });

  it('has no hash for authenticator data it cannot read', async () => {
    expect(await hashed({ base64url: '@@@@' })).toEqual({ answer: '', hex: '', hash: '' });
    expect(await hashed(42)).toEqual({ answer: '', hex: '', hash: '' });
  });

  it('gives the hex but no hash without Web Crypto', async () => {
    const entry = es256();
    vi.stubGlobal('crypto', undefined);
    expect(await hashed(entry.authenticatorDataDecode.data)).toEqual({ answer: '', hex: hexOf(entry), hash: '' });
  });

  it('gives the hex but no hash when Web Crypto does not digest', async () => {
    const entry = es256();
    vi.stubGlobal('crypto', { subtle: { digest: () => Promise.reject(new Error('The operation is not supported.')) } });
    expect(await hashed(entry.authenticatorDataDecode.data)).toEqual({ answer: '', hex: hexOf(entry), hash: '' });
  });
});

describe('prepareRegistrationState', () => {
  it('decodes the attestation object and keeps its certificates', async () => {
    const entry = registration('packedX5c');
    const { state, preparation } = await preparedState('packedX5c');
    const certificate = entry.attestationDecode.data.attestationObject.attStmt.x5c[0];
    expect(preparation).toEqual({
      attestationObjectValue: entry.attestationObject,
      attestationDecodeError: '',
      authenticatorDataValue: entry.authenticatorData,
      authenticatorDecodeError: '',
    });
    expect(state.attestationObject).toEqual(entry.attestationDecode.data.attestationObject);
    expect(state.attestationCertificates).toEqual([{ parsedX5c: certificate.parsedX5c, pem: certificate.pem, raw: certificate.raw }]);
  });

  it('keeps the authenticator data the attestation object held, without decoding it again', async () => {
    const entry = registration('packedX5c');
    const state = createRegistrationState();
    const decode = vi.fn(goldenDecode(entry));
    await prepareRegistrationState(state, {
      attestationObjectValue: entry.attestationObject,
      authenticatorDataValue: entry.authenticatorData,
    }, { decode });
    expect(decode).toHaveBeenCalledTimes(1);
    expect(state.authenticatorData).toEqual(entry.attestationDecode.data.authenticatorData);
  });

  it('decodes and hashes the authenticator data when there is no attestation object', async () => {
    const entry = registration('es256');
    const state = createRegistrationState();
    await prepareRegistrationState(state, { authenticatorDataValue: entry.authenticatorData }, { decode: goldenDecode(entry) });
    expect(state.authenticatorData).toEqual(entry.authenticatorDataDecode.data);
    expect(state.authenticatorDataHex).toBe(entry.storedCredential.authenticatorDataHex);
    expect(state.authenticatorDataHash).toBe(entry.storedCredential.authenticatorDataHash);
  });

  it('trims the values it decodes', async () => {
    const entry = registration('es256');
    const decode = vi.fn(goldenDecode(entry));
    const preparation = await prepareRegistrationState(createRegistrationState(), {
      attestationObjectValue: ` ${entry.attestationObject}\n`,
    }, { decode });
    expect(decode).toHaveBeenCalledWith(entry.attestationObject);
    expect(preparation.attestationObjectValue).toBe(entry.attestationObject);
  });

  it('empties the state before it fills it', async () => {
    const { state } = await preparedState('packedX5c');
    await prepareRegistrationState(state, {});
    expect(state).toEqual(EMPTY_STATE);
  });

  it('treats missing options, values that are not text and a missing decode as nothing to decode', async () => {
    expect(await prepareRegistrationState(createRegistrationState(), null)).toEqual(EMPTY_DETAIL_PREPARATION);
    expect(await prepareRegistrationState(createRegistrationState())).toEqual(EMPTY_DETAIL_PREPARATION);
    expect(await prepareRegistrationState(createRegistrationState(), {
      attestationObjectValue: 42,
      authenticatorDataValue: { base64url: 'SZYN' },
      fallbackCertificates: null,
    })).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('says why the attestation object did not decode', async () => {
    const state = createRegistrationState();
    const preparation = await prepareRegistrationState(state, { attestationObjectValue: 'o2Nm' }, { decode: goldenDecode() });
    expect(preparation.attestationDecodeError).toBe('The payload is not valid CBOR.');
    expect(state.attestationObject).toBeNull();
  });

  it('says the attestation object did not decode when the refusal gives no reason', async () => {
    const decode = () => Promise.reject(new Error(''));
    const preparation = await prepareRegistrationState(createRegistrationState(), { attestationObjectValue: 'o2Nm' }, { decode });
    expect(preparation.attestationDecodeError).toBe('Failed to decode attestationObject.');
  });

  it('says why the authenticator data did not decode, and keeps it as given', async () => {
    const entry = registration('es256');
    const state = createRegistrationState();
    const preparation = await prepareRegistrationState(state, { authenticatorDataValue: entry.authenticatorData }, { decode: goldenDecode() });
    expect(preparation.authenticatorDecodeError).toBe('The payload is not valid CBOR.');
    expect(state.authenticatorData).toEqual({
      base64url: entry.authenticatorData,
      raw: entry.storedCredential.authenticatorDataHex,
    });
    expect(state.authenticatorDataHash).toBe(entry.storedCredential.authenticatorDataHash);
  });

  it('says the authenticator data did not decode when the refusal gives no reason', async () => {
    const decode = () => Promise.reject(undefined);
    const preparation = await prepareRegistrationState(createRegistrationState(), { authenticatorDataValue: 'SZYN' }, { decode });
    expect(preparation.authenticatorDecodeError).toBe('Failed to decode authenticatorData.');
  });

  it('keeps authenticator data it cannot read as bytes as it was given', async () => {
    const state = createRegistrationState();
    await prepareRegistrationState(state, { authenticatorDataValue: 'SZYN5' }, { decode: async () => ({}) });
    expect(state.authenticatorData).toEqual({ base64url: 'SZYN5', raw: 'SZYN5' });
    expect([state.authenticatorDataHex, state.authenticatorDataHash]).toEqual(['', '']);
  });

  it('reads an answer whose data is the attestation object itself', async () => {
    const state = createRegistrationState();
    const decode = async () => ({ data: { fmt: 'none', attStmt: {} } });
    await prepareRegistrationState(state, { attestationObjectValue: 'o2Nm' }, { decode });
    expect(state.attestationObject).toEqual({ fmt: 'none', attStmt: {} });
    expect(state.authenticatorData).toBeNull();
  });

  it('keeps nothing from an answer without a decoded map', async () => {
    for (const answer of [{}, { data: 'o2Nm' }]) {
      const state = createRegistrationState();
      const preparation = await prepareRegistrationState(state, { attestationObjectValue: 'o2Nm' }, { decode: async () => answer });
      expect(preparation.attestationDecodeError).toBe('');
      expect(state).toEqual(EMPTY_STATE);
    }
  });

  it('adds no certificate for a decoded attestation object without a statement', async () => {
    const state = createRegistrationState();
    const decode = async () => ({ data: { attestationObject: { fmt: 'none' } } });
    await prepareRegistrationState(state, { attestationObjectValue: 'o2Nm' }, { decode });
    expect(state.attestationObject).toEqual({ fmt: 'none' });
    expect(state.attestationCertificates).toEqual([]);
  });

  it('uses the decoded attestation object the record holds when there is nothing to decode', async () => {
    const decoded = registration('packedX5c').attestationDecode.data.attestationObject;
    const state = createRegistrationState();
    const decode = vi.fn();
    await prepareRegistrationState(state, { attestationObjectDecoded: decoded }, { decode });
    expect(decode).not.toHaveBeenCalled();
    expect(state.attestationObject).toEqual(decoded);
    expect(state.attestationCertificates).toHaveLength(1);
  });

  it("reads a decoded object's certificates under their other spellings", async () => {
    const certificate = decodedCertificate();
    const state = createRegistrationState();
    await prepareRegistrationState(state, { attestationObjectDecoded: { fmt: 'packed', att_statement: { X5C: [certificate] } } });
    expect(state.attestationCertificates).toHaveLength(1);
  });

  it('adds no certificate for a decoded object without them', async () => {
    for (const attestationObjectDecoded of [{ fmt: 'none', attStmt: {} }, { fmt: 'none' }]) {
      const state = createRegistrationState();
      await prepareRegistrationState(state, { attestationObjectDecoded });
      expect(state.attestationObject).toEqual(attestationObjectDecoded);
      expect(state.attestationCertificates).toEqual([]);
    }
  });

  it('prefers what the decoder answers to the decoded object the record holds', async () => {
    const entry = registration('packedX5c');
    const state = createRegistrationState();
    await prepareRegistrationState(state, {
      attestationObjectValue: entry.attestationObject,
      attestationObjectDecoded: { fmt: 'none', attStmt: {} },
    }, { decode: goldenDecode(entry) });
    expect(state.attestationObject.fmt).toBe('packed');
  });

  it('ignores a decoded object that is not a map', async () => {
    const state = createRegistrationState();
    await prepareRegistrationState(state, { attestationObjectDecoded: 'o2Nm' });
    expect(state.attestationObject).toBeNull();
  });

  it('adds the certificates it is given before those the attestation object holds', async () => {
    const entry = registration('packedX5c');
    const given = { parsedX5c: { subject: 'CN=Given' } };
    const state = createRegistrationState();
    await prepareRegistrationState(state, {
      attestationObjectValue: entry.attestationObject,
      fallbackCertificates: [given],
    }, { decode: goldenDecode(entry) });
    expect(state.attestationCertificates.map((certificate) => certificate.parsedX5c.subject)).toEqual([
      'CN=Given',
      entry.attestationDecode.data.attestationObject.attStmt.x5c[0].parsedX5c.subject,
    ]);
  });

  it('keeps only the certificates it is given when asked to prefer them', async () => {
    const entry = registration('packedX5c');
    const given = { parsedX5c: { subject: 'CN=Given' } };
    for (const options of [
      { attestationObjectValue: entry.attestationObject },
      { attestationObjectDecoded: entry.attestationDecode.data.attestationObject },
    ]) {
      const state = createRegistrationState();
      await prepareRegistrationState(state, {
        ...options,
        fallbackCertificates: [given],
        preferFallbackCertificates: true,
      }, { decode: goldenDecode(entry) });
      expect(state.attestationCertificates).toEqual([given]);
    }
  });

  it("takes the attestation object's certificates when asked to prefer given ones but none were given", async () => {
    const entry = registration('packedX5c');
    const state = createRegistrationState();
    await prepareRegistrationState(state, {
      attestationObjectValue: entry.attestationObject,
      preferFallbackCertificates: true,
    }, { decode: goldenDecode(entry) });
    expect(state.attestationCertificates).toHaveLength(1);
  });

  it("takes the relying party's certificate when nothing else gave one", async () => {
    const relyingPartyInfo = advancedComplete().relyingParty;
    const state = createRegistrationState();
    await prepareRegistrationState(state, { relyingPartyInfo });
    expect(state.attestationCertificates).toEqual([{
      parsedX5c: relyingPartyInfo.attestationCertificate,
      pem: relyingPartyInfo.attestationCertificate.pem,
      raw: decodedCertificate().raw,
    }]);
  });

  it("takes the relying party's list of certificates when it names no single one", async () => {
    const certificate = describedCertificate();
    const state = createRegistrationState();
    await prepareRegistrationState(state, { relyingPartyInfo: { attestationCertificates: [certificate] } });
    expect(state.attestationCertificates).toHaveLength(1);
  });
});

describe('normaliseDetailPreparationSnapshot', () => {
  it('keeps what a snapshot said about the decodes', () => {
    const said = {
      attestationObjectValue: 'o2Nm',
      attestationDecodeError: 'The payload is not valid CBOR.',
      authenticatorDataValue: 'SZYN',
      authenticatorDecodeError: '',
    };
    expect(normaliseDetailPreparationSnapshot({ ...said, extra: true })).toEqual(said);
  });

  it('gives empty sentences for what is not text', () => {
    expect(normaliseDetailPreparationSnapshot({
      attestationObjectValue: 1, attestationDecodeError: null, authenticatorDataValue: {}, authenticatorDecodeError: [],
    })).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('gives a fresh copy of the empty sentences without a snapshot', () => {
    const answer = normaliseDetailPreparationSnapshot(null);
    expect(answer).toEqual(EMPTY_DETAIL_PREPARATION);
    expect(answer).not.toBe(EMPTY_DETAIL_PREPARATION);
  });
});

describe('captureRegistrationState', () => {
  it('copies the state as a snapshot keeps it, with what it said about the decodes', async () => {
    const { state, preparation } = await preparedState('packedX5c');
    state.visibleAttestationCertificateIndices = [0];
    const captured = captureRegistrationState(state, preparation);
    expect(captured).toEqual({
      detailPreparation: preparation,
      attestationObject: state.attestationObject,
      attestationCertificates: state.attestationCertificates,
      visibleAttestationCertificateIndices: [0],
      authenticatorData: state.authenticatorData,
      authenticatorDataHex: state.authenticatorDataHex,
      authenticatorDataHash: state.authenticatorDataHash,
    });
  });

  it('keeps copies the state can no longer change', async () => {
    const { state } = await preparedState('packedX5c');
    const captured = captureRegistrationState(state);
    state.attestationObject.fmt = 'none';
    state.attestationCertificates.push({ parsedX5c: {} });
    expect(captured.attestationObject.fmt).toBe('packed');
    expect(captured.attestationCertificates).toHaveLength(1);
  });

  it('says nothing about the decodes when not told', () => {
    expect(captureRegistrationState(createRegistrationState())).toEqual({ ...EMPTY_STATE, detailPreparation: EMPTY_DETAIL_PREPARATION });
  });

  it('captures empty values for parts of the wrong kind', () => {
    for (const attestationCertificates of [null, { 0: 'MIIB' }]) {
      const captured = captureRegistrationState({
        attestationObject: 'o2Nm',
        attestationCertificates,
        visibleAttestationCertificateIndices: '0',
        authenticatorData: 7,
        authenticatorDataHex: 5,
        authenticatorDataHash: null,
      });
      expect(captured).toEqual({ ...EMPTY_STATE, detailPreparation: EMPTY_DETAIL_PREPARATION });
    }
  });
});

describe('applyRegistrationSnapshot', () => {
  it('restores the state it captured, and what it said about the decodes', async () => {
    const { state, preparation } = await preparedState('packedX5c');
    state.visibleAttestationCertificateIndices = [0];
    const restored = createRegistrationState();
    expect(applyRegistrationSnapshot(restored, captureRegistrationState(state, preparation))).toEqual(preparation);
    expect(restored).toEqual(state);
  });

  it('reads a snapshot that keeps the state under state', async () => {
    const { state, preparation } = await preparedState('es256');
    const snapshot = { schemaVersion: 2, state: captureRegistrationState(state, preparation) };
    const restored = createRegistrationState();
    expect(applyRegistrationSnapshot(restored, snapshot)).toEqual(preparation);
    expect(restored.attestationObject).toEqual(state.attestationObject);
  });

  it('gives empty sentences for a snapshot that kept none', () => {
    expect(applyRegistrationSnapshot(createRegistrationState(), { attestationObject: { fmt: 'none' } })).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('does nothing without a snapshot', () => {
    const state = createRegistrationState();
    expect(applyRegistrationSnapshot(state, null)).toBeUndefined();
    expect(applyRegistrationSnapshot(state, 'snapshot')).toBeUndefined();
    expect(state).toEqual(EMPTY_STATE);
  });

  it('lists every certificate when the snapshot names none', () => {
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, { attestationCertificates: [decodedCertificate(), describedCertificate()] });
    expect(state.visibleAttestationCertificateIndices).toEqual([0, 1]);
  });

  it("gives the authenticator data its hex as raw bytes when it has none", () => {
    const hex = registration('es256').storedCredential.authenticatorDataHex;
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, { authenticatorData: { counter: 0 }, authenticatorDataHex: hex });
    expect(state.authenticatorData).toEqual({ counter: 0, raw: hex });
    applyRegistrationSnapshot(state, { authenticatorData: { raw: 'abcd' }, authenticatorDataHex: hex });
    expect(state.authenticatorData).toEqual({ raw: 'abcd' });
  });

  it('keeps empty values for parts of the wrong kind', () => {
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, {
      attestationObject: 'o2Nm',
      attestationCertificates: { 0: 'MIIB' },
      visibleAttestationCertificateIndices: '0',
      authenticatorData: 'SZYN',
      authenticatorDataHex: 5,
      authenticatorDataHash: null,
    });
    expect(state).toEqual(EMPTY_STATE);
  });
});
