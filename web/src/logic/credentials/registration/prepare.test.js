import { Buffer } from 'node:buffer';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { hashAuthenticatorData, prepareRegistrationState } from './prepare.js';
import { EMPTY_DETAIL_PREPARATION, createRegistrationState } from './state.js';
import { advancedComplete, goldenDecode, registration } from '@/test/logic/credentials/registration-detail-answers.js';
import { EMPTY_STATE, decodedCertificate, describedCertificate, preparedState } from '@/test/logic/credentials/registration-state.js';

// A registration state filled from a record and the decoder
// (credentials/registration/prepare.js), over the server's recorded answers.

afterEach(() => {
  vi.unstubAllGlobals();
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
