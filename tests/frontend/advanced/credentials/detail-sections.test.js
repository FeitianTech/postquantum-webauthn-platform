import { describe, expect, it } from 'vitest';

import {
  DETAIL_TEXT,
  describeAaguid,
  describeAttestationFormat,
  describeAuthenticatorDataFlags,
  describeExtensions,
  describeProperties,
  describePublicKey,
  describeUserInfo,
  describeValue,
} from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/detail-sections.js';
import { extractCredentialAttestationContext } from '../../../../frontend/static/scripts/advanced/credential-display/attestation-context.js';
import {
  describeCoseAlgorithm,
  describeCoseKeyType,
  describeMldsaParameterSet,
} from '../../../../frontend/static/scripts/advanced/cose-labels.js';
import { advancedRecord, simpleRecord } from './registration-detail-answers.js';

// What a saved credential's details show above its registration
// (credential-display/credential-detail-runtime/detail-sections.js).

const AAGUID = '00112233445566778899aabbccddeeff';
const AAGUID_GUID = '00112233-4455-6677-8899-aabbccddeeff';
const DESCRIBERS = { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet };

/** The Properties section for a record, as the details build it. */
function properties(cred, extra = {}) {
  return describeProperties({ cred, attestationContext: extractCredentialAttestationContext(cred), ...extra });
}

const checkValues = (section) => Object.fromEntries(section.checks.map(({ label, value }) => [label, value]));
const aaguidValues = (section) => Object.fromEntries(section.values.map(({ label, value }) => [label, value]));

describe('describeValue', () => {
  it('says true for true, in any spelling of the word', () => {
    expect([true, 'true', ' TRUE '].map(describeValue)).toEqual(Array(3).fill({ kind: 'true', text: 'true' }));
  });

  it('says false for false, in any spelling of the word', () => {
    expect([false, 'false', 'False'].map(describeValue)).toEqual(Array(3).fill({ kind: 'false', text: 'false' }));
  });

  it('says N/A for a value that is absent', () => {
    expect([null, undefined].map(describeValue)).toEqual(Array(2).fill({ kind: 'missing', text: 'N/A' }));
  });

  it('shows any other value as written', () => {
    expect([8, 'maybe', ''].map(describeValue)).toEqual([
      { kind: 'other', text: '8' },
      { kind: 'other', text: 'maybe' },
      { kind: 'other', text: '' },
    ]);
  });
});

describe('describeProperties', () => {
  it('gives a packed registration\'s properties and its four checks', () => {
    const record = simpleRecord('packedX5c');
    const section = properties(record, { fallbackCertificates: record.properties.attestationCertificates });
    expect(section.title).toBe('Properties');
    expect(section.minPinLength).toBe(8);
    expect(checkValues(section)).toEqual({
      'Signature Valid': true,
      'Root Valid': null,
      'RPID Hash Valid': true,
      'AAGUID Match': true,
    });
    expect(section.warning).toBe('');
  });

  it('lists which roots the Root Valid check tried, each with its verdict', () => {
    const section = properties(simpleRecord('packedX5c'));
    const [signature, root, rpid, aaguid] = section.checks;
    expect(root.rootChecks).toEqual([
      { label: 'FIDO MDS', value: null },
      { label: 'Chain', value: null },
    ]);
    expect([signature.rootChecks, rpid.rootChecks, aaguid.rootChecks]).toEqual([null, null, null]);
  });

  it('reads the roots under their camelCase names, and a root not tried as null', () => {
    const section = properties({ attestationChecks: { rootChecks: { fidoMds: 'pass' } } });
    expect(section.checks[1].rootChecks).toEqual([
      { label: 'FIDO MDS', value: true },
      { label: 'Chain', value: null },
    ]);
  });

  it('names no roots when the checks name none, or there are no checks', () => {
    expect(properties(simpleRecord('es256')).checks[1].rootChecks).toBeNull();
    expect(properties({}).checks[1].rootChecks).toBeNull();
  });

  it('takes an advanced registration\'s discoverability, large blob and minPinLength from the record', () => {
    const record = advancedRecord();
    const section = properties(record);
    expect([section.discoverable, section.largeBlob, section.minPinLength]).toEqual([false, true, 6]);
    expect(checkValues(section)['AAGUID Match']).toBe(true);
  });

  it('falls back to the older names for discoverable and large blob, then to false', () => {
    expect(properties({ discoverable: true, largeBlobSupported: true })).toMatchObject({ discoverable: true, largeBlob: true });
    expect(properties({})).toMatchObject({ discoverable: false, largeBlob: false, minPinLength: null });
  });

  it('matches the AAGUID from the certificate and the authenticator data it is given', () => {
    const section = properties({}, { certificateAaguidHex: AAGUID, authDataAaguidHex: 'ff'.repeat(16) });
    expect(checkValues(section)['AAGUID Match']).toBe(false);
  });

  it('gives the metadata\'s warning from the first place that has one', () => {
    const places = [
      { attestationChecks: { metadata: { verification_warning: 'checks' } } },
      { attestationChecks: { metadata: { verificationWarning: 'checks, camelCase' } } },
      { attestationSummary: { metadata: { verification_warning: 'summary' } } },
      { attestationSummary: { metadata: { verificationWarning: 'summary, camelCase' } } },
      { properties: { metadata: { verification_warning: 'properties' } } },
      { properties: { metadata: { verificationWarning: 'properties, camelCase' } } },
      { metadata: { verification_warning: 'record' } },
      { metadata: { verificationWarning: 'record, camelCase' } },
    ];
    expect(places.map((cred) => properties(cred).warning)).toEqual([
      'checks',
      'checks, camelCase',
      'summary',
      'summary, camelCase',
      'properties',
      'properties, camelCase',
      'record',
      'record, camelCase',
    ]);
  });
});

describe('describeUserInfo', () => {
  it('gives the user\'s name, display name, and the user handle and credential id in each spelling', () => {
    const record = simpleRecord('es256');
    const section = describeUserInfo(record);
    expect(section).toMatchObject({ title: 'User info at creation', name: 'user@example.com', displayName: 'user@example.com' });
    expect(section.identifiers.map(({ title }) => title)).toEqual([DETAIL_TEXT.userHandle, DETAIL_TEXT.credentialId]);
    expect(section.identifiers[0].spellings).toEqual([
      { label: 'b64', value: 'dXNlckBleGFtcGxlLmNvbQ==' },
      { label: 'b64u', value: 'dXNlckBleGFtcGxlLmNvbQ' },
      { label: 'hex', value: Array.from(new TextEncoder().encode('user@example.com'), (byte) => byte.toString(16).padStart(2, '0')).join('') },
    ]);
    expect(section.identifiers[1].spellings.find(({ label }) => label === 'hex').value).toBe(record.credentialIdHex);
  });

  it('shows an identifier that is not base64url as stored, and says so', () => {
    const [handle] = describeUserInfo({ userHandle: 'not base64url!' }).identifiers;
    expect(handle).toEqual({ title: DETAIL_TEXT.userHandle, stored: 'not base64url!', note: DETAIL_TEXT.notBase64Url });
  });

  it('names the user by the email when there is no user name, and says N/A when there is neither', () => {
    expect(describeUserInfo({ email: 'a@example.com' })).toMatchObject({ name: 'a@example.com', displayName: 'a@example.com', identifiers: [] });
    expect(describeUserInfo({ userName: 'alice' })).toMatchObject({ name: 'alice', displayName: 'alice' });
    expect(describeUserInfo({})).toMatchObject({ name: 'N/A', displayName: 'N/A' });
  });
});

describe('describeAaguid', () => {
  const aaguid = (cred) => aaguidValues(describeAaguid(cred, extractCredentialAttestationContext(cred)));

  it('gives the record\'s AAGUID in each spelling', () => {
    expect(aaguid(simpleRecord('es256'))).toEqual({
      b64: 'ABEiM0RVZneImaq7zN3u/w==',
      b64u: 'ABEiM0RVZneImaq7zN3u_w',
      hex: AAGUID,
      guid: AAGUID_GUID,
    });
  });

  it('takes the AAGUID from where else the record keeps it', () => {
    expect(aaguid({ properties: { aaguidGuid: AAGUID_GUID } }).hex).toBe(AAGUID);
    expect(aaguid({ attestationSummary: { aaguid: AAGUID } }).hex).toBe(AAGUID);
    expect(aaguid({ metadata: { guid: AAGUID_GUID } }).hex).toBe(AAGUID);
  });

  it('takes the AAGUID the relying party reported, as an object or as text', () => {
    expect(aaguid({ relyingParty: { aaguid: { guid: AAGUID_GUID } } }).hex).toBe(AAGUID);
    expect(aaguid({ relyingParty: { aaguid: AAGUID_GUID } }).hex).toBe(AAGUID);
  });

  it('reads the AAGUID from the authenticator data when nothing else names it', () => {
    expect(aaguid({ authenticatorData: simpleRecord('es256').authenticatorData }).guid).toBe(AAGUID_GUID);
  });

  it('says N/A in each spelling when the AAGUID is unknown', () => {
    expect(aaguid({})).toEqual({ b64: 'N/A', b64u: 'N/A', hex: 'N/A', guid: 'N/A' });
  });

  it('gives no GUID for an AAGUID that is not sixteen bytes', () => {
    expect(aaguid({ aaguid: 'abcd' })).toEqual({ b64: 'q80=', b64u: 'q80', hex: 'abcd', guid: 'N/A' });
  });

  it('gives only the hex of an AAGUID with an odd number of digits', () => {
    expect(aaguid({ aaguid: 'abc!' })).toEqual({ b64: 'N/A', b64u: 'N/A', hex: 'abc', guid: 'N/A' });
  });
});

describe('describeAttestationFormat', () => {
  it('gives the format as it is', () => {
    expect(describeAttestationFormat('packed')).toEqual({ title: 'Attestation Format', value: 'packed' });
  });
});

describe('describeAuthenticatorDataFlags', () => {
  it('has no section for a record without flags', () => {
    expect(describeAuthenticatorDataFlags(simpleRecord('es256'))).toBeNull();
  });

  it('gives each flag and the signature counter', () => {
    const section = describeAuthenticatorDataFlags({
      flags: { at: true, be: false, bs: false, ed: false, up: true, uv: true },
      signCount: 7,
    });
    expect(section).toEqual({
      title: 'Authenticator Data (registration)',
      flags: [
        { name: 'AT', value: 'true' },
        { name: 'BE', value: 'false' },
        { name: 'BS', value: 'false' },
        { name: 'ED', value: 'false' },
        { name: 'UP', value: 'true' },
        { name: 'UV', value: 'true' },
      ],
      counter: '7',
    });
  });

  it('counts from 0 when the record keeps no counter', () => {
    expect(describeAuthenticatorDataFlags({ flags: { up: true } }).counter).toBe('0');
  });
});

describe('describeExtensions', () => {
  it('shows the client extension outputs as indented JSON', () => {
    const record = simpleRecord('packedX5c');
    expect(describeExtensions(record)).toEqual({
      title: 'Client extension outputs (registration)',
      text: JSON.stringify(record.clientExtensionOutputs, null, 2),
    });
  });

  it('has no section when there are no outputs', () => {
    expect(describeExtensions(simpleRecord('es256'))).toBeNull();
    expect(describeExtensions({})).toBeNull();
  });
});

describe('describePublicKey', () => {
  const lines = (cred) => describePublicKey(cred, DESCRIBERS)?.lines;

  it('names an ES256 key\'s algorithm and COSE key type', () => {
    expect(describePublicKey(simpleRecord('es256'), DESCRIBERS)).toEqual({
      title: 'Public Key',
      lines: [
        { label: 'Algorithm:', value: describeCoseAlgorithm(-7) },
        { label: 'COSE key type:', value: describeCoseKeyType(2) },
      ],
    });
  });

  it('gives an ML-DSA key\'s parameter set', () => {
    expect(lines(simpleRecord('mldsa65'))).toEqual([
      { label: 'Algorithm:', value: describeCoseAlgorithm(-49) },
      { label: 'COSE key type:', value: describeCoseKeyType(7) },
      { label: 'ML-DSA parameter set:', value: 'ML-DSA-65' },
    ]);
  });

  it('takes the key type the record names before the one in the COSE key', () => {
    expect(lines({ ...advancedRecord(), publicKeyType: 1 })[1]).toEqual({ label: 'COSE key type:', value: describeCoseKeyType(1) });
  });

  it('reads the algorithm from the COSE key when the record names none', () => {
    expect(lines({ publicKeyCose: { 1: 1, 3: -8 } })).toEqual([
      { label: 'Algorithm:', value: describeCoseAlgorithm(-8) },
      { label: 'COSE key type:', value: describeCoseKeyType(1) },
    ]);
  });

  it('shows the COSE key\'s algorithm as it is when it is not a number', () => {
    expect(lines({ publicKeyAlgorithm: 'unknown', publicKeyCose: { 3: 'unknown' } })).toEqual([
      { label: 'Algorithm:', value: describeCoseAlgorithm('unknown') },
    ]);
  });

  it('says the algorithm is unknown, with no key type, when the record names neither', () => {
    expect(lines({ algorithm: null })).toEqual([{ label: 'Algorithm:', value: 'Unknown' }]);
    expect(lines({ algorithm: -7, publicKeyType: null, publicKeyCose: { 1: null } })).toEqual([
      { label: 'Algorithm:', value: describeCoseAlgorithm(-7) },
    ]);
  });

  it('has no section without an algorithm or a COSE key', () => {
    expect(describePublicKey({}, DESCRIBERS)).toBeNull();
    expect(describePublicKey({ publicKeyCose: {} }, DESCRIBERS)).toBeNull();
  });
});
