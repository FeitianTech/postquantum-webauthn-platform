import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  sanitiseRegistrationDetailSnapshot,
  stripKeysRecursively,
} from './snapshot-sanitize.js';
import { repoFile } from '@/test/logic/repo-file.js';

// The parsed attestation certificate register-complete answers (characterization golden).
const GOLDEN = JSON.parse(
  readFileSync(repoFile('tests/app/characterization/golden/routes/advanced-register-packed-x5c-everything.json'), 'utf8'),
);
const CERTIFICATE = GOLDEN.requests[1].body.relyingParty.attestationCertificates[0];
const { derBase64: CERTIFICATE_DER, ...CERTIFICATE_WITHOUT_DER } = CERTIFICATE;

const CREDENTIAL = {
  id: 'HhfJJzOBVmmUZYuGYc2aY9SMJiNMjQ1Y0QppVmqI4yI',
  rawId: 'HhfJJzOBVmmUZYuGYc2aY9SMJiNMjQ1Y0QppVmqI4yI',
  type: 'public-key',
  response: { clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0', attestationObject: 'o2NmbXRkbm9uZQ' },
};

// JSON.stringify writes an invalid Date as null: an in-memory value with no JSON form.
const WRITES_AS_NULL = new Date(Number.NaN);

// The state a snapshot keeps. The response is there so that a snapshot whose
// state keeps nothing is still a snapshot.
function keptState(state) {
  return sanitiseRegistrationDetailSnapshot({ schemaVersion: 2, state, response: { credential: CREDENTIAL } }).state;
}

describe('stripKeysRecursively', () => {
  it('leaves the target alone when there are no keys to strip', () => {
    const target = { derBase64: CERTIFICATE_DER };

    stripKeysRecursively(target, []);

    expect(target).toEqual({ derBase64: CERTIFICATE_DER });
  });
});

describe('attestation certificates in a snapshot', () => {
  it('drops an entry that is not an object, such as a certificate kept as text', () => {
    const state = keptState({ attestationCertificates: [null, CERTIFICATE_DER, { parsedX5c: CERTIFICATE }] });

    expect(state.attestationCertificates).toEqual([{ parsedX5c: CERTIFICATE_WITHOUT_DER }]);
  });

  it('drops an extension that is not an object', () => {
    const parsedX5c = { ...CERTIFICATE, extensions: [null, ...CERTIFICATE.extensions] };

    const [entry] = keptState({ attestationCertificates: [{ parsedX5c }] }).attestationCertificates;

    expect(entry.parsedX5c.extensions).toEqual(CERTIFICATE.extensions);
  });

  it('moves a certificate parsed under the older name to parsedX5c', () => {
    const [entry] = keptState({ attestationCertificates: [{ parsed: CERTIFICATE }] }).attestationCertificates;

    expect(entry).toEqual({ parsedX5c: CERTIFICATE_WITHOUT_DER });
  });

  it('keeps an entry that was never parsed, without its DER', () => {
    const pem = CERTIFICATE.pem;

    const state = keptState({ attestationCertificates: [{ pem, derBase64: CERTIFICATE_DER }] });

    expect(state.attestationCertificates).toEqual([{ pem }]);
  });

  it('keeps no entry that held only its DER', () => {
    const state = keptState({ attestationCertificates: [{ derBase64: CERTIFICATE_DER }], authenticatorDataHex: '0a0b' });

    expect(state).toEqual({ authenticatorDataHex: '0a0b' });
  });

  it('drops a parsed certificate with no JSON form, keeping the rest of its entry', () => {
    // The BigInt keeps the entry from being copied through JSON, so the value reaches the certificate's own copy.
    const state = keptState({ attestationCertificates: [{ parsedX5c: WRITES_AS_NULL, serialNumber: 7855n }] });

    expect(state.attestationCertificates).toEqual([{ serialNumber: 7855n }]);
  });

  it('drops a certificate parsed under the older name with no JSON form', () => {
    const state = keptState({ attestationCertificates: [{ parsed: WRITES_AS_NULL, serialNumber: 7855n }] });

    expect(state.attestationCertificates).toEqual([{ serialNumber: 7855n }]);
  });
});

// A packed self-attestation's parts (the advanced-register-packed-self-ed25519 golden).
const AUTH_DATA = 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPNsKemupOarUv0isLTr2uyGeYsXWxzJGUqdoh3uTGQlpAEBAycgBiFYIMeGk8ZtMtfSNKJbhBbTtDkWCOnaORR8r4yL_LqxNIEl';
const SELF_SIGNATURE = 'ZvBVgFmdOqs_lVCfujgunTyijUVOHeOMydSzPuP7FstixDkiAxR7cVwdG6EOg_ziy2LUERiZ_EZGez0KvD9xDg';

describe('the decoded registration in a snapshot', () => {
  it('keeps an attestation object that has no statement', () => {
    const attestationObject = { fmt: 'none', authData: AUTH_DATA };

    expect(keptState({ attestationObject }).attestationObject).toEqual(attestationObject);
  });

  it('keeps a self-attestation statement, which has no certificate chain', () => {
    const attestationObject = { fmt: 'packed', attStmt: { alg: -8, sig: SELF_SIGNATURE }, authData: AUTH_DATA };

    expect(keptState({ attestationObject }).attestationObject).toEqual(attestationObject);
  });

  it('keeps no attestation object with no JSON form', () => {
    expect(keptState({ attestationObject: WRITES_AS_NULL, authenticatorDataHex: '0a0b' })).toEqual({ authenticatorDataHex: '0a0b' });
  });

  it('keeps no authenticator data with no JSON form', () => {
    expect(keptState({ authenticatorData: WRITES_AS_NULL, authenticatorDataHex: '0a0b' })).toEqual({ authenticatorDataHex: '0a0b' });
  });

  it('keeps no state that is not an object', () => {
    expect(keptState('0a0b')).toBeUndefined();
  });
});

describe('the response in a snapshot', () => {
  it('leaves out a part that cannot be written as JSON', () => {
    const snapshot = sanitiseRegistrationDetailSnapshot({
      schemaVersion: 2,
      response: { credential: { ...CREDENTIAL, signCount: 10n }, relyingParty: { rpName: 'Demo server' } },
    });

    expect(snapshot.response).toEqual({ relyingParty: { rpName: 'Demo server' } });
  });
});
