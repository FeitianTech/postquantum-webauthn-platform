import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { TRY_IN_ADVANCED_TEXT, statementSettings } from './statement-settings.js';
import { repoFile } from '@/test/logic/repo-file.js';

// What an MDS statement says that the Advanced registration can take (advanced/registration/statement-settings.js).

// The fixture's statements, as the entry pages load them (tests/fixtures/mds, through mds-files.json).
const DETAILS = JSON.parse(readFileSync(repoFile('web/src/test/mds-files.json'), 'utf8')).details;
const statementOf = (entryId) => structuredClone(DETAILS[`/assets/mds/entries/${encodeURIComponent(entryId)}`].metadataStatement);

describe('statementSettings', () => {
  it('takes getInfo\'s algorithms, verification when one is listed, and an external authenticator\'s attachment', () => {
    // L1: getInfo lists ES256 and EdDSA; presence alone or a PIN; external, wired, NFC.
    expect(statementSettings(statementOf('aaguid:f1d0f1d0-0000-4000-8000-000000000001'))).toEqual({
      algorithms: [-8, -7],
      userVerification: 'required',
      attachment: 'cross-platform',
    });
  });

  it('reads the authentication algorithms by their registry names when getInfo lists none, and an internal one\'s attachment', () => {
    const statement = statementOf('aaguid:f1d0f1d0-0000-4000-8000-000000000004');
    expect(statement.authenticatorGetInfo?.algorithms ?? []).toEqual([]);
    expect(statementSettings(statement)).toEqual({ algorithms: [-8, -7], userVerification: 'required', attachment: 'platform' });
  });

  it('discourages verification for an authenticator that can only test presence', () => {
    expect(statementSettings(statementOf('aaguid:f1d0f1d0-0000-4000-8000-000000000020'))).toMatchObject({ userVerification: 'discouraged' });
  });

  it('takes a U2F authenticator\'s, and nothing of a UAF one, which WebAuthn does not register', () => {
    expect(statementSettings(statementOf('akid:f1d0000000000000000000000000000000000011'))).toEqual({
      algorithms: [-7],
      userVerification: 'discouraged',
      attachment: 'cross-platform',
    });
    expect(statementSettings(statementOf('aaid:F1D0#0012'))).toBeNull();
  });

  it('keeps the form\'s order and the algorithms it offers, and reads getInfo\'s first while it names one the form offers', () => {
    const statement = {
      protocolFamily: 'fido2',
      authenticatorGetInfo: { algorithms: [{ type: 'public-key', alg: -257 }, null, { type: 'public-key', alg: -48 }, { alg: -999 }] },
      authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    };
    expect(statementSettings(statement)).toEqual({ algorithms: [-48, -257] });

    statement.authenticatorGetInfo.algorithms = [{ alg: -999 }];
    statement.authenticationAlgorithms = [
      'rsassa_pss_sha512_raw', 'ed448_eddsa_sha512_raw', 'secp256k1_ecdsa_sha256_der', 'rsassa_pkcsv15_sha1_raw',
      'rsa_emsa_pkcs1_sha256_der', 'secp521r1_ecdsa_sha512_raw', 'sm2_sm3_raw', '__proto__',
    ];
    expect(statementSettings(statement)).toEqual({ algorithms: [-257, -36, -65535, -47, -39, -53] });
  });

  it('gives the attachment only when the statement says one, and verification only when it lists ways', () => {
    const base = { protocolFamily: 'fido2' };
    expect(statementSettings({ ...base, attachmentHint: ['internal', 'nfc'] })).toBeNull();
    expect(statementSettings({ ...base, attachmentHint: ['ready_on_request'] })).toBeNull();
    expect(statementSettings({ ...base, attachmentHint: ['wifi_direct'] })).toEqual({ attachment: 'cross-platform' });
    expect(statementSettings({ ...base, userVerificationDetails: [[], 'none'] })).toBeNull();
    expect(statementSettings({ ...base, userVerificationDetails: [[{ userVerificationMethod: 'none' }], [null]] })).toEqual({
      userVerification: 'required',
    });
    expect(statementSettings({ ...base, userVerificationDetails: [[{ userVerificationMethod: 'none' }]] })).toEqual({
      userVerification: 'discouraged',
    });
  });

  it('gives nothing for no statement, or one of no family WebAuthn registers', () => {
    expect(statementSettings(null)).toBeNull();
    expect(statementSettings('fido2')).toBeNull();
    expect(statementSettings({ attachmentHint: ['external'] })).toBeNull();
  });
});

describe('TRY_IN_ADVANCED_TEXT', () => {
  it('names the entry the registration was set from', () => {
    expect(TRY_IN_ADVANCED_TEXT.filled('Fixture Security Key L1')).toBe(
      'The Advanced registration now asks for what the metadata of Fixture Security Key L1 says.',
    );
  });
});
