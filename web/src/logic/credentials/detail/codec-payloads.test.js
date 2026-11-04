import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { codecPayloads } from './codec-payloads.js';
import { readSnapshotResponse } from './snapshot-context.js';
import { createRegistrationState } from '../registration/state.js';
import { simpleRecord } from '@/test/logic/credentials/registration-detail-answers.js';
import { repoFile } from '@/test/logic/repo-file.js';

// What a saved credential's details hand the Codec (credentials/detail/codec-payloads.js).

// What an earlier release stored in visitors' browsers: a Simple record and an
// Advanced one with its saved snapshot (web/e2e/recorded/stored-records).
const EARLIER = JSON.parse(readFileSync(repoFile('web/e2e/recorded/stored-records/records.json'), 'utf8')).records;
const earlier = (type) => structuredClone(EARLIER.find((record) => record.type === type));

/** The state with these certificates listed, in this order. */
function listing(...entries) {
  return { ...createRegistrationState(), attestationCertificates: entries, visibleAttestationCertificateIndices: entries.map((_, index) => index) };
}

const NONE = createRegistrationState();

describe('codecPayloads', () => {
  it('gives the browser\'s response the record keeps, and each part as it spells it', () => {
    const record = simpleRecord('packedX5c');
    const payloads = codecPayloads(record, { state: NONE });

    expect(JSON.parse(payloads.response)).toEqual(record.registrationResponse);
    expect(payloads.response).toContain('\n  "response": {');
    expect(payloads.attestationObject).toBe(record.registrationResponse.response.attestationObject);
    expect(payloads.clientDataJSON).toBe(record.registrationResponse.response.clientDataJSON);
    // The response gives none: the record's own, in base64url.
    expect(payloads.authenticatorData).toBe(record.authenticatorData);
    expect(payloads.certificates).toEqual([]);
  });

  it('gives the response\'s own authenticator data first', () => {
    const record = simpleRecord('es256');
    record.registrationResponse.response.authenticatorData = 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQ';
    expect(codecPayloads(record, { state: NONE }).authenticatorData).toBe('SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQ');
  });

  it('reads an earlier release\'s Simple record: its response and its own authenticator data', () => {
    const record = earlier('simple');
    const payloads = codecPayloads(record, { state: NONE });

    expect(payloads.attestationObject).toBe(record.registrationResponse.response.attestationObject);
    expect(payloads.clientDataJSON).toBe(record.registrationResponse.response.clientDataJSON);
    expect(payloads.authenticatorData).toBe(record.authenticatorData);
  });

  it('reads an Advanced record\'s snapshot: its response, and the relying party\'s hex for the authenticator data', () => {
    const record = earlier('advanced');
    const snapshotResponse = readSnapshotResponse(record.registrationDetailSnapshot);
    const payloads = codecPayloads(record, { snapshotResponse, state: NONE });

    expect(JSON.parse(payloads.response)).toEqual(snapshotResponse.credential);
    expect(payloads.attestationObject).toBe(snapshotResponse.credential.response.attestationObject);
    expect(payloads.clientDataJSON).toBe(snapshotResponse.credential.response.clientDataJSON);
    expect(payloads.authenticatorData).toBe(snapshotResponse.relyingParty.authenticatorData);
    expect(payloads.authenticatorData).toMatch(/^[0-9a-f]{258}$/);
  });

  it('reads the hex the relying party\'s registration data keeps last', () => {
    const payloads = codecPayloads({ relyingParty: { registrationData: { authenticatorData: '4996' } } }, { state: NONE });
    expect(payloads.authenticatorData).toBe('4996');
  });

  it('gives the parts of a response kept bare, without a response to decode', () => {
    const payloads = codecPayloads({ registrationResponse: { attestationObject: 'o2Nm', clientDataJSON: 'eyJ0' } }, { state: NONE });
    expect(payloads).toMatchObject({ response: '', attestationObject: 'o2Nm', clientDataJSON: 'eyJ0' });
  });

  it('falls back to the record\'s own fields when the response holds none', () => {
    const payloads = codecPayloads({ registrationResponse: { response: {} }, attestationObject: 'o2Nm', clientDataJSON: 'eyJ0' }, { state: NONE });
    expect(payloads).toMatchObject({ attestationObject: 'o2Nm', clientDataJSON: 'eyJ0', authenticatorData: '' });
  });

  it('gives nothing for a part only a snapshot\'s state keeps, which an earlier release may have cut short', () => {
    const record = earlier('advanced');
    const { response: _kept, ...snapshot } = record.registrationDetailSnapshot;
    const state = { ...createRegistrationState(), authenticatorDataHex: '49960de5880e8c68' };
    const payloads = codecPayloads({ ...record, registrationDetailSnapshot: snapshot }, { snapshotResponse: null, state });

    expect(snapshot.state.detailPreparation.attestationObjectValue).not.toBe('');
    expect(payloads).toEqual({ response: '', attestationObject: '', clientDataJSON: '', authenticatorData: '', certificates: [] });
  });

  it('gives each listed certificate\'s PEM, else its DER in base64, else its hex, and nothing for one without', () => {
    const state = listing(
      { pem: '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----', parsedX5c: { derBase64: 'BB==' } },
      { parsedX5c: { pem: '-----BEGIN CERTIFICATE-----\nCC==\n-----END CERTIFICATE-----' } },
      { parsedX5c: { derBase64: 'MIIB' }, raw: '3082' },
      { derBase64: 'MIIC' },
      { raw: '308201d4' },
      { parsedX5c: { subject: 'CN=Kept without its DER' } },
      { parsedX5c: 'not an object' },
    );
    expect(codecPayloads({}, { state }).certificates).toEqual([
      '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----',
      '-----BEGIN CERTIFICATE-----\nCC==\n-----END CERTIFICATE-----',
      'MIIB',
      'MIIC',
      '308201d4',
      '',
      '',
    ]);
  });

  it('lists the certificates in the details\' order, the ones they show only', () => {
    const state = { ...listing({ raw: '01' }, { raw: '02' }, { raw: '03' }), visibleAttestationCertificateIndices: [2, 0] };
    expect(codecPayloads({}, { state }).certificates).toEqual(['03', '01']);
  });

  it('gives an earlier release\'s snapshot certificate its whole PEM', () => {
    const record = earlier('advanced');
    const { state } = record.registrationDetailSnapshot;
    const payloads = codecPayloads(record, { snapshotResponse: readSnapshotResponse(record.registrationDetailSnapshot), state });
    expect(payloads.certificates).toHaveLength(1);
    expect(payloads.certificates[0]).toMatch(/^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----$/);
  });
});
