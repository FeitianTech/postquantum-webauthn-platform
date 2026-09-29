import { describe, expect, it } from 'vitest';

import {
  computeCredentialAaguidMatchStatus,
  deriveCredentialStatusIndicators,
  extractCredentialAttestationContext,
  normaliseAttestationResultValue,
  resolveCredentialAttestationValue,
} from './attestation-context.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

const AAGUID = '00112233445566778899aabbccddeeff';

/** The record register-complete answers for a golden scenario, a fresh copy each time. */
function savedRecord(scenario) {
  const answer = goldenAnswers(scenario).find(({ body }) => body && body.storedCredential);
  return structuredClone(answer.body.storedCredential);
}

const packedX5c = () => savedRecord('simple-register-packed-x5c-extensions');
const advancedPacked = () => savedRecord('advanced-register-packed-x5c-everything');
const noneAttestation = () => savedRecord('simple-register-es256');

describe('extractCredentialAttestationContext', () => {
  it("reads a saved record's summary and checks from its properties", () => {
    const record = packedX5c();
    const context = extractCredentialAttestationContext(record);
    expect(context.attestationSummaryData).toBe(record.properties.attestationSummary);
    expect(context.attestationChecksData).toBe(record.properties.attestationChecks);
  });

  it("prefers the summary and checks at the record's top level", () => {
    const summary = { signatureValid: false };
    const checks = { signature_valid: false };
    const context = extractCredentialAttestationContext({ ...packedX5c(), attestationSummary: summary, attestationChecks: checks });
    expect(context.attestationSummaryData).toBe(summary);
    expect(context.attestationChecksData).toBe(checks);
  });

  it("takes the checks' metadata from the summary when the record keeps no checks", () => {
    const record = advancedPacked();
    const context = extractCredentialAttestationContext(record);
    expect(context.attestationChecksData).toEqual({ metadata: record.properties.attestationSummary.metadata });
  });

  it('has no summary or checks for a record without properties', () => {
    expect(extractCredentialAttestationContext(null)).toEqual({
      propertiesData: {},
      attestationSummaryData: null,
      attestationChecksData: null,
    });
  });
});

describe('resolveCredentialAttestationValue', () => {
  it("answers from the attestation summary first", () => {
    expect(resolveCredentialAttestationValue(packedX5c(), 'signatureValid', 'attestationSignatureValid')).toBe(true);
  });

  it("falls back to the record's properties when the summary lacks the value", () => {
    const record = packedX5c();
    delete record.properties.attestationSummary.signatureValid;
    record.properties.attestationSignatureValid = false;
    expect(resolveCredentialAttestationValue(record, 'signatureValid', 'attestationSignatureValid')).toBe(false);
  });

  it("falls back to the record's own field when its properties lack the value", () => {
    expect(resolveCredentialAttestationValue({ attestationRootValid: true }, 'rootValid', 'attestationRootValid')).toBe(true);
  });

  it('answers null when nothing holds the value', () => {
    expect(resolveCredentialAttestationValue({}, 'rootValid', 'attestationRootValid')).toBeNull();
  });
});

describe('normaliseAttestationResultValue', () => {
  it('keeps booleans, null and undefined as they are', () => {
    expect([true, false, null, undefined].map(normaliseAttestationResultValue)).toEqual([true, false, null, undefined]);
  });

  it('reads 1 and 0 as yes and no, and NaN as unknown', () => {
    expect([1, 0, Number.NaN].map(normaliseAttestationResultValue)).toEqual([true, false, null]);
  });

  it('keeps any other number as it is', () => {
    expect(normaliseAttestationResultValue(2)).toBe(2);
  });

  it('reads words of success and failure in any case and spacing', () => {
    expect([' Passed ', 'OK', 'invalid', 'KO'].map(normaliseAttestationResultValue)).toEqual([true, true, false, false]);
  });

  it('reads the digits 1 and 0 written as text', () => {
    expect(['1', ' 0 '].map(normaliseAttestationResultValue)).toEqual([true, false]);
  });

  it('reads blank text as unknown', () => {
    expect(normaliseAttestationResultValue('   ')).toBeNull();
  });

  it('keeps text it does not recognise', () => {
    expect(normaliseAttestationResultValue('pending')).toBe('pending');
  });

  it('keeps a value that is neither text nor a number', () => {
    const value = { valid: true };
    expect(normaliseAttestationResultValue(value)).toBe(value);
  });
});

describe('computeCredentialAaguidMatchStatus', () => {
  it('has no answer without a record', () => {
    expect(computeCredentialAaguidMatchStatus(null)).toBeNull();
    expect(computeCredentialAaguidMatchStatus('record')).toBeNull();
  });

  it("finds the certificate's AAGUID equal to the authenticator data's", () => {
    expect(computeCredentialAaguidMatchStatus(packedX5c())).toBe(true);
  });

  it('treats null options as none', () => {
    expect(computeCredentialAaguidMatchStatus(packedX5c(), null)).toBe(true);
  });

  it("sees a certificate AAGUID that differs from the authenticator data's", () => {
    expect(computeCredentialAaguidMatchStatus(packedX5c(), { certificateAaguidHex: 'ff'.repeat(16) })).toBe(false);
  });

  it('reads the AAGUID from the certificate entries it is given', () => {
    const certificateEntries = [{ aaguidHex: 'ff'.repeat(16) }];
    expect(computeCredentialAaguidMatchStatus(packedX5c(), { certificateEntries })).toBe(false);
  });

  it('compares with the authenticator data AAGUID it is given', () => {
    expect(computeCredentialAaguidMatchStatus(packedX5c(), { authDataAaguidHex: AAGUID.toUpperCase() })).toBe(true);
  });

  it("falls back to the summary's verdict when the record holds neither AAGUID", () => {
    expect(computeCredentialAaguidMatchStatus(advancedPacked())).toBe(true);
  });

  it('has no answer when the summary recorded no verdict', () => {
    expect(computeCredentialAaguidMatchStatus(noneAttestation())).toBeNull();
  });
});

describe('deriveCredentialStatusIndicators', () => {
  it("gives a packed attestation's four checks", () => {
    const indicators = deriveCredentialStatusIndicators(packedX5c());
    expect(indicators).toMatchObject({
      signatureStatus: true,
      rootStatus: null,
      rpidStatus: true,
      aaguidStatus: true,
      metadataAvailable: false,
      aaguidGuid: '00112233-4455-6677-8899-aabbccddeeff',
    });
  });

  it("gives a 'none' attestation's checks as unknown but its relying party", () => {
    const indicators = deriveCredentialStatusIndicators(noneAttestation());
    expect([indicators.signatureStatus, indicators.rpidStatus, indicators.aaguidStatus]).toEqual([null, true, null]);
  });

  it('says metadata is available when the checks found it', () => {
    const record = packedX5c();
    record.properties.attestationChecks.metadata.available = true;
    expect(deriveCredentialStatusIndicators(record).metadataAvailable).toBe(true);
  });

  it('reads metadata availability written as text', () => {
    expect(deriveCredentialStatusIndicators({ metadata: { available: ' Available ' } }).metadataAvailable).toBe(true);
    expect(deriveCredentialStatusIndicators({ metadata: { available: 'no' } }).metadataAvailable).toBe(false);
  });

  it('has no GUID for an AAGUID that is not sixteen bytes, and gives the stored one as unreadable', () => {
    const indicators = deriveCredentialStatusIndicators({ aaguidHex: 'abcd' });
    expect([indicators.aaguidGuid, indicators.aaguidUnreadable]).toEqual(['', 'abcd']);
  });

  it('reads a record whose stored AAGUID has no base64 length, rather than throwing', () => {
    const indicators = deriveCredentialStatusIndicators({ aaguid: ' abcde ', attestationSummary: { rootValid: true } });
    expect([indicators.aaguidGuid, indicators.aaguidUnreadable, indicators.rootStatus]).toEqual(['', 'abcde', true]);
  });

  it('reads a stored base64url AAGUID made only of hex digits as base64url, the all-zero one included', () => {
    expect(deriveCredentialStatusIndicators({ aaguid: 'AAAAAAAAAAAAAAAAAAAAAA' }).aaguidGuid).toBe('00000000-0000-0000-0000-000000000000');
    expect(deriveCredentialStatusIndicators({ aaguid: '0123456789abcdefABCDEA' }).aaguidGuid).toBe('d35db7e3-9ebb-f3d6-9b71-d79f00108310');
  });

  it('reads a stored AAGUID given as a dashed GUID', () => {
    const indicators = deriveCredentialStatusIndicators({ aaguidGuid: '00112233-4455-6677-8899-AABBCCDDEEFF' });
    expect([indicators.aaguidGuid, indicators.aaguidUnreadable]).toEqual(['00112233-4455-6677-8899-aabbccddeeff', '']);
  });

  it('has nothing unreadable without a stored AAGUID, or with one that is not text', () => {
    expect(deriveCredentialStatusIndicators({}).aaguidUnreadable).toBe('');
    expect(deriveCredentialStatusIndicators({ aaguid: { raw: [1, 2] } }).aaguidUnreadable).toBe('');
  });
});
