import { describe, expect, it } from 'vitest';

import { prepareRegistrationState } from './prepare.js';
import { createRegistrationState } from './state.js';
import { sanitiseAttestationObjectForDisplay } from './sanitize-attestation-object.js';
import { sanitizeParsedCertificateDetails } from './sanitize.js';
import { advancedComplete, goldenDecode, registration } from '@/test/logic/credentials/registration-detail-answers.js';

// The attestation object as the registration view shows it
// (credentials/registration/sanitize-attestation-object.js).

/** The packed x5c registration's state, as the view prepares it from the decoder's answers. */
async function packedState() {
  const entry = registration('packedX5c');
  const state = createRegistrationState();
  await prepareRegistrationState(state, { attestationObjectValue: entry.attestationObject }, { decode: goldenDecode(entry) });
  return state;
}

/** The decoded certificate's details as the view shows them: no encodings, no signature formatting. */
function shownDetails(parsed) {
  const details = sanitizeParsedCertificateDetails(parsed);
  delete details.signature.colon;
  delete details.signature.lines;
  return details;
}

/** An attestation statement's x5c entry as the decoder answers it. */
const decodedEntry = () => registration('packedX5c').attestationDecode.data.attestationObject.attStmt.x5c[0];

describe('sanitiseAttestationObjectForDisplay', () => {
  it('shows the decoded attestation object with each certificate as the view knows it', async () => {
    const state = await packedState();
    const { attStmt } = state.attestationObject;
    expect(sanitiseAttestationObjectForDisplay(state.attestationObject, 'packed', state.attestationCertificates)).toEqual({
      fmt: 'packed',
      attStmt: {
        alg: attStmt.alg,
        sig: attStmt.sig,
        x5c: [{ certificateIndex: 1, details: shownDetails(attStmt.x5c[0].parsedX5c) }],
      },
    });
  });

  it('puts the format first and leaves out the raw bytes', async () => {
    const state = await packedState();
    const shown = sanitiseAttestationObjectForDisplay({ attStmt: {}, ...state.attestationObject }, 'packed', []);
    expect(Object.keys(shown)).toEqual(['fmt', 'attStmt']);
    expect(state.attestationObject.raw).toBeTruthy();
  });

  it('describes each x5c entry by the certificate the view knows at its place', async () => {
    const state = await packedState();
    const certificate = advancedComplete().relyingParty.attestationCertificate;
    const shown = sanitiseAttestationObjectForDisplay(state.attestationObject, 'packed', [{ parsedX5c: certificate }]);
    expect(shown.attStmt.x5c).toMatchObject([{ certificateIndex: 1, details: shownDetails(certificate) }]);
  });

  it("describes the statement's own certificates when the view knows none", async () => {
    const state = await packedState();
    for (const certificates of [[], null]) {
      const shown = sanitiseAttestationObjectForDisplay(state.attestationObject, 'packed', certificates);
      expect(shown.attStmt.x5c).toEqual([{ certificateIndex: 1, details: shownDetails(decodedEntry().parsedX5c) }]);
    }
  });

  it('lists a certificate the statement holds beyond those the view knows', async () => {
    const state = await packedState();
    const attestationObject = { ...state.attestationObject, attStmt: { x5c: [decodedEntry(), decodedEntry()] } };
    const shown = sanitiseAttestationObjectForDisplay(attestationObject, 'packed', state.attestationCertificates);
    expect(shown.attStmt.x5c.map(entry => entry.certificateIndex)).toEqual([1, 2]);
  });

  it('shows the details of a certificate the relying party described', () => {
    const certificate = advancedComplete().relyingParty.attestationCertificate;
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } }, '', [{ parsedX5c: certificate }]);
    expect(shown.attStmt.x5c).toMatchObject([{ certificateIndex: 1, details: shownDetails(certificate) }]);
  });

  it('keeps in the chain a certificate the view knows only by its summary', () => {
    const certificates = [{ parsedX5c: { summary: ' Version: 3 (0x2) ', pem: '-----BEGIN CERTIFICATE-----' } }];
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } }, 'packed', certificates);
    expect(shown.attStmt.x5c).toEqual([{ certificateIndex: 1, summary: 'Version: 3 (0x2)' }]);
  });

  it('shows a certificate with details by its details alone, not its summary as well', () => {
    const certificate = advancedComplete().relyingParty.attestationCertificate;
    expect(certificate.summary).toBeTruthy();
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } }, '', [{ parsedX5c: certificate }]);
    expect(shown.attStmt.x5c).toEqual([{ certificateIndex: 1, details: shownDetails(certificate) }]);
  });

  it('shows the certificates that failed to parse when none parsed', () => {
    const failed = { parsedX5c: { parseError: 'error parsing asn1 value', error: ' Unable to parse the certificate. ', raw: '3082' } };
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } }, 'packed', [failed]);
    expect(shown.attStmt.x5c).toEqual([{
      certificateIndex: 1,
      details: { parseError: 'error parsing asn1 value' },
      error: 'Unable to parse the certificate.',
    }]);
  });

  it('leaves out a certificate with nothing to show, and the x5c left empty', () => {
    const certificates = [{ parsedX5c: { raw: '3082', summary: ' ' } }, { pem: '-----BEGIN CERTIFICATE-----' }];
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { alg: -7, x5c: ['MIIB', 'MIIC'] } }, 'packed', certificates);
    expect(shown).toEqual({ fmt: 'packed', attStmt: { alg: -7 } });
  });

  it('leaves out the x5c when neither the statement nor the view has a certificate', () => {
    const shown = sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt: { alg: -7, x5c: 'MIIB' } }, 'packed', []);
    expect(shown).toEqual({ fmt: 'packed', attStmt: { alg: -7 } });
  });

  it('removes the parse errors, certificate lists, public key hex and signature formatting from the statement', () => {
    const attStmt = {
      x5cParseErrors: ['error parsing asn1 value'],
      attestationCertificates: [],
      PublicKeyBase64: 'pQEC',
      publicKeyHex: 'a501',
      signature: { algorithm: 'ES256', colon: '30:45', lines: ['30:45'] },
    };
    expect(sanitiseAttestationObjectForDisplay({ fmt: 'packed', attStmt }, 'packed', [])).toEqual({
      fmt: 'packed',
      attStmt: { signature: { algorithm: 'ES256' } },
    });
  });

  it('removes summaries, raw bytes, certificate lists, public key hex and signature formatting from the object', () => {
    const attestationObject = {
      fmt: 'none',
      attStmt: 'none',
      summary: 'none attestation',
      raw: 'o2Nm',
      attestationCertificates: [],
      publicKeyHexLines: ['a501'],
      authData: { raw: 'SZYN', rpIdHash: '4996', sig: { colon: '30:45', hex: '3045' } },
    };
    expect(sanitiseAttestationObjectForDisplay(attestationObject, '', [])).toEqual({
      fmt: 'none',
      attStmt: 'none',
      authData: { rpIdHash: '4996', sig: { hex: '3045' } },
    });
  });

  it("puts the given format in place of the object's", () => {
    expect(sanitiseAttestationObjectForDisplay({ fmt: 'none', attStmt: {} }, ' packed ', [])).toEqual({ fmt: 'packed', attStmt: {} });
  });

  it("takes the object's format when none is given", () => {
    expect(sanitiseAttestationObjectForDisplay({ attStmt: {}, fmt: 'none' }, 5, [])).toEqual({ fmt: 'none', attStmt: {} });
  });

  it('leaves the format out when neither gives one', () => {
    expect(sanitiseAttestationObjectForDisplay({ fmt: 7, attStmt: {} }, '', [])).toEqual({ attStmt: {} });
    expect(sanitiseAttestationObjectForDisplay({ attStmt: {} }, '', [])).toEqual({ attStmt: {} });
  });

  it('gives the format alone when there is no attestation object', () => {
    expect(sanitiseAttestationObjectForDisplay(null, ' packed ', [])).toEqual({ fmt: 'packed' });
    expect(sanitiseAttestationObjectForDisplay('o2Nm', 'none', [])).toEqual({ fmt: 'none' });
  });

  it('has nothing to show without an attestation object or a format', () => {
    expect(sanitiseAttestationObjectForDisplay(undefined, '', [])).toBeNull();
    expect(sanitiseAttestationObjectForDisplay(null, 5, [])).toBeNull();
  });

  it('works on a copy', async () => {
    const state = await packedState();
    const before = structuredClone(state.attestationObject);
    sanitiseAttestationObjectForDisplay(state.attestationObject, 'packed', state.attestationCertificates);
    expect(state.attestationObject).toEqual(before);
  });
});
