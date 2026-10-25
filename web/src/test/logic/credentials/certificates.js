// Recorded attestation certificates for the tests of credentials/certificates/ and
// the registration view: as a registration keeps one, and as the server serialises
// one whole, the way records from earlier releases kept them.
import { readFileSync } from 'node:fs';

import { repoFile } from '../repo-file.js';
import { goldenAnswers } from '../simple/ceremony-answers.js';

/** The record register-complete answers for a packed x5c attestation, a fresh copy each time. */
export function savedRecord() {
  const answer = goldenAnswers('simple-register-packed-x5c-extensions').find(({ body }) => body && body.storedCredential);
  return structuredClone(answer.body.storedCredential);
}

/** Its attestation certificate as the registration keeps it (derBase64, fingerprints, extensions; no PEM or summary). */
export const certificate = () => savedRecord().properties.attestationCertificates[0];

/**
 * Every certificate the server's characterization serialised whole, by name: with its
 * PEM, its summary and its signature's colon text and lines (serialize_attestation_certificate;
 * tests/app/characterization keeps the file equal to the server).
 */
export function wholeCertificates() {
  return JSON.parse(readFileSync(repoFile('tests/app/characterization/golden/certificates.json'), 'utf8'));
}

/** An attestation leaf serialised whole, as an earlier release kept it in a record. */
export const wholeCertificate = () => wholeCertificates()['generated-attestation-leaf'];
