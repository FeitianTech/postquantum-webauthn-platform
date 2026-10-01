// Real registrations for the registration view's tests: the server's answers as
// the characterization goldens record them (tests/app/characterization, kept
// equal to the server; CHARACTERIZATION_WRITE=1 rewrites them).
import { vi } from 'vitest';

import { goldenAnswers, goldenArtifact } from '../simple/ceremony-answers.js';

// registration-detail-decodes: four Simple registrations (ES256 with AAGUID
// 00112233..., EdDSA, ML-DSA-65, packed with an x5c certificate), then POST
// /api/codec for each stored attestation object, in that order, and for the
// first one's authenticator data.
const DETAIL = 'registration-detail-decodes';
const NAMES = ['es256', 'eddsa', 'mldsa65', 'packedX5c'];

/** One of the four registrations: register-complete's answer, and the decoder's answers for it. */
export function registration(name) {
  const answers = goldenAnswers(DETAIL);
  const index = NAMES.indexOf(name);
  const completes = answers.filter(({ request }) => request.startsWith('POST /api/register/complete'));
  const decodes = answers.filter(({ request }) => request === 'POST /api/codec');
  const complete = structuredClone(completes[index].body);
  return {
    complete,
    storedCredential: complete.storedCredential,
    relyingParty: complete.relyingParty,
    attestationObject: complete.storedCredential.attestationObject,
    authenticatorData: complete.storedCredential.authenticatorData,
    attestationDecode: structuredClone(decodes[index].body),
    authenticatorDataDecode: index === 0 ? structuredClone(decodes[NAMES.length].body) : null,
  };
}

/**
 * A `decode` as the registration view is given one (POST /api/codec): the
 * decoder's recorded answer for a payload the goldens hold, else the refusal a
 * failed request throws.
 */
export function goldenDecode(...registrations) {
  const answers = new Map();
  registrations.forEach((entry) => {
    answers.set(entry.attestationObject, entry.attestationDecode);
    if (entry.authenticatorDataDecode) {
      answers.set(entry.authenticatorData, entry.authenticatorDataDecode);
    }
  });
  return async (payload) => {
    if (!answers.has(payload)) {
      throw new Error('The payload is not valid CBOR.');
    }
    return structuredClone(answers.get(payload));
  };
}

/** The artifact the advanced registration's register-complete wrote (its `payload`). */
export function advancedArtifact() {
  return structuredClone(goldenArtifact('advanced-register-packed-x5c-everything').artifact);
}

/** The advanced registration's register-complete answer. */
export function advancedComplete() {
  const answers = goldenAnswers('advanced-register-packed-x5c-everything');
  return structuredClone(answers.find(({ request }) => request === 'POST /api/advanced/register/complete').body);
}

// The same answers by the names the details' tests use.

/** A Simple registration's register-complete answer, a fresh copy each time. */
export function completeAnswer(name) {
  return registration(name).complete;
}

/** The record a Simple registration saved in the browser, a fresh copy each time. */
export function simpleRecord(name) {
  return registration(name).storedCredential;
}

/** What POST /api/codec answered for a Simple registration's attestation object, a fresh copy. */
export function attestationDecodeAnswer(name) {
  return registration(name).attestationDecode;
}

/** The decoder as the view calls it, answering every recorded payload, as a mock to count its calls. */
export function recordedDecoder() {
  return vi.fn(goldenDecode(...NAMES.map(registration)));
}

/** The advanced registration's register-complete answer, a fresh copy. */
export function advancedCompleteAnswer() {
  return advancedComplete();
}

/** The record the advanced registration saved in the browser (type 'advanced', with its storageId). */
export function advancedRecord() {
  return advancedComplete().storedCredential;
}
