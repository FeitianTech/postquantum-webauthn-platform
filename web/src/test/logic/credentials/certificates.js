// A recorded attestation certificate for the tests of credentials/certificates/.
import { goldenAnswers } from '../simple/ceremony-answers.js';

/** The record register-complete answers for a packed x5c attestation, a fresh copy each time. */
export function savedRecord() {
  const answer = goldenAnswers('simple-register-packed-x5c-extensions').find(({ body }) => body && body.storedCredential);
  return structuredClone(answer.body.storedCredential);
}

/** Its attestation certificate as the server parsed it (derBase64, pem, fingerprints, extensions). */
export const certificate = () => savedRecord().properties.attestationCertificates[0];
