// Real advanced registrations for the Advanced tab's tests, in both UIs: the
// server's answers as the characterization goldens record them (scenario
// advanced-registration-detail-decodes: a none attestation, a packed one with a
// certificate and every extension, an ML-DSA one, each followed by the
// decoder's answer for its attestation object), and the credential the
// authenticator gave for each. The new UI's tests import this through
// @legacy-tests.
import { goldenAnswers } from '../../simple/ceremony-answers.js';

export const ADVANCED_SCENARIO = 'advanced-registration-detail-decodes';

/** Each registration: its begin and complete answers and the decoder's answer for its attestation object. */
export function advancedRegistrations() {
  const answers = goldenAnswers(ADVANCED_SCENARIO);
  const begins = answers.filter(({ request }) => request.includes('/register/begin'));
  const completes = answers.filter(({ request }) => request.includes('/register/complete'));
  const decodes = answers.filter(({ request }) => request === 'POST /api/decode');
  return completes.map((complete, index) => ({ begin: begins[index], complete, decode: decodes[index] }));
}

/** The decoder as the server answered the registrations' attestation objects, by the payload asked. */
export function advancedDecodeAnswer(payload) {
  const found = advancedRegistrations().find(({ complete }) => complete.body.relyingParty.attestationObject === payload);
  return found ? found.decode : { status: 422, body: { error: 'The payload is not valid CBOR.' } };
}

const bytes = (base64url) => {
  const data = Buffer.from(base64url, 'base64url');
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
};

/**
 * The credential navigator.credentials.create() gave for a recorded
 * registration: its id and attestation object as the server received them, and
 * client data naming the begin answer's challenge.
 */
export function recordedCredential({ begin, complete }) {
  const clientData = { type: 'webauthn.create', challenge: begin.body.publicKey.challenge, origin: 'https://localhost' };
  return {
    type: 'public-key',
    id: complete.body.storedCredential.credentialIdBase64Url,
    rawId: bytes(complete.body.storedCredential.credentialIdBase64Url),
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: new TextEncoder().encode(JSON.stringify(clientData)).buffer,
      attestationObject: bytes(complete.body.relyingParty.attestationObject),
      getTransports: () => ['usb'],
    },
    getClientExtensionResults: () => ({ credProps: { rk: false } }),
  };
}
