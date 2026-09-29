// Real advanced registrations for the tests of the Advanced tab and its logic: the
// server's answers as the characterization goldens record them (scenario
// advanced-registration-detail-decodes: a none attestation, a packed one with a
// certificate and every extension, an ML-DSA one, each followed by the
// decoder's answer for its attestation object), and the credential the
// authenticator gave for each.
import { goldenAnswers } from '../../simple/ceremony-answers.js';

export const ADVANCED_SCENARIO = 'advanced-registration-detail-decodes';

/** Each registration: its begin and complete answers and the decoder's answer for its attestation object. */
export function advancedRegistrations() {
  const answers = goldenAnswers(ADVANCED_SCENARIO);
  const begins = answers.filter(({ request }) => request.includes('/register/begin'));
  const completes = answers.filter(({ request }) => request.includes('/register/complete'));
  const decodes = answers.filter(({ request }) => request === 'POST /api/codec');
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

// Real advanced authentications (scenario advanced-authentication-answers): two
// credentials the tab registered, the first reporting largeBlob and prf
// support, then authentications of the first.
export const AUTHENTICATION_SCENARIO = 'advanced-authentication-answers';

/**
 * The records the tab keeps for the two registrations (the server's stored
 * credentials: the capable one first), and each authentication's answers:
 * `first` (a first use), `regressed` (a counter lower than the stored one),
 * `refused` (a bad signature, naming the credential), each `{begin, complete}`;
 * and `none`, the begin answered for no stored credential.
 */
export function advancedAuthentications() {
  const answers = goldenAnswers(AUTHENTICATION_SCENARIO);
  const records = answers
    .filter(({ request }) => request.includes('/register/complete'))
    .map(({ body }) => ({ ...body.storedCredential, type: 'advanced' }));
  const begins = answers.filter(({ request }) => request.includes('/authenticate/begin'));
  const completes = answers.filter(({ request }) => request.includes('/authenticate/complete'));
  return {
    records,
    first: { begin: begins[0], complete: completes[0] },
    regressed: { begin: begins[1], complete: completes[1] },
    refused: { begin: begins[2], complete: completes[2] },
    none: begins[3],
  };
}

/**
 * The assertion navigator.credentials.get() gave for a recorded
 * authentication: the credential's id, and client data naming the begin
 * answer's challenge.
 */
export function recordedAssertion({ begin, complete }, extensionResults = {}) {
  const id = complete.body.authenticatedCredentialId ?? complete.body.failedCredentialId;
  const clientData = { type: 'webauthn.get', challenge: begin.body.publicKey.challenge, origin: 'https://localhost' };
  return {
    type: 'public-key',
    id,
    rawId: bytes(id),
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: new TextEncoder().encode(JSON.stringify(clientData)).buffer,
      authenticatorData: new Uint8Array(37).buffer,
      signature: new Uint8Array([0x30, 0x44]).buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => extensionResults,
  };
}
