// Real ceremonies for the Simple tab's tests, in both UIs: the server's answers
// as the characterization goldens record them (tests/app/characterization, kept
// equal to the server; CHARACTERIZATION_WRITE=1 rewrites them), and a stand-in
// for the browser's authenticator that gives what the WebAuthn ponyfill reads.
// The new UI's tests import this through @legacy-tests.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The requests a golden scenario records, whole: with the files each one stored. */
export function goldenRequests(scenario) {
  // Not new URL(…, import.meta.url): Vite rewrites that form into an asset URL.
  const path = join(import.meta.dirname, '..', '..', 'app', 'characterization', 'golden', 'routes', `${scenario}.json`);
  return JSON.parse(readFileSync(path, 'utf8')).requests;
}

/** The requests a golden scenario records: each its request line, status and answer. */
export function goldenAnswers(scenario) {
  return goldenRequests(scenario).map(({ request, status, body }) => ({ request, status, body }));
}

/** The artifact the server stored for a golden advanced registration, as GET …/credential-artifacts/<id> answers it. */
export function goldenArtifact(scenario) {
  const complete = goldenRequests(scenario).find(({ request, status }) => request.includes('/register/complete') && status === 200);
  const { content } = complete.stored.find(({ file }) => file.startsWith('artifacts/'));
  return { storageId: content.storageId, artifact: content.payload };
}

/** An answer as the browser receives it: JSON, or the recorded page for a non-JSON one. */
export function answerResponse({ status, body }) {
  if (body && typeof body === 'object' && '$text' in body) {
    return new Response(body.$text, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function buffer(bytes) {
  return new Uint8Array(bytes).buffer;
}

const encoder = new TextEncoder();

/** A registration's credential, as navigator.credentials.create() gives it. */
export function createdCredential(id = [1, 2, 3, 4]) {
  return {
    type: 'public-key',
    id: 'AQIDBA',
    rawId: buffer(id),
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: encoder.encode('{"type":"webauthn.create"}').buffer,
      attestationObject: buffer([0xa0]),
      getTransports: () => ['usb'],
    },
    getClientExtensionResults: () => ({}),
  };
}

/** An authentication's assertion, as navigator.credentials.get() gives it. */
export function assertion(id = [1, 2, 3, 4]) {
  return {
    type: 'public-key',
    id: 'AQIDBA',
    rawId: buffer(id),
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: encoder.encode('{"type":"webauthn.get"}').buffer,
      authenticatorData: buffer([0x49, 0x96]),
      signature: buffer([0x30, 0x44]),
      userHandle: buffer([0x75]),
    },
    getClientExtensionResults: () => ({}),
  };
}

/**
 * Puts an authenticator in the browser: navigator.credentials.create and get,
 * each answering what it is given (a value, or a function of the options).
 * Gives the two mocks and a function that takes the authenticator away.
 */
export function installAuthenticator(vi, { create = createdCredential(), get = assertion() } = {}) {
  const answer = (value) => (options) => (typeof value === 'function' ? value(options) : Promise.resolve(value));
  const credentials = { create: vi.fn(answer(create)), get: vi.fn(answer(get)) };
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
  return {
    ...credentials,
    remove: () => {
      delete navigator.credentials;
    },
  };
}
