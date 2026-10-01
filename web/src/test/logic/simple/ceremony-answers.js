// Real ceremonies for the tests of the Simple tab and its logic: the server's
// answers as the characterization goldens record them (tests/app/characterization,
// kept equal to the server; CHARACTERIZATION_WRITE=1 rewrites them), and stand-ins
// for the browser: its PublicKeyCredential's JSON methods and its authenticator.
import { readFileSync } from 'node:fs';

import { repoFile } from '../repo-file.js';

/** The requests a golden scenario records, whole: with the files each one stored. */
export function goldenRequests(scenario) {
  return JSON.parse(readFileSync(repoFile(`tests/app/characterization/golden/routes/${scenario}.json`), 'utf8')).requests;
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

// An ArrayBuffer from either realm the tests run in (Node's TextEncoder gives Node's).
const isArrayBuffer = (value) => Object.prototype.toString.call(value) === '[object ArrayBuffer]';

function base64url(value) {
  const view = isArrayBuffer(value) ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return Buffer.from(view).toString('base64url');
}

// A value as toJSON() writes it: every buffer as base64url, the rest as it is.
function jsonValue(value) {
  if (isArrayBuffer(value) || ArrayBuffer.isView(value)) return base64url(value);
  if (Array.isArray(value)) return value.map(jsonValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonValue(item)]));
  return value;
}

/** What a browser's credential.toJSON() gives: its response's bytes and its extension outputs as base64url. */
export function credentialToJSON(credential) {
  const response = {};
  for (const [key, value] of Object.entries(credential.response)) {
    if (key === 'getTransports') response.transports = value();
    else if (value != null) response[key] = jsonValue(value);
  }
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response,
    clientExtensionResults: jsonValue(credential.getClientExtensionResults()),
  };
}

// Base64url text as the browser's parsers read it: strictly, or a TypeError.
function bytesOf(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new TypeError(`not base64url: ${JSON.stringify(text)}`);
  }
  return new Uint8Array(Buffer.from(text, 'base64url')).buffer;
}

const descriptors = (list) => list?.map((descriptor) => ({ ...descriptor, id: bytesOf(descriptor.id) }));
const evaluation = (inputs) => Object.fromEntries(Object.entries(inputs).map(([name, text]) => [name, bytesOf(text)]));
const defined = (object) => Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined));

// The extension inputs WebAuthn Level 3 spells in base64url, as buffers.
function extensionInputs(extensions) {
  if (!extensions) return extensions;
  const { prf, largeBlob, credBlob } = extensions;
  return defined({
    ...extensions,
    prf: prf && defined({
      ...prf,
      eval: prf.eval && evaluation(prf.eval),
      evalByCredential: prf.evalByCredential
        && Object.fromEntries(Object.entries(prf.evalByCredential).map(([id, inputs]) => [id, evaluation(inputs)])),
    }),
    largeBlob: largeBlob?.write === undefined ? largeBlob : { ...largeBlob, write: bytesOf(largeBlob.write) },
    credBlob: credBlob === undefined ? undefined : bytesOf(credBlob),
  });
}

/** A browser's PublicKeyCredential as far as the ceremonies use it: its two parsers and toJSON(). */
export class StandInPublicKeyCredential {
  static parseCreationOptionsFromJSON(json) {
    return defined({
      ...json,
      challenge: bytesOf(json.challenge),
      user: { ...json.user, id: bytesOf(json.user.id) },
      excludeCredentials: descriptors(json.excludeCredentials),
      extensions: extensionInputs(json.extensions),
    });
  }

  static parseRequestOptionsFromJSON(json) {
    return defined({
      ...json,
      challenge: bytesOf(json.challenge),
      allowCredentials: descriptors(json.allowCredentials),
      extensions: extensionInputs(json.extensions),
    });
  }

  toJSON() {
    return credentialToJSON(this);
  }
}

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
    toJSON() {
      return credentialToJSON(this);
    },
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
    toJSON() {
      return credentialToJSON(this);
    },
  };
}

/**
 * Puts an authenticator in the browser: navigator.credentials.create and get,
 * each answering what it is given (a value, or a function of the options), and
 * the browser's PublicKeyCredential with its JSON methods. Gives the two mocks
 * and a function that takes both away.
 */
export function installAuthenticator(vi, { create = createdCredential(), get = assertion() } = {}) {
  const answer = (value) => (options) => (typeof value === 'function' ? value(options) : Promise.resolve(value));
  const credentials = { create: vi.fn(answer(create)), get: vi.fn(answer(get)) };
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
  Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, writable: true, value: StandInPublicKeyCredential });
  return {
    ...credentials,
    remove: () => {
      delete navigator.credentials;
      delete globalThis.PublicKeyCredential;
    },
  };
}
