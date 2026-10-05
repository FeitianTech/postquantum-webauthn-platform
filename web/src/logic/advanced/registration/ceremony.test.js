// The Advanced tab's registration with no DOM (advanced/registration/ceremony.js), over the server's recorded answers.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ADVANCED_CEREMONY_TEXT,
  advancedRegisteredMessage,
  advancedRegistrationFailureText,
  collectPotentialUnsupportedFeatures,
  readCreationRequest,
  registerAdvancedCredential,
  registeredRecord,
} from './ceremony.js';
import {
  applyAuthenticatorAttachmentPreference,
  enforceAuthenticatorAttachmentWithHints,
} from '../hints.js';
import { FailedResponseError } from '../../shared/failed-response.js';
import { UPDATE_BROWSER_TEXT } from '../../shared/native-json.js';
import {
  StandInPublicKeyCredential,
  answerResponse,
  goldenAnswers,
  installAuthenticator,
} from '@/test/logic/simple/ceremony-answers.js';
import { advancedRegistrations, recordedCredential } from '@/test/logic/advanced/advanced-answers.js';

// The hints' rules, real, and watched.
vi.mock('../hints.js', async (importOriginal) => {
  const real = await importOriginal();
  return {
    ...real,
    enforceAuthenticatorAttachmentWithHints: vi.fn(real.enforceAuthenticatorAttachmentWithHints),
    applyAuthenticatorAttachmentPreference: vi.fn(real.applyAuthenticatorAttachmentPreference),
  };
});

const BEGIN = '/api/advanced/register/begin';
const COMPLETE = '/api/advanced/register/complete';

// The three recorded registrations: a none attestation (ES256), a packed one
// with a certificate and every extension, and an ML-DSA-44 one.
const [NONE, EVERYTHING, MLDSA] = advancedRegistrations();
// Begin answers naming the PQC algorithms the server skipped, with warnings.
const PQC_UNAVAILABLE = goldenAnswers('advanced-register-begin-pqc-unavailable');
// Completes the server refused, each after its begin.
const COMPLETE_FAILURES = goldenAnswers('advanced-register-complete-failures');
// Begins the server refused.
const BEGIN_FAILURES = goldenAnswers('advanced-register-begin-failures');
// A request hinting client-device: its begin, then completes with no attachment and with a platform one.
const ATTACHMENT_HINTS = goldenAnswers('advanced-register-attachment-hints');

const CHALLENGE = { $base64url: 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE' };

/** The request the recorded registrations sent (the characterization's _options()), with `overrides` in publicKey. */
function request(overrides = {}) {
  return {
    publicKey: {
      rp: { id: 'localhost', name: 'Demo server' },
      user: { id: '757365722d68616e646c65', name: 'user@example.com', displayName: 'A. User' },
      challenge: CHALLENGE,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      ...overrides,
    },
  };
}

/** Every extension the packed registration's request asked for (the characterization's EVERY_EXTENSION). */
const EVERY_EXTENSION = {
  credProps: true,
  minPinLength: true,
  credentialProtectionPolicy: 'userVerificationOptionalWithCredentialIDList',
  enforceCredentialProtectionPolicy: true,
  largeBlob: { support: 'preferred' },
  prf: { eval: { first: { $base64url: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' }, second: '0a0b0c' } },
  credBlob: { $base64url: 'YmxvYg' },
  hmacCreateSecret: true,
};

const EVERYTHING_REQUEST = request({
  authenticatorSelection: { residentKey: 'preferred', authenticatorAttachment: 'cross-platform' },
  extensions: EVERY_EXTENSION,
});

const text = (value) => JSON.stringify(value);
const base64url = (value) => Buffer.from(value).toString('base64url');
const hex = (buffer) => Buffer.from(buffer).toString('hex');

let fetch;
let authenticator;

/** The server: each path answers its recorded answer. */
function serving(answers) {
  fetch = vi.fn(async (url) => {
    if (!(url in answers)) {
      throw new Error(`Nothing answers ${url}`);
    }
    return answerResponse(answers[url]);
  });
  vi.stubGlobal('fetch', fetch);
}

function sent(call) {
  const [url, init] = fetch.mock.calls[call];
  return { url, init, body: JSON.parse(init.body) };
}

/** The paths the ceremony asked the server, in order. */
const asked = () => fetch.mock.calls.map(([url]) => url);

/** What the form's views give the ceremony: the switch off, and where it says what it does. */
function formOptions(overrides = {}) {
  return {
    minPinLength: vi.fn(() => false),
    onStart: vi.fn(),
    onProgress: vi.fn(),
    onWarning: vi.fn(),
    onResult: vi.fn(),
    ...overrides,
  };
}

/** The authenticator gives `credential` (the recorded one for a registration by default). */
function authenticatorGiving(credential) {
  authenticator.remove();
  authenticator = installAuthenticator(vi, { create: credential });
}

/** The credential JSON the server is sent for a recorded registration's credential. */
function sentCredential({ begin, complete }) {
  const clientData = { type: 'webauthn.create', challenge: begin.body.publicKey.challenge, origin: 'https://localhost' };
  return {
    type: 'public-key',
    id: complete.body.storedCredential.credentialIdBase64Url,
    rawId: complete.body.storedCredential.credentialIdBase64Url,
    authenticatorAttachment: 'cross-platform',
    response: {
      clientDataJSON: base64url(JSON.stringify(clientData)),
      attestationObject: complete.body.relyingParty.attestationObject,
      transports: ['usb'],
    },
    clientExtensionResults: { credProps: { rk: false } },
  };
}

beforeEach(() => {
  authenticator = installAuthenticator(vi, { create: recordedCredential(NONE) });
});

afterEach(() => {
  authenticator.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('readCreationRequest', () => {
  it('gives the object the editor\'s text parses to', () => {
    expect(readCreationRequest(text(EVERYTHING_REQUEST))).toEqual(EVERYTHING_REQUEST);
  });

  it('throws the parser\'s error for text that is not JSON', () => {
    expect(() => readCreationRequest('{"publicKey":')).toThrow(SyntaxError);
  });

  it('says the request lacks publicKey', () => {
    expect(() => readCreationRequest(text({ rp: {} }))).toThrow('Invalid JSON structure: Missing "publicKey" property');
    expect(() => readCreationRequest(text({ publicKey: null }))).toThrow(ADVANCED_CEREMONY_TEXT.missingPublicKey);
  });

  it('says publicKey lacks rp, user or challenge, in that order', () => {
    const { rp, user, challenge, ...rest } = request().publicKey;
    expect(() => readCreationRequest(text({ publicKey: rest }))).toThrow('Invalid CredentialCreationOptions: Missing required "rp" property');
    expect(() => readCreationRequest(text({ publicKey: { ...rest, rp } }))).toThrow('Invalid CredentialCreationOptions: Missing required "user" property');
    expect(() => readCreationRequest(text({ publicKey: { ...rest, rp, user } }))).toThrow('Invalid CredentialCreationOptions: Missing required "challenge" property');
    expect(readCreationRequest(text({ publicKey: { ...rest, rp, user, challenge } }))).toEqual(request());
  });
});

describe('advancedRegisteredMessage', () => {
  it('names the algorithm the server registered, as a success', () => {
    expect(advancedRegisteredMessage(NONE.complete.body)).toEqual({
      text: 'Advanced registration successful! Algorithm: ES256 (ECDSA)',
      tone: 'success',
    });
  });

  it('adds the server\'s warnings, as a warning', () => {
    expect([EVERYTHING.complete.body.warnings, MLDSA.complete.body.warnings]).toEqual([['metadata_not_available'], ['metadata_not_available']]);
    expect(advancedRegisteredMessage(EVERYTHING.complete.body)).toEqual({
      text: 'Advanced registration successful! Algorithm: ES256 (ECDSA) metadata_not_available',
      tone: 'warning',
    });
    expect(advancedRegisteredMessage(MLDSA.complete.body)).toEqual({
      text: 'Advanced registration successful! Algorithm: ML-DSA-44 (PQC) metadata_not_available',
      tone: 'warning',
    });
  });

  it('says the algorithm is unknown when the answer names none', () => {
    const { algo, ...answer } = NONE.complete.body;
    expect(advancedRegisteredMessage(answer).text).toBe('Advanced registration successful! Algorithm: Unknown');
  });

  it('leaves out warnings that are not text or are blank, and warnings that are not a list', () => {
    const answer = { ...EVERYTHING.complete.body, warnings: ['  ', 7, null, 'metadata_not_available'] };
    expect(advancedRegisteredMessage(answer).text).toBe('Advanced registration successful! Algorithm: ES256 (ECDSA) metadata_not_available');
    expect(advancedRegisteredMessage({ ...answer, warnings: [' ', 0] }).tone).toBe('success');
    expect(advancedRegisteredMessage({ ...answer, warnings: 'metadata_not_available' }).tone).toBe('success');
  });
});

describe('registeredRecord', () => {
  const credential = () => recordedCredential(NONE);
  const answer = () => structuredClone(NONE.complete.body);
  const { publicKey } = request();

  it('is the stored credential with the browser\'s ID, in base64url and hex, and the user\'s name', () => {
    const stored = answer().storedCredential;
    expect(registeredRecord(answer(), credential(), publicKey)).toEqual({
      ...stored,
      id: stored.credentialIdBase64Url,
      credentialId: stored.credentialIdBase64Url,
      credentialIdBase64Url: stored.credentialIdBase64Url,
      credentialIdHex: stored.credentialIdHex,
      userName: 'user@example.com',
    });
  });

  it('is none when the server stored nothing', () => {
    const { storedCredential, ...unstored } = answer();
    expect(registeredRecord(unstored, credential(), publicKey)).toBeNull();
    expect(registeredRecord({ ...unstored, storedCredential: 'stored' }, credential(), publicKey)).toBeNull();
  });

  it('takes the browser\'s ID trimmed, and its raw ID\'s bytes from a view as well as a buffer', () => {
    const given = { id: '  AQIDBA  ', rawId: new Uint8Array([9, 1, 2, 3, 4]).subarray(1) };
    const record = registeredRecord(answer(), given, publicKey);
    expect([record.id, record.credentialId, record.credentialIdBase64Url, record.credentialIdHex]).toEqual([
      'AQIDBA', 'AQIDBA', 'AQIDBA', '01020304',
    ]);
  });

  it('falls back on the stored base64url ID, then the stored ID, when the browser\'s is blank or not text', () => {
    const stored = answer().storedCredential;
    const { credentialIdBase64Url, ...withoutBase64Url } = answer().storedCredential;
    expect(registeredRecord(answer(), { id: '   ' }, publicKey).credentialIdBase64Url).toBe(stored.credentialIdBase64Url);
    const record = registeredRecord({ storedCredential: { ...withoutBase64Url, credentialId: 'c3RvcmVk' } }, { id: 7 }, publicKey);
    expect([record.id, record.credentialId, record.credentialIdBase64Url]).toEqual(['c3RvcmVk', 'c3RvcmVk', 'c3RvcmVk']);
  });

  it('keeps the stored ID and credential ID when no ID is known anywhere', () => {
    const { credentialIdBase64Url, credentialId, ...stored } = answer().storedCredential;
    const record = registeredRecord({ storedCredential: { ...stored, id: 'record-id' } }, {}, publicKey);
    expect([record.id, record.credentialId, record.credentialIdBase64Url]).toEqual(['record-id', undefined, '']);
  });

  it('keeps the stored hex ID when the raw ID is not bytes or holds none', () => {
    const stored = answer().storedCredential;
    expect(registeredRecord(answer(), { rawId: stored.credentialIdBase64Url }, publicKey).credentialIdHex).toBe(stored.credentialIdHex);
    expect(registeredRecord(answer(), { rawId: new ArrayBuffer(0) }, publicKey).credentialIdHex).toBe(stored.credentialIdHex);
  });

  it('names the user from the request when the server stored no name, else no one', () => {
    const { userName, ...stored } = answer().storedCredential;
    const nameless = { storedCredential: stored };
    expect(registeredRecord(nameless, credential(), { user: { name: 'alice' } }).userName).toBe('alice');
    expect(registeredRecord(nameless, credential(), {}).userName).toBe('');
    expect(registeredRecord(nameless, credential(), undefined).userName).toBe('');
  });
});

describe('collectPotentialUnsupportedFeatures', () => {
  // The options the authenticator is given for a recorded begin answer, as the browser reads them.
  const beginOptions = (begin) => ({ publicKey: StandInPublicKeyCredential.parseCreationOptionsFromJSON(begin.body.publicKey) });

  it('names nothing for a request that is not an object', () => {
    expect(collectPotentialUnsupportedFeatures(null, beginOptions(MLDSA.begin))).toEqual([]);
    expect(collectPotentialUnsupportedFeatures('publicKey', beginOptions(MLDSA.begin))).toEqual([]);
  });

  it('names nothing an authenticator commonly supports', () => {
    expect(collectPotentialUnsupportedFeatures(request().publicKey, beginOptions(NONE.begin))).toEqual([]);
  });

  it('names a required resident key, by either spelling, and required user verification', () => {
    const required = { authenticatorSelection: { residentKey: 'required', userVerification: 'required' } };
    const legacy = { authenticatorSelection: { requireResidentKey: true } };
    expect(collectPotentialUnsupportedFeatures(required)).toEqual(['resident key requirement', 'user verification requirement']);
    expect(collectPotentialUnsupportedFeatures(legacy)).toEqual(['resident key requirement']);
  });

  it('reads an authenticator selection that is not an object as none', () => {
    expect(collectPotentialUnsupportedFeatures({ authenticatorSelection: 'not-a-mapping' })).toEqual([]);
  });

  it('names each extension the request, then the options the browser was given, hold, once and in the labels\' order', () => {
    expect(collectPotentialUnsupportedFeatures({ extensions: { credProps: true, prf: {} } }, beginOptions(EVERYTHING.begin))).toEqual([
      'prf extension',
      'credProps extension',
      'largeBlob extension',
      'minPinLength extension',
      'credProtect extension',
    ]);
  });

  it('reads extensions that are not an object as none', () => {
    expect(collectPotentialUnsupportedFeatures({ extensions: 'largeBlob' }, { publicKey: { extensions: 'prf' } })).toEqual([]);
  });

  it('names the signature algorithms when none the options offer is commonly supported', () => {
    expect(collectPotentialUnsupportedFeatures({}, beginOptions(MLDSA.begin))).toEqual(['selected signature algorithms']);
    expect(collectPotentialUnsupportedFeatures({}, beginOptions(PQC_UNAVAILABLE[1]))).toEqual([]);
  });

  it('reads only the numeric algorithms of the parameters that are objects', () => {
    const options = (pubKeyCredParams) => ({ publicKey: { pubKeyCredParams } });
    expect(collectPotentialUnsupportedFeatures({}, options(['ES384', null, { alg: 'ES256' }, { alg: -48 }]))).toEqual([
      'selected signature algorithms',
    ]);
    expect(collectPotentialUnsupportedFeatures({}, options(['ES384', { alg: 'not-a-number' }]))).toEqual([]);
    expect(collectPotentialUnsupportedFeatures({}, options([]))).toEqual([]);
  });

  it('reads options without parameters as offering no algorithm', () => {
    expect(collectPotentialUnsupportedFeatures({}, 'options')).toEqual([]);
    expect(collectPotentialUnsupportedFeatures({}, { publicKey: null })).toEqual([]);
    expect(collectPotentialUnsupportedFeatures({}, { publicKey: { pubKeyCredParams: { alg: -48 } } })).toEqual([]);
  });
});

describe('advancedRegistrationFailureText', () => {
  const context = { publicKey: { authenticatorSelection: { residentKey: 'required' } } };

  it('says the browser\'s refusals by name', () => {
    expect([
      advancedRegistrationFailureText(new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')),
      advancedRegistrationFailureText(new DOMException('The authenticator was previously registered.', 'InvalidStateError')),
      advancedRegistrationFailureText(new DOMException('This is an invalid domain.', 'SecurityError')),
    ]).toEqual([
      'Credential registration failed: User cancelled or authenticator not available',
      'Credential registration failed: Authenticator is already registered for this account',
      'Credential registration failed: Security error - check your connection and try again',
    ]);
  });

  it('says what the request asked that the authenticator may not support, when the authenticator refused', () => {
    expect(advancedRegistrationFailureText(new DOMException('The operation failed for an unknown transient reason', 'UnknownError'), context)).toBe(
      'Credential registration failed: The operation failed for an unknown transient reason The authenticator may not support: resident key requirement.',
    );
  });

  it('says nothing of what the authenticator supports when the refusal was not the authenticator\'s', () => {
    expect(advancedRegistrationFailureText(new DOMException('This is an invalid domain.', 'SecurityError'), context)).toBe(
      'Credential registration failed: Security error - check your connection and try again',
    );
    const failure = new FailedResponseError({ text: 'Username is required in user.name' });
    expect(advancedRegistrationFailureText(failure, context)).toBe('Credential registration failed: Username is required in user.name');
  });

  it('says anything else thrown as text', () => {
    expect([
      advancedRegistrationFailureText('The editor is empty'),
      advancedRegistrationFailureText(null),
      advancedRegistrationFailureText({ name: 'NotAllowedError', message: 42 }),
      advancedRegistrationFailureText({ reason: 'nothing' }),
    ]).toEqual([
      'Credential registration failed: The editor is empty',
      'Credential registration failed: null',
      'Credential registration failed: User cancelled or authenticator not available',
      'Credential registration failed: [object Object]',
    ]);
  });
});

describe('registerAdvancedCredential', () => {
  it('asks the server to begin with the request, the authenticator with the options it answered, then the server to complete', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    const outcome = await registerAdvancedCredential(text(request()), formOptions());

    expect(outcome.registered).toBe(true);
    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(0).init).toMatchObject({ method: 'POST', headers: { 'Content-Type': 'application/json' } });
    expect(sent(0).body).toEqual(request());
    expect(authenticator.create).toHaveBeenCalledTimes(1);
    expect(sent(1).init).toMatchObject({ method: 'POST', headers: { 'Content-Type': 'application/json' } });
    expect(fetch.mock.invocationCallOrder[0]).toBeLessThan(authenticator.create.mock.invocationCallOrder[0]);
    expect(authenticator.create.mock.invocationCallOrder[0]).toBeLessThan(fetch.mock.invocationCallOrder[1]);
  });

  it('completes with the request and the credential as JSON', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    await registerAdvancedCredential(text(request()), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(1).body).toEqual({
      ...request(),
      __credential_response: sentCredential(NONE),
    });
  });

  it('gives the server\'s answer, the credential, its JSON, the request\'s publicKey and the record to keep', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    const outcome = await registerAdvancedCredential(text(request()), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    const stored = NONE.complete.body.storedCredential;
    expect(outcome).toEqual({
      registered: true,
      answer: NONE.complete.body,
      credential: await authenticator.create.mock.results[0].value,
      credentialJson: sentCredential(NONE),
      publicKey: request().publicKey,
      record: {
        ...stored,
        id: stored.credentialIdBase64Url,
        credentialId: stored.credentialIdBase64Url,
        credentialIdBase64Url: stored.credentialIdBase64Url,
        credentialIdHex: stored.credentialIdHex,
        userName: 'user@example.com',
      },
    });
    expect(outcome.credential.id).toBe(stored.credentialIdBase64Url);
  });

  it('says it has started once the request is checked, then each step as it starts', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    const options = formOptions();
    await registerAdvancedCredential(text(request()), options);

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(options.onStart).toHaveBeenCalledTimes(1);
    expect(options.onStart.mock.invocationCallOrder[0]).toBeLessThan(options.onProgress.mock.invocationCallOrder[0]);
    expect(options.onStart.mock.invocationCallOrder[0]).toBeLessThan(fetch.mock.invocationCallOrder[0]);
    expect(options.onProgress.mock.calls.map(([step]) => step)).toEqual([
      'Starting advanced registration...',
      'Connecting your authenticator device...',
      'Completing registration...',
    ]);
    expect(options.onWarning).not.toHaveBeenCalled();
  });

  it('gives the result panel the challenge\'s source and status the server answered', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    const options = formOptions();
    await registerAdvancedCredential(text(request()), options);

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(options.onResult).toHaveBeenCalledTimes(1);
    expect(options.onResult.mock.invocationCallOrder[0]).toBeGreaterThan(fetch.mock.invocationCallOrder[1]);
    expect(options.onResult).toHaveBeenCalledWith({
      title: 'Last registration',
      showChallenge: true,
      challengeSource: 'server-session',
      challengeStatus: 'fresh',
    });
  });

  it('hands the authenticator the server\'s options, their bytes as buffers', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    await registerAdvancedCredential(text(request()), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    const [options] = authenticator.create.mock.calls[0];
    const answered = NONE.begin.body.publicKey;
    expect(Object.keys(options)).toEqual(['publicKey']);
    expect(options.publicKey).toMatchObject({ rp: answered.rp, pubKeyCredParams: answered.pubKeyCredParams, attestation: 'none' });
    expect(options.publicKey.challenge).toBeInstanceOf(ArrayBuffer);
    expect(base64url(options.publicKey.challenge)).toBe(answered.challenge);
    expect(base64url(options.publicKey.user.id)).toBe(answered.user.id);
  });

  it('hands the authenticator every extension the server answered, their bytes as buffers', async () => {
    authenticatorGiving(recordedCredential(EVERYTHING));
    serving({ [BEGIN]: EVERYTHING.begin, [COMPLETE]: EVERYTHING.complete });
    await registerAdvancedCredential(text(EVERYTHING_REQUEST), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(0).body).toEqual(EVERYTHING_REQUEST);
    const { extensions } = authenticator.create.mock.calls[0][0].publicKey;
    expect(extensions).toEqual({
      credBlob: expect.any(ArrayBuffer),
      credProps: true,
      credentialProtectionPolicy: 'userVerificationOptionalWithCredentialIDList',
      enforceCredentialProtectionPolicy: true,
      hmacCreateSecret: true,
      largeBlob: { support: 'preferred' },
      minPinLength: true,
      prf: { eval: { first: expect.any(ArrayBuffer), second: expect.any(ArrayBuffer) } },
    });
    expect([hex(extensions.prf.eval.first), hex(extensions.prf.eval.second)]).toEqual(['07'.repeat(32), '0a0b0c']);
    expect(Buffer.from(extensions.credBlob).toString()).toBe('blob');
  });

  it('gives the attachment preference the hints\' attachments and both publicKeys, and the authenticator the attachment it chose', async () => {
    const hinted = request({ hints: ['client-device'] });
    authenticatorGiving({ ...recordedCredential(NONE), authenticatorAttachment: 'platform' });
    serving({ [BEGIN]: ATTACHMENT_HINTS[4], [COMPLETE]: ATTACHMENT_HINTS[5] });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(hinted), options);

    expect(outcome.registered).toBe(true);
    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(0).body).toEqual(hinted);
    expect(enforceAuthenticatorAttachmentWithHints).toHaveBeenCalledWith(hinted.publicKey);
    expect(enforceAuthenticatorAttachmentWithHints).toHaveReturnedWith(['platform']);
    const createOptions = authenticator.create.mock.calls[0][0];
    expect(applyAuthenticatorAttachmentPreference).toHaveBeenCalledWith(createOptions, ['platform'], ATTACHMENT_HINTS[4].body.publicKey, hinted.publicKey);
    expect(createOptions.publicKey.authenticatorSelection.authenticatorAttachment).toBe('platform');
    expect(sent(1).body.__credential_response.authenticatorAttachment).toBe('platform');
  });

  it('warns with the server\'s warnings about the request, joined, and hands the authenticator none of them', async () => {
    // The first recorded answer's warning, then the second's: two warnings in one answer.
    const [, first, second] = PQC_UNAVAILABLE;
    const warned = { ...first, body: { ...first.body, warnings: [...first.body.warnings, ...second.body.warnings] } };
    serving({ [BEGIN]: warned, [COMPLETE]: NONE.complete });
    const options = formOptions();
    const pqc = [{ type: 'public-key', alg: -48 }, { type: 'public-key', alg: -49 }];
    await registerAdvancedCredential(text(request({ pubKeyCredParams: pqc })), options);

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(0).body.publicKey.pubKeyCredParams).toEqual(pqc);
    expect(options.onWarning).toHaveBeenCalledTimes(1);
    expect(options.onWarning).toHaveBeenCalledWith(
      'Unsupported PQC algorithms were skipped (ML-DSA-87). Unsupported PQC algorithms were skipped (ML-DSA-87, ML-DSA-65, ML-DSA-44).',
    );
    expect(authenticator.create.mock.calls[0][0]).not.toHaveProperty('warnings');
  });

  it('adds minPinLength to the request\'s extensions when the switch is on', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    const outcome = await registerAdvancedCredential(text(request({ extensions: { credProps: true } })), formOptions({ minPinLength: () => true }));

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(0).body.publicKey.extensions).toEqual({ credProps: true, minPinLength: true });
    expect(sent(1).body.publicKey.extensions).toEqual({ credProps: true, minPinLength: true });
    expect(outcome.publicKey.extensions).toEqual({ credProps: true, minPinLength: true });
  });

  it('gives a request whose extensions are not an object extensions holding minPinLength when the switch is on', async () => {
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    await registerAdvancedCredential(text(request()), formOptions({ minPinLength: () => true }));
    await registerAdvancedCredential(text(request({ extensions: 'none' })), formOptions({ minPinLength: () => true }));

    expect(asked()).toEqual([BEGIN, COMPLETE, BEGIN, COMPLETE]);
    expect([sent(0).body.publicKey.extensions, sent(2).body.publicKey.extensions]).toEqual([{ minPinLength: true }, { minPinLength: true }]);
  });

  it('sends a null attachment when the browser names none, which the server refuses for a hinted request', async () => {
    const { authenticatorAttachment, ...unattached } = recordedCredential(NONE);
    authenticatorGiving(unattached);
    serving({ [BEGIN]: ATTACHMENT_HINTS[0], [COMPLETE]: ATTACHMENT_HINTS[1] });
    const outcome = await registerAdvancedCredential(text(request({ hints: ['client-device'] })), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(1).body.__credential_response).toHaveProperty('authenticatorAttachment', null);
    expect(outcome.text).toBe('Credential registration failed: Authenticator attachment could not be determined to enforce selected hints.');
  });

  it('sends every extension result as the browser\'s JSON writes it, bytes in base64url', async () => {
    const results = { credProps: { rk: false }, prf: { enabled: true, results: { first: new Uint8Array([7, 7, 7]).buffer } } };
    authenticatorGiving({ ...recordedCredential(EVERYTHING), getClientExtensionResults: () => results });
    serving({ [BEGIN]: EVERYTHING.begin, [COMPLETE]: EVERYTHING.complete });
    await registerAdvancedCredential(text(EVERYTHING_REQUEST), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(1).body.__credential_response.clientExtensionResults).toEqual({
      credProps: { rk: false },
      prf: { enabled: true, results: { first: 'BwcH' } },
    });
  });

  it('sends no extension results when the browser gives none', async () => {
    authenticatorGiving({ ...recordedCredential(NONE), getClientExtensionResults: () => ({}) });
    serving({ [BEGIN]: NONE.begin, [COMPLETE]: NONE.complete });
    await registerAdvancedCredential(text(request()), formOptions());

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(sent(1).body.__credential_response.clientExtensionResults).toEqual({});
  });

  it('registers without being told where to say its steps', async () => {
    serving({ [BEGIN]: PQC_UNAVAILABLE[1], [COMPLETE]: NONE.complete });
    const { onStart, onProgress, onWarning, onResult, ...silent } = formOptions();
    const outcome = await registerAdvancedCredential(text(request()), silent);

    expect(outcome.registered).toBe(true);
    expect(asked()).toEqual([BEGIN, COMPLETE]);
  });

  it('says text that is not JSON as the parser does, and asks nothing', async () => {
    serving({});
    const options = formOptions();
    const outcome = await registerAdvancedCredential('{"publicKey":', options);

    let parserError;
    try {
      JSON.parse('{"publicKey":');
    } catch (error) {
      parserError = error.message;
    }
    expect(outcome).toEqual({
      registered: false,
      text: `Credential registration failed: ${parserError}`,
      context: { publicKey: null, createOptions: null },
    });
    expect(asked()).toEqual([]);
    expect(options.onStart).not.toHaveBeenCalled();
  });

  it('asks nothing in a browser without WebAuthn\'s JSON methods, and says to update it', async () => {
    serving({});
    delete globalThis.PublicKeyCredential;
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(request()), options);

    expect(outcome).toMatchObject({ registered: false, text: `Credential registration failed: ${UPDATE_BROWSER_TEXT}` });
    expect(asked()).toEqual([]);
    expect(options.onStart).not.toHaveBeenCalled();
    expect(authenticator.create).not.toHaveBeenCalled();
  });

  it('says what the request lacks, and asks nothing', async () => {
    serving({});
    const { rp, ...rpless } = request().publicKey;
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text({ publicKey: rpless }), options);

    expect(outcome.text).toBe('Credential registration failed: Invalid CredentialCreationOptions: Missing required "rp" property');
    expect(asked()).toEqual([]);
    expect(enforceAuthenticatorAttachmentWithHints).not.toHaveBeenCalled();
    expect(options.onStart).not.toHaveBeenCalled();
  });

  it('stops before anything is asked when the hints refuse the request', async () => {
    serving({});
    vi.mocked(enforceAuthenticatorAttachmentWithHints).mockImplementationOnce(() => {
      throw new Error('base64 has "!" at position 0, outside its alphabet');
    });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(request({ hints: ['unknown'] })), options);

    expect(outcome.text).toBe('Credential registration failed: base64 has "!" at position 0, outside its alphabet');
    expect(outcome.context.publicKey).toEqual(request({ hints: ['unknown'] }).publicKey);
    expect(asked()).toEqual([]);
    expect(options.onStart).not.toHaveBeenCalled();
  });

  it('says a refused begin as the server says it, and asks the authenticator nothing', async () => {
    serving({ [BEGIN]: BEGIN_FAILURES[5] });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(request({ user: { id: '00', name: '' } })), options);

    expect(asked()).toEqual([BEGIN]);
    expect(sent(0).body.publicKey.user).toEqual({ id: '00', name: '' });
    expect(outcome.text).toBe('Credential registration failed: Username is required in user.name');
    expect(outcome.context.createOptions).toBeNull();
    expect(authenticator.create).not.toHaveBeenCalled();
    expect(options.onResult).not.toHaveBeenCalled();
  });

  it('fails as the options do when the server begins with something that is not options', async () => {
    serving({ [BEGIN]: { status: 200, body: null } });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(request()), options);

    expect(asked()).toEqual([BEGIN]);
    expect(outcome.text).toMatch(/^Credential registration failed: \S/);
    expect(options.onWarning).not.toHaveBeenCalled();
    expect(authenticator.create).not.toHaveBeenCalled();
  });

  it('says what the authenticator may not support when it refuses, and completes nothing', async () => {
    authenticatorGiving(() => Promise.reject(new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')));
    serving({ [BEGIN]: EVERYTHING.begin });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(EVERYTHING_REQUEST), options);

    expect(outcome.registered).toBe(false);
    expect(outcome.text).toBe(
      'Credential registration failed: User cancelled or authenticator not available The authenticator may not support: '
      + 'largeBlob extension, prf extension, minPinLength extension, credProtect extension, credProps extension.',
    );
    expect(outcome.context).toEqual({
      publicKey: EVERYTHING_REQUEST.publicKey,
      createOptions: authenticator.create.mock.calls[0][0],
    });
    expect(asked()).toEqual([BEGIN]);
    expect(options.onResult).not.toHaveBeenCalled();
  });

  it('names the signature algorithms when the authenticator refuses an ML-DSA request', async () => {
    authenticatorGiving(() => Promise.reject(new DOMException('The algorithms requested are not supported.', 'NotSupportedError')));
    serving({ [BEGIN]: MLDSA.begin });
    const outcome = await registerAdvancedCredential(text(request({ pubKeyCredParams: [{ type: 'public-key', alg: -48 }] })), formOptions());

    expect(asked()).toEqual([BEGIN]);
    expect(outcome.text).toBe(
      'Credential registration failed: The algorithms requested are not supported. The authenticator may not support: selected signature algorithms.',
    );
  });

  it('says a refused completion as the server says it, and gives the result panel its challenge', async () => {
    serving({ [BEGIN]: COMPLETE_FAILURES[11], [COMPLETE]: COMPLETE_FAILURES[12] });
    const options = formOptions();
    const outcome = await registerAdvancedCredential(text(request()), options);

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(outcome.text).toBe('Credential registration failed: Wrong challenge in response. Start the ceremony again.');
    expect(options.onResult).toHaveBeenCalledWith({
      title: 'Last registration',
      showChallenge: true,
      challengeSource: 'server-session',
      challengeStatus: 'replayed',
    });
  });
});
