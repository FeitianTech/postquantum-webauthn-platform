// The Advanced tab's logic comes from the modules in src/logic: the
// registration's and the authentication's requests
// and the forms' settings (advanced/json-editor/registration-request.js,
// authentication-request.js, algorithm-options.js), a form change over the
// editor's text (json-editor/request-patch.js), the JSON editor
// (json-editor/editor-model.js, advanced/editor/json-editing.js), the hints'
// rules, the fake credential IDs, the byte fields' check, the Allow Credentials
// choices and the extensions' availability (advanced/auth/hint-rules.js,
// fake-credentials.js, hex-input.js, allow-credentials.js, capabilities.js),
// the two ceremonies (advanced/auth/ceremony.js, assertion.js) and the snapshot
// a registration's result keeps (credential-display/registration-snapshot.js).
// These are the types the components read them through.
import { advancedRegisteredMessage, advancedRegistrationFailureText, registerAdvancedCredential } from '@/logic/advanced/auth/ceremony.js';
import {
  FAKE_CREDENTIAL_TEXT,
  fakeCredentialLength,
  fakeCredentialSize,
  normaliseFakeCredentialList,
  withoutFakeCredential,
} from '@/logic/advanced/auth/fake-credentials.js';
import { ALLOW_CREDENTIALS_TEXT, allowCredentialChoices, authenticationCredentials, keptChoice } from '@/logic/advanced/auth/allow-credentials.js';
import { ADVANCED_ASSERTION_TEXT, advancedAuthenticationFailureText, authenticateAdvancedCredential } from '@/logic/advanced/auth/assertion.js';
import { authenticationAvailability } from '@/logic/advanced/auth/capabilities.js';
import { hexInputIsValid } from '@/logic/advanced/auth/hex-input.js';
import {
  HINT_VALUES,
  applyAuthenticatorAttachmentPreference,
  deriveAllowedAttachmentsFromHints,
  enforceAuthenticatorAttachmentWithHints,
  ensureAuthenticationHintsAllowed,
} from '@/logic/advanced/auth/hint-rules.js';
import { describeCoseAlgorithm } from '@/logic/advanced/cose-labels.js';
import { describeCredentialAlgorithmWith } from '@/logic/advanced/credentials/algorithm-tag.js';
import { getCredentialIdHex, getStoredCredentialAttachment } from '@/logic/advanced/credentials/utils.js';
import { decodePayloadThroughApi } from '@/logic/advanced/credential-display/decode-payload.js';
import { keepRegistrationSnapshot } from '@/logic/advanced/credential-display/registration-snapshot.js';
import { createRegistrationState } from '@/logic/advanced/credential-display/registration-state.js';
import { composeRegistration } from '@/logic/advanced/credential-display/registration-view.js';
import { applyJsonEditorAutoIndent, applyTabIndentation, wrapSelectionWithPair } from '@/logic/advanced/editor/json-editing.js';
import { ALGORITHM_OPTIONS } from '@/logic/advanced/json-editor/algorithm-options.js';
import {
  authenticationControls,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from '@/logic/advanced/json-editor/authentication-request.js';
import { EDITOR_TEXT, editorTitle, readEditedRequest, requestText, topLevelExtras } from '@/logic/advanced/json-editor/editor-model.js';
import { followForm } from '@/logic/advanced/json-editor/request-patch.js';
import {
  buildCreationOptions,
  changeRegistration,
  readCreationOptions,
  registrationControls,
  registrationDefaults,
} from '@/logic/advanced/json-editor/registration-request.js';
import { generateRandom10DigitUsername } from '@/logic/shared/auth/random-username.js';
import {
  prepareAdvancedCredentialsForServer,
  saveAdvancedCredential,
  updateAdvancedCredentialRegistrationSnapshot,
  updateAdvancedCredentialSignCount,
} from '@/logic/shared/storage/records.js';
import { generateRandomHex } from '@/logic/shared/utils/binary.js';

import type { CeremonyResultInput } from '@/components/ceremony/model';
import type { SavedCredential } from '@/components/credentials/model';

/** The registration form's settings (registration-request.js): byte fields as hex text, numbers as text. */
export type RegistrationSettings = {
  userId: string;
  userName: string;
  displayName: string;
  challenge: string;
  timeout: string;
  attachment: string;
  residentKey: string;
  userVerification: string;
  attestation: string;
  excludeCredentials: boolean;
  fakeCredLength: string;
  algorithms: number[];
  hints: string[];
  credProps: boolean;
  minPinLength: boolean;
  credProtect: string;
  enforceCredProtect: boolean;
  largeBlob: string;
  prf: boolean;
  prfFirst: string;
  prfSecond: string;
};

export type RegistrationField = keyof RegistrationSettings;

export type RequestContext = {
  rpName: string;
  hostname: string;
  storedCredentials: SavedCredential[];
  fakeExcludeCredentials: string[];
};

type Json = Record<string, unknown>;
export type CreationOptions = { publicKey: Json };

export const ALGORITHMS = ALGORITHM_OPTIONS as { key: string; alg: number; label: string; pqc: boolean }[];
export const HINTS = HINT_VALUES as string[];

export const defaultSettings = registrationDefaults as () => Omit<RegistrationSettings, 'userId' | 'userName' | 'displayName' | 'challenge'>;
export const buildRequest = buildCreationOptions as (settings: RegistrationSettings, context: RequestContext) => CreationOptions;
export const readRequest = readCreationOptions as (
  publicKey: Json,
  previous: RegistrationSettings,
  context: { storedCredentials: SavedCredential[] },
) => { settings: RegistrationSettings; fakeExcludeCredentials: string[] };
export const changeSetting = changeRegistration as <F extends RegistrationField>(
  settings: RegistrationSettings,
  field: F,
  value: RegistrationSettings[F],
) => RegistrationSettings;
export const lockedFields = registrationControls as (settings: RegistrationSettings) => { enforceCredProtect: boolean; prfSecond: boolean };

export const hexIsValid = hexInputIsValid as (text: string, minBytes: number) => boolean;
export const randomHex = generateRandomHex as (bytes: number) => string;
export const randomName = generateRandom10DigitUsername as () => string;

export const FAKE_TEXT = FAKE_CREDENTIAL_TEXT as Record<'noExclude' | 'noAllow' | 'invalidLength' | 'truncated', string>;
export const fakeLength = fakeCredentialLength as (length: string) => { bytes: number; error: string | null; notice: string | null };
export const fakeSize = fakeCredentialSize as (hex: string) => string;
export const fakeList = normaliseFakeCredentialList as (values: unknown) => string[];
export const withoutFake = withoutFakeCredential as (list: string[], index: number) => string[] | null;

// The editor.
export type EditorLocation = { offset: number; line: number; column: number };
export type EditedRequest =
  | { status: 'unparsed'; message: string; location: EditorLocation | null }
  | { status: 'refused'; root: unknown; message: string }
  | { status: 'accepted'; root: { publicKey: Json } & Json };
export const EDITOR_WORDS = EDITOR_TEXT as Record<'title' | 'registrationTitle' | 'authenticationTitle' | 'reset', string>;
export const titleOf = editorTitle as (scope: 'registration' | 'authentication') => string;
export const textOf = requestText as (options: unknown) => string;
export const readEdit = readEditedRequest as (text: string, scope: 'registration' | 'authentication') => EditedRequest;
export const extrasOf = topLevelExtras as (root: unknown) => Json;
/** The editor's text after the form's request went from `before` to `after`, the rest kept as typed. */
export const follow = followForm as (text: string, before: { publicKey: Json }, after: { publicKey: Json }, extras?: Json) => string;

/** A textarea's state, which the editor's key edits change. */
export type EditorState = { value: string; selectionStart: number; selectionEnd: number };
export const wrapPair = wrapSelectionWithPair as (typed: EditorState, opening: string, closing: string) => void;
export const autoIndent = applyJsonEditorAutoIndent as (typed: EditorState) => void;
export const indent = applyTabIndentation as (typed: EditorState, shift: boolean) => void;

// The ceremony and the result it keeps.
export type RegistrationAnswer = { algo?: string; relyingParty?: Json | null; storedCredential?: Json | null; [field: string]: unknown };
export type RegistrationOutcome =
  | {
      registered: true;
      answer: RegistrationAnswer;
      credentialJson: Json;
      publicKey: Json;
      record: SavedCredential | null;
    }
  | { registered: false; text: string };
type CeremonyOptions = {
  enforceHints: (publicKey: Json) => string[];
  applyAttachmentPreference: (...args: unknown[]) => void;
  minPinLength: () => boolean;
  onStart: () => void;
  onProgress: (text: string) => void;
  onWarning: (text: string) => void;
  onResult: (result: CeremonyResultInput) => void;
};
export const registerCredential = registerAdvancedCredential as unknown as (text: string, options: CeremonyOptions) => Promise<RegistrationOutcome>;
export const registeredMessage = advancedRegisteredMessage as (answer: RegistrationAnswer) => { text: string; tone: 'success' | 'warning' };
export const failureText = advancedRegistrationFailureText as (error: unknown) => string;
export const enforceHints = enforceAuthenticatorAttachmentWithHints as (publicKey: Json) => string[];
export const attachmentPreference = applyAuthenticatorAttachmentPreference as (...args: unknown[]) => void;
export const saveRecord = saveAdvancedCredential as (record: SavedCredential) => (SavedCredential & { storageId?: string }) | null;

/** Composes a registration into a state of its own, and saves it as the record's snapshot. */
export function keepSnapshot(credentialJson: Json, relyingPartyInfo: Json | null, storageId: string | null) {
  const registration = createRegistrationState();
  return (
    keepRegistrationSnapshot as (
      input: { credentialJson: Json; relyingPartyInfo: Json | null; storageId: string | null },
      options: { compose: (input: object) => Promise<unknown>; saveSnapshot: (id: string, payload: object) => Promise<boolean> },
    ) => Promise<{ saved: boolean }>
  )(
    { credentialJson, relyingPartyInfo, storageId },
    {
      compose: (input) => (composeRegistration as (input: object, deps: object) => Promise<unknown>)(input, { state: registration, decode: decodePayloadThroughApi }),
      saveSnapshot: updateAdvancedCredentialRegistrationSnapshot as (id: string, payload: object) => Promise<boolean>,
    },
  );
}

// The authentication's request and form.
/** The authentication form's settings (authentication-request.js): byte fields as hex text, numbers as text. */
export type AuthenticationSettings = {
  userVerification: string;
  /** `all`, `empty`, or a saved credential's ID (hex). */
  allowCredentials: string;
  fakeCredLength: string;
  challenge: string;
  timeout: string;
  hints: string[];
  hashAlgorithm: string;
  largeBlob: string;
  largeBlobWrite: string;
  prfFirst: string;
  prfSecond: string;
};
export type AuthenticationField = keyof AuthenticationSettings;
export type AllowChoice = { value: string; label: string; attachment: string };
export type Availability = { available: boolean; message: string };
export type Availabilities = { largeBlob: Availability; prf: Availability };
type AuthenticationContext = { hostname: string; storedCredentials: SavedCredential[]; fakeAllowCredentials: string[] };

export const authDefaults = authenticationDefaults as () => Omit<AuthenticationSettings, 'challenge'>;
export const buildAuthRequest = buildRequestOptions as (settings: AuthenticationSettings, context: AuthenticationContext) => { publicKey: Json };
export const readAuthRequest = readRequestOptions as (
  publicKey: Json,
  previous: AuthenticationSettings,
  context: { storedCredentials: SavedCredential[]; choices: string[] },
) => { settings: AuthenticationSettings; fakeAllowCredentials: string[] };
export const changeAuth = changeAuthentication as <F extends AuthenticationField>(
  settings: AuthenticationSettings,
  field: F,
  value: AuthenticationSettings[F],
) => AuthenticationSettings;
export const settleAvailability = withAvailability as (settings: AuthenticationSettings, availability: Availabilities) => AuthenticationSettings;
export const lockedAuthFields = authenticationControls as (
  settings: AuthenticationSettings,
  availability: Availabilities,
) => { largeBlob: boolean; largeBlobWrite: boolean; prfFirst: boolean; prfSecond: boolean };
export const availabilityOf = authenticationAvailability as (storedCredentials: SavedCredential[], selection: string) => Availabilities;

export const ALLOW_WORDS = ALLOW_CREDENTIALS_TEXT as { all: string; empty: string };
export const keptAllowChoice = keptChoice as (choices: AllowChoice[], value: string) => string;
/** The saved credentials an authentication can use: the advanced ones, which its ceremony sends. */
export const usableForAuthentication = authenticationCredentials as (storedCredentials: SavedCredential[]) => SavedCredential[];
/** The saved credentials Allow Credentials offers: those whose attachment the authentication's hints allow (every one without hints). */
export function allowChoices(storedCredentials: SavedCredential[], hints: string[]): AllowChoice[] {
  const attachments = (deriveAllowedAttachmentsFromHints as (hints: string[]) => string[])(hints);
  return (allowCredentialChoices as (stored: SavedCredential[], helpers: object) => AllowChoice[])(storedCredentials, {
    attachments,
    getCredentialIdHex,
    getStoredCredentialAttachment,
    describeAlgorithm: (credential: SavedCredential) =>
      (describeCredentialAlgorithmWith as (record: SavedCredential, describe: unknown) => string)(credential, describeCoseAlgorithm),
  });
}

// The authentication ceremony.
export const ASSERTION_WORDS = ADVANCED_ASSERTION_TEXT as Record<'authenticated' | 'lastAuthentication', string>;
export type AuthenticationAnswer = { authenticatedCredentialId?: string; signCount?: number; [field: string]: unknown };
export type AuthenticationOutcome =
  | { authenticated: true; answer: AuthenticationAnswer; result: CeremonyResultInput }
  | { authenticated: false; text: string; result?: CeremonyResultInput; failedCredentialId?: string };
type AssertionOptions = {
  ensureHints: (publicKey: Json) => unknown;
  prepareForServer: () => unknown[];
  hashAlgorithm: () => string;
  onStart: () => void;
  onProgress: (text: string) => void;
};
export const authenticate = authenticateAdvancedCredential as unknown as (text: string, options: AssertionOptions) => Promise<AuthenticationOutcome>;
export const assertionFailureText = advancedAuthenticationFailureText as (error: unknown) => string;
export const checkHints = ensureAuthenticationHintsAllowed as (publicKey: Json, options: { storedCredentials: SavedCredential[] }) => string[];
export const recordsForServer = prepareAdvancedCredentialsForServer as () => unknown[];
export const keepAdvancedSignCount = updateAdvancedCredentialSignCount as (credentialId: string, signCount?: number) => void;
