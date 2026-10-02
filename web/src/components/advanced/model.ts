// The Advanced tab's logic comes from the modules in src/logic/advanced: each
// ceremony's request, form settings and ceremony (registration/request.js,
// algorithm-options.js, ceremony.js; authentication/request.js, ceremony.js), a
// the hints' rules, the fake credential IDs,
// the byte fields' check, the Allow Credentials choices and the extensions'
// availability (hints.js, fake-credentials.js, hex-input.js,
// authentication/allow-credentials.js, authentication/capabilities.js).
// These are the types the components read them through.
import { advancedRegisteredMessage, advancedRegistrationFailureText, registerAdvancedCredential } from '@/logic/advanced/registration/ceremony.js';
import {
  FAKE_CREDENTIAL_TEXT,
  fakeCredentialLength,
  fakeCredentialSize,
  normaliseFakeCredentialList,
  withoutFakeCredential,
} from '@/logic/advanced/fake-credentials.js';
import { ADVANCED_ASSERTION_TEXT, advancedAuthenticationFailureText, authenticateAdvancedCredential } from '@/logic/advanced/authentication/ceremony.js';
import { authenticationAvailability } from '@/logic/advanced/authentication/capabilities.js';
import { hexInputIsValid } from '@/logic/advanced/hex-input.js';
import {
  HINT_VALUES,
  applyAuthenticatorAttachmentPreference,
  enforceAuthenticatorAttachmentWithHints,
  ensureAuthenticationHintsAllowed,
} from '@/logic/advanced/hints.js';
import { ALGORITHM_OPTIONS } from '@/logic/advanced/registration/algorithm-options.js';
import {
  authenticationControls,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from '@/logic/advanced/authentication/request.js';
import {
  buildCreationOptions,
  changeRegistration,
  readCreationOptions,
  registrationControls,
  registrationDefaults,
} from '@/logic/advanced/registration/request.js';
import { generateRandom10DigitUsername } from '@/logic/shared/random-username.js';
import {
  prepareAdvancedCredentialsForServer,
  saveAdvancedCredential,
  updateAdvancedCredentialSignCount,
} from '@/logic/credentials/storage/local/advanced-credentials.js';
import { generateRandomHex } from '@/logic/shared/bytes.js';

import type { SavedCredential } from '@/logic/credentials/saved-list.js';
import type { CeremonyResultInput } from '@/logic/shared/ceremony-result.js';

/** The registration form's settings (registration/request.js): byte fields as hex text, numbers as text. */
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

type RequestContext = {
  rpName: string;
  hostname: string;
  storedCredentials: SavedCredential[];
  fakeExcludeCredentials: string[];
};

type Json = Record<string, unknown>;
type CreationOptions = { publicKey: Json };

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

// The ceremony and the result it keeps.
export type RegistrationAnswer = { algo?: string; relyingParty?: Json | null; storedCredential?: Json | null; [field: string]: unknown };
type RegistrationOutcome =
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

// The authentication's request and form.
/** The authentication form's settings (authentication/request.js): byte fields as hex text, numbers as text. */
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
type Availability = { available: boolean; message: string };
type Availabilities = { largeBlob: Availability; prf: Availability };
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
