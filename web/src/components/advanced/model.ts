// The Advanced tab's authentication comes from the modules in
// src/logic/advanced/authentication (request.js, ceremony.js, capabilities.js)
// and the hints' rules (hints.js). These are the types the components read them
// through.
import { ADVANCED_ASSERTION_TEXT, advancedAuthenticationFailureText, authenticateAdvancedCredential } from '@/logic/advanced/authentication/ceremony.js';
import { authenticationAvailability } from '@/logic/advanced/authentication/capabilities.js';
import { ensureAuthenticationHintsAllowed } from '@/logic/advanced/hints.js';
import {
  authenticationControls,
  authenticationDefaults,
  buildRequestOptions,
  changeAuthentication,
  readRequestOptions,
  withAvailability,
} from '@/logic/advanced/authentication/request.js';
import {
  prepareAdvancedCredentialsForServer,
  updateAdvancedCredentialSignCount,
} from '@/logic/credentials/storage/local/advanced-credentials.js';

import type { SavedCredential } from '@/logic/credentials/saved-list.js';
import type { CeremonyResultInput } from '@/logic/shared/ceremony-result.js';

type Json = Record<string, unknown>;

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
