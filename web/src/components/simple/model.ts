// The Simple tab's ceremonies come from src/logic/simple/ceremony.js, and the
// credentials they use and keep from the storage both tabs read and write
// (shared/storage/records.js).
import { generateRandom10DigitUsername } from '@/logic/shared/auth/random-username.js';
import {
  getSimpleCredentialsForEmail,
  prepareCredentialsForServer,
  saveSimpleCredential,
  updateSimpleCredentialSignCount,
} from '@/logic/shared/storage/records.js';
import {
  SIMPLE_CEREMONY_TEXT,
  authenticateSimplePasskey,
  ceremonyErrorText,
  registerSimplePasskey,
  registeredText,
} from '@/logic/simple/ceremony.js';

import type { CeremonyResultInput } from '@/components/ceremony/model';

export type Ceremony = 'registration' | 'authentication';

export const CEREMONY_TEXT = SIMPLE_CEREMONY_TEXT as Record<
  | 'usernameRequired'
  | 'registrationStarting'
  | 'connecting'
  | 'registrationCompleting'
  | 'authenticationStarting'
  | 'authenticationCompleting'
  | 'authenticated'
  | 'noStoredCredentials'
  | 'noServerCredentials'
  | 'rejected'
  | 'lastAuthentication',
  string
>;

/** What the server answered a registration: storedCredential is what this browser keeps. */
export type RegistrationAnswer = { algo?: string; storedCredential?: Record<string, unknown> | null; [field: string]: unknown };
export type AuthenticationAnswer = { authenticatedCredentialId?: string; signCount?: number; signCountStatus?: string; [field: string]: unknown };
export type RefusedAssertion = { text: string; failedCredentialId: string | null; signCountStatus: string | null };

export type AuthenticationOutcome =
  | { answer: AuthenticationAnswer; failure?: undefined; result: CeremonyResultInput }
  | { answer?: undefined; failure: RefusedAssertion; result: CeremonyResultInput };

type Progress = { onProgress: (text: string) => void };

export const randomUsername = generateRandom10DigitUsername as () => string;
export const successText = registeredText as (answer: RegistrationAnswer) => string;
export const failureText = ceremonyErrorText as (error: unknown, ceremony: Ceremony) => string;

export function registerPasskey(username: string, progress: Progress): Promise<RegistrationAnswer> {
  return (registerSimplePasskey as (email: string, options: Progress) => Promise<RegistrationAnswer>)(username, progress);
}

/** Authenticates with the passkeys this browser keeps for the username. */
export function authenticateWithPasskey(username: string, progress: Progress): Promise<AuthenticationOutcome> {
  return (authenticateSimplePasskey as (email: string, options: object) => Promise<AuthenticationOutcome>)(username, {
    credentialsFor: getSimpleCredentialsForEmail,
    prepareForServer: prepareCredentialsForServer,
    ...progress,
  });
}

/** Keeps what a registration saved: the server's record, for this username. */
export function keepRegistered(storedCredential: Record<string, unknown>, username: string) {
  saveSimpleCredential({ ...storedCredential, email: username });
}

/** Keeps the counter the server now holds for a credential this username used. */
export function keepSignCount(username: string, credentialId: string, signCount: number | undefined) {
  updateSimpleCredentialSignCount(username, credentialId, signCount);
}
