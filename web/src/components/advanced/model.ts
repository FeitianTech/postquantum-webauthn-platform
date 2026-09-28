// The Advanced tab's logic comes from the modules both UIs share
// (docs/UI_MIGRATION.md): the registration's request and the form's settings
// (advanced/json-editor/registration-request.js, algorithm-options.js), the
// JSON editor (json-editor/editor-model.js, advanced/editor/json-editing.js),
// the hints' rules, the fake credential IDs and the byte fields' check
// (advanced/auth/hint-rules.js, fake-credentials.js, hex-input.js), the
// registration ceremony (advanced/auth/ceremony.js) and the snapshot its result
// keeps (credential-display/registration-snapshot.js). These are the types web/
// reads them through.
import { ADVANCED_CEREMONY_TEXT, advancedRegisteredMessage, advancedRegistrationFailureText, registerAdvancedCredential } from '@legacy/advanced/auth/ceremony.js';
import {
  FAKE_CREDENTIAL_TEXT,
  fakeCredentialLength,
  fakeCredentialSize,
  normaliseFakeCredentialList,
  withoutFakeCredential,
} from '@legacy/advanced/auth/fake-credentials.js';
import { hexInputIsValid } from '@legacy/advanced/auth/hex-input.js';
import { HINT_VALUES, applyAuthenticatorAttachmentPreference, enforceAuthenticatorAttachmentWithHints } from '@legacy/advanced/auth/hint-rules.js';
import { decodePayloadThroughApi } from '@legacy/advanced/credential-display/decode-payload.js';
import { keepRegistrationSnapshot } from '@legacy/advanced/credential-display/registration-snapshot.js';
import { createRegistrationState } from '@legacy/advanced/credential-display/registration-state.js';
import { composeRegistration } from '@legacy/advanced/credential-display/registration-view.js';
import { applyJsonEditorAutoIndent, applyTabIndentation, wrapSelectionWithPair } from '@legacy/advanced/editor/json-editing.js';
import { ALGORITHM_OPTIONS } from '@legacy/advanced/json-editor/algorithm-options.js';
import { EDITOR_TEXT, editorTitle, readEditedRequest, requestText, topLevelExtras } from '@legacy/advanced/json-editor/editor-model.js';
import {
  buildCreationOptions,
  changeRegistration,
  readCreationOptions,
  registrationControls,
  registrationDefaults,
} from '@legacy/advanced/json-editor/registration-request.js';
import { generateRandom10DigitUsername } from '@legacy/shared/auth/random-username.js';
import { saveAdvancedCredential, updateAdvancedCredentialRegistrationSnapshot } from '@legacy/shared/storage/records.js';
import { generateRandomHex } from '@legacy/shared/utils/binary.js';

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

/** A textarea's state, which the editor's key edits change. */
export type EditorState = { value: string; selectionStart: number; selectionEnd: number };
export const wrapPair = wrapSelectionWithPair as (typed: EditorState, opening: string, closing: string) => void;
export const autoIndent = applyJsonEditorAutoIndent as (typed: EditorState) => void;
export const indent = applyTabIndentation as (typed: EditorState, shift: boolean) => void;

// The ceremony and the result it keeps.
export const CEREMONY_WORDS = ADVANCED_CEREMONY_TEXT as Record<'lastRegistration' | 'invalidHints', string>;
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
  fakeCredentialLength: () => number;
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
