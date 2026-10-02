// The saved credentials' logic comes from the modules in src/logic: the storage
// (credentials/storage/), the list and what a card shows
// (credentials/saved-list.js), deleting and clearing
// (credentials/delete-flow.js). These are the types the components read them
// through.
import { CLEAR_ALL_CONFIRMATION, deleteConfirmation } from '@/logic/credentials/delete-flow.js';
import { SAVED_LIST_TEXT, credentialFlashKey, credentialKey } from '@/logic/credentials/saved-list.js';
import { followStoredCredentialChanges } from '@/logic/credentials/storage/local/storage-core.js';

/** A saved credential as the list holds it (the stored record, typed, with its ids in hex). */
export type SavedCredential = { type: 'simple' | 'advanced'; [field: string]: unknown };

type CredentialCheck = { label: string; value: boolean | null };

/** What a row shows. */
type CredentialCardView = {
  name: string;
  checks: CredentialCheck[];
  tags: string[];
  /** The AAGUID "FIDO MDS" opens, or '' when the row has no such button. */
  mdsAaguid: string;
  credentialIdHex: string;
  credentialId: string;
  aaguid: string;
  /** A stored AAGUID no spelling reads, as stored ('' when there is none). */
  aaguidUnreadable: string;
};

export type CredentialRowView = CredentialCardView & { key: string; credential: SavedCredential };

export const LIST_TEXT = SAVED_LIST_TEXT as { empty: string; unknownUser: string; openMetadata: string };
export const CLEAR_ALL_QUESTION = CLEAR_ALL_CONFIRMATION as string;
export const deleteQuestion = deleteConfirmation as (credential: SavedCredential) => string;
export const flashKey = credentialFlashKey as (credentialId: unknown) => string;
/** A saved record's key in the list, and in its details' URL (the storage's own identifier). */
export const recordKey = credentialKey as (record: SavedCredential) => string;

/** Calls `onChange` when another tab changes the saved credentials; gives the function that stops. */
export const followOtherTabs = followStoredCredentialChanges as (onChange: () => void) => () => void;
