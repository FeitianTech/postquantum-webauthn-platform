// The saved credentials' logic comes from the modules both UIs share
// (docs/UI_MIGRATION.md): the storage (frontend/static/scripts/shared/storage/
// records.js, the one localStorage array both UIs read and write), what a card
// shows (advanced/credentials/saved-list.js and the helpers it is given),
// deleting and clearing (advanced/credentials/delete-flow.js). These are the
// types web/ reads them through.
import { describeCoseAlgorithm } from '@legacy/advanced/cose-labels.js';
import { describeCredentialAlgorithmTagWith } from '@legacy/advanced/credentials/algorithm-tag.js';
import {
  CLEAR_ALL_CONFIRMATION,
  clearSavedCredentials,
  deleteConfirmation,
  deleteSavedCredential,
} from '@legacy/advanced/credentials/delete-flow.js';
import {
  SAVED_LIST_TEXT,
  credentialFlashKey,
  credentialKey,
  describeCredentialCard,
  listSavedCredentials,
  warmSavedCredentials,
} from '@legacy/advanced/credentials/saved-list.js';
import {
  getCredentialIdHex,
  getCredentialUserHandleHex,
  normaliseAaguidValue,
} from '@legacy/advanced/credentials/utils.js';
import { deriveCredentialStatusIndicators } from '@legacy/advanced/credential-display/attestation-context.js';
import { deleteCredentialArtifact } from '@legacy/shared/storage/artifacts-client.js';
import {
  clearSimpleCredentials,
  ensureAdvancedCredentialArtifactsSynced,
  ensureAdvancedCredentialSnapshotsPrefetched,
  getAllAdvancedCredentials,
  getAllSimpleCredentials,
  getAllStoredCredentialsInOrder,
  removeAdvancedCredential,
  removeSimpleCredential,
} from '@legacy/shared/storage/records.js';

/** A saved credential as the list holds it (the stored record, typed, with its ids in hex). */
export type SavedCredential = { type: 'simple' | 'advanced'; [field: string]: unknown };

export type CredentialCheck = { label: string; value: boolean | null };

/** What a row shows. */
export type CredentialCardView = {
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

/** A message of the list's: a success is a toast, the rest stay under the header. */
export type ListTone = 'success' | 'error' | 'warning' | 'info';

export const LIST_TEXT = SAVED_LIST_TEXT as { empty: string; unknownUser: string; openMetadata: string };
export const CLEAR_ALL_QUESTION = CLEAR_ALL_CONFIRMATION as string;
export const deleteQuestion = deleteConfirmation as (credential: SavedCredential) => string;
export const flashKey = credentialFlashKey as (credentialId: unknown) => string;

/** Every saved credential, simple and advanced, in the order stored. */
export function readSavedCredentials(): SavedCredential[] {
  return (listSavedCredentials as (records: unknown[], helpers: object) => SavedCredential[])(
    (getAllStoredCredentialsInOrder as () => unknown[])(),
    { normaliseAaguidValue, getCredentialIdHex, getCredentialUserHandleHex },
  );
}

/** Each row: its key (the storage's own identifier) and what it shows. */
export function describeRows(credentials: SavedCredential[]): CredentialRowView[] {
  return credentials.map((credential) => ({
    key: (credentialKey as (record: SavedCredential) => string)(credential),
    credential,
    ...(describeCredentialCard as (record: SavedCredential, inputs: object) => CredentialCardView)(credential, {
      indicators: deriveCredentialStatusIndicators(credential),
      algorithmTag: (describeCredentialAlgorithmTagWith as (record: SavedCredential, describe: unknown) => string)(
        credential,
        describeCoseAlgorithm,
      ),
      credentialIdHex: getCredentialIdHex(credential),
    }),
  }));
}

/** Heavy advanced records to the server, missing snapshots from it; `reload` when anything changed. */
export function warmUp(reload: () => void): Promise<boolean> {
  return (warmSavedCredentials as (steps: object) => Promise<boolean>)({
    syncArtifacts: ensureAdvancedCredentialArtifactsSynced,
    prefetchSnapshots: ensureAdvancedCredentialSnapshotsPrefetched,
    reload,
  });
}

/** Where a deletion's steps report, and whether one is running. */
export type DeletionReport = {
  isRunning: () => boolean;
  setRunning: (running: boolean) => void;
  dismiss: () => void;
  progress: (text: string | null) => void;
  status: (text: string, tone: ListTone) => void;
  reload: () => Promise<void>;
};

// The flow's own names for what it is given, from what the list gives it. The
// person was asked in a dialog before, so the flow's question is answered yes.
function deletionSteps(report: DeletionReport) {
  return {
    confirm: () => true,
    isCredentialDeletionInProgress: report.isRunning,
    setCredentialDeletionInProgress: report.setRunning,
    dismissAllTransientMessages: report.dismiss,
    showSharedCredentialProgress: (text: string) => report.progress(text),
    hideSharedCredentialProgress: () => report.progress(null),
    showSharedCredentialStatus: report.status,
    loadSavedCredentials: report.reload,
    removeSimpleCredentialFromLocal: removeSimpleCredential,
    removeAdvancedCredentialFromLocal: removeAdvancedCredential,
    deleteCredentialArtifact,
    getAllSimpleCredentials,
    getAllAdvancedCredentials,
    clearLocalSimpleCredentials: clearSimpleCredentials,
  };
}

export function removeCredential(credential: SavedCredential, report: DeletionReport): Promise<void> {
  return (deleteSavedCredential as (record: SavedCredential, steps: object) => Promise<void>)(credential, deletionSteps(report));
}

export function removeEveryCredential(report: DeletionReport): Promise<void> {
  return (clearSavedCredentials as (steps: object) => Promise<void>)(deletionSteps(report));
}
