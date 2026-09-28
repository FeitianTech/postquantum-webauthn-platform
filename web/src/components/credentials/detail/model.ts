// A saved credential's details come from the modules both UIs share
// (docs/UI_MIGRATION.md): what the sections above the registration show
// (advanced/credential-display/credential-detail-runtime/detail-sections.js),
// the registration's own view (credential-display/registration-view.js), both
// composed by credential-detail-runtime/compose.js over a registration state
// (credential-display/registration-state.js), the decode (decode-payload.js), the
// artifact's hydration (advanced/credentials/hydrate.js) and a certificate's
// text (credential-display/certificate-text.js). These are the types web/ reads
// them through.
import { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet } from '@legacy/advanced/cose-labels.js';
import { composeCredentialDetail, needsArtifact } from '@legacy/advanced/credential-display/credential-detail-runtime/compose.js';
import { DETAIL_TEXT, describeValue } from '@legacy/advanced/credential-display/credential-detail-runtime/detail-sections.js';
import { decodePayloadThroughApi } from '@legacy/advanced/credential-display/decode-payload.js';
import { createRegistrationState } from '@legacy/advanced/credential-display/registration-state.js';
import {
  REGISTRATION_TEXT,
  describeAttestationCertificate,
  describeAuthenticatorData,
} from '@legacy/advanced/credential-display/registration-view.js';
import { HYDRATE_TEXT, hydrateCredentialFromServer } from '@legacy/advanced/credentials/hydrate.js';
import { certificateSummary } from '@legacy/advanced/mds/explorer/certificate.js';
import { fetchCredentialArtifact } from '@legacy/shared/storage/artifacts-client.js';
import { updateAdvancedCredentialRegistrationSnapshot } from '@legacy/shared/storage/records.js';

import type { CertificateSummary } from '@/components/mds/entryModel';

import type { SavedCredential } from '../model';

export type ValueKind = 'true' | 'false' | 'missing' | 'other';
export type DescribedValue = { kind: ValueKind; text: string };
export type Check = { label: string; value: unknown; rootChecks: { label: string; value: unknown }[] | null };
export type Identifier =
  | { title: string; spellings: { label: string; value: string }[]; stored?: undefined; note?: undefined }
  | { title: string; stored: string; note: string; spellings?: undefined };

export type DetailSectionsView = {
  properties: {
    title: string;
    discoverable: unknown;
    largeBlob: unknown;
    minPinLength: number | null;
    checks: Check[];
    warning: string;
  };
  userInfo: { title: string; name: string; displayName: string; identifiers: Identifier[] };
  aaguid: { title: string; values: { label: string; value: string }[] };
  attestationFormat: { title: string; value: string };
  authenticatorData: { title: string; flags: { name: string; value: string }[]; counter: string } | null;
  extensions: { title: string; text: string } | null;
  publicKey: { title: string; lines: { label: string; value: string }[] } | null;
};

export type AttestationBody = { kind: 'json' | 'placeholder' | 'error'; text: string };
export type AttestationView = {
  body: AttestationBody;
  certificates: { index: number; title: string }[];
  certificateMessage: string;
  hasAuthenticatorData: boolean;
  authenticatorError: string;
};
export type RegistrationView = {
  response: { credential: string; clientData: string; relyingParty: string };
  attestation: AttestationView | null;
};
export type CredentialDetail = DetailSectionsView & { registration: RegistrationView };

/** The registration state a detail is composed into; its levels read it. */
export type RegistrationState = Record<string, unknown>;

export type CertificateView = {
  title: string;
  details: Record<string, unknown>;
  text: string;
  error: string;
  placeholder: string;
};

export const DETAIL_WORDS = DETAIL_TEXT as {
  discoverable: string;
  largeBlob: string;
  minPinLength: string;
  checksNote: readonly string[];
  name: string;
  displayName: string;
  signatureCounter: string;
  notAvailable: string;
};
export const REGISTRATION_WORDS = REGISTRATION_TEXT as {
  responseTitle: string;
  createResponse: string;
  noCredentialResponse: string;
  parsedClientData: string;
  noClientData: string;
  serverDataTitle: string;
  noRelyingParty: string;
  attestationTitle: string;
  attestationObject: string;
  noCertificates: string;
  authenticatorData: string;
};
export const HYDRATE_FAILED = (HYDRATE_TEXT as { failed: string }).failed;

export const valueOf = describeValue as (value: unknown) => DescribedValue;

/** Whether the record must first be completed from its server artifact. */
export const needsItsArtifact = needsArtifact as (record: SavedCredential) => boolean;

/** Completes `record` (a copy) from its artifact; saving the snapshot calls `onSaved` when it was kept. */
export function hydrate(record: SavedCredential, onSaved: () => void): Promise<unknown> {
  return (hydrateCredentialFromServer as (record: SavedCredential, steps: object) => Promise<unknown>)(record, {
    fetchCredentialArtifact,
    saveSnapshot: async (storageId: string, snapshot: unknown) => {
      const saved = await (updateAdvancedCredentialRegistrationSnapshot as (id: string, snapshot: unknown) => Promise<boolean>)(
        storageId,
        snapshot,
      );
      if (saved) onSaved();
      return saved;
    },
  });
}

/** Everything the details show, composed into a state of their own (the levels read it). */
export async function compose(record: SavedCredential): Promise<{ detail: CredentialDetail; state: RegistrationState }> {
  const registration = (createRegistrationState as () => RegistrationState)();
  const detail = await (composeCredentialDetail as (record: SavedCredential, steps: object) => Promise<CredentialDetail>)(record, {
    state: registration,
    decode: decodePayloadThroughApi,
    describers: { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet },
  });
  return { detail, state: registration };
}

export const certificateView = describeAttestationCertificate as (state: RegistrationState, index: number) => CertificateView | null;
export const authenticatorDataView = describeAuthenticatorData as (state: RegistrationState) => { title: string; text: string } | null;
export const summaryOf = certificateSummary as (details: unknown) => CertificateSummary | null;
