// A saved credential's details come from the modules in src/logic: what the
// sections above the registration show
// (credentials/detail/sections.js),
// the registration's own view (credentials/registration/view.js), both
// composed by credentials/detail/compose.js over a registration state
// (credentials/registration/state.js), the decode (decode-payload.js), the
// artifact's hydration (credentials/hydrate.js) and a certificate's
// text (credentials/certificates/text.js). These are the types the components read
// them through.
import { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet } from '@/logic/credentials/cose-labels.js';
import { composeCredentialDetail, needsArtifact } from '@/logic/credentials/detail/compose.js';
import { DETAIL_TEXT, describeValue } from '@/logic/credentials/detail/sections.js';
import { decodePayloadThroughApi } from '@/logic/credentials/registration/decode-payload.js';
import { createRegistrationState } from '@/logic/credentials/registration/state.js';
import {
  REGISTRATION_TEXT,
  describeAttestationCertificate,
  describeAuthenticatorData,
} from '@/logic/credentials/registration/view.js';
import { HYDRATE_TEXT } from '@/logic/credentials/hydrate.js';
import { certificateSummary } from '@/logic/mds/explorer/certificate.js';

import type { CertificateSummary } from '@/logic/mds/explorer/certificate.js';
import type { SavedCredential } from '@/logic/credentials/saved-list.js';

export type ValueKind = 'true' | 'false' | 'missing' | 'other';
type DescribedValue = { kind: ValueKind; text: string };
export type Check = { label: string; value: unknown; rootChecks: { label: string; value: unknown }[] | null };
export type Identifier =
  | { title: string; spellings: { label: string; value: string }[]; stored?: undefined; note?: undefined }
  | { title: string; stored: string; note: string; spellings?: undefined };

type DetailSectionsView = {
  properties: {
    title: string;
    discoverable: unknown;
    largeBlob: unknown;
    minPinLength: number | null;
    checks: Check[];
  };
  userInfo: { title: string; name: string; displayName: string; identifiers: Identifier[] };
  aaguid: { title: string; values: { label: string; value: string }[] };
  attestationFormat: { title: string; value: string };
  authenticatorData: { title: string; flags: { name: string; value: string }[]; counter: string } | null;
  extensions: { title: string; text: string } | null;
  publicKey: { title: string; lines: { label: string; value: string }[] } | null;
};

type AttestationBody = { kind: 'json' | 'placeholder' | 'error'; text: string };
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
