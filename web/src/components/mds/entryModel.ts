// The entry page's, certificate page's and raw view's logic comes from the
// modules both UIs share: frontend/static/scripts/advanced/mds/explorer/detail.js,
// certificate.js, entry-link.js, raw-data.js and raw-stringify.js. These are the
// types web/ reads them through.
import { detailSections, detailSubtitleParts, detailTitle, formatDetailSubtitle } from '@/logic/advanced/mds/explorer/detail.js';
import {
  describeCertificate as describeCertificateJs,
  normaliseCertificateBase64,
  requestCertificateDecode,
} from '@/logic/advanced/mds/explorer/certificate.js';
import { entryIdForAaguid, requestResolvedEntry, resolveQueryForEntry } from '@/logic/advanced/mds/explorer/entry-link.js';
import { hasInlineDetail } from '@/logic/advanced/mds/metadata/metadata-helpers.js';
import { authenticatorRawTitle, getAuthenticatorRawData } from '@/logic/advanced/mds/raw-data.js';
import { stringifyAuthenticatorRawData } from '@/logic/advanced/mds/raw-stringify.js';

import type { MdsEntry } from './model';

/** A field: a value (an identifier is copyable, in Geist Mono), or a list of codes. */
export type DetailField = { label: string; value?: string; codes?: string[]; identifier?: boolean };
export type ChipList = { label: string; values: string[] };
export type VerificationMethod = {
  method: string;
  codeAccuracy: string;
  biometricAccuracy: string;
  patternAccuracy: string;
};
export type Combination = { title: string; methods: VerificationMethod[] };
export type CertificateLink = { number: number; label: string; certificate: string };
export type StatusReportRow = {
  status: string;
  effectiveDate: string;
  authenticatorVersion: string;
  certificateNumber: string;
  descriptor: string;
  details: string;
};

/** One of the page's sections, in the current page's order; what it holds depends on its kind. */
export type DetailSection = {
  key: string;
  title: string;
  fields?: DetailField[];
  chipLists?: ChipList[];
  combinations?: Combination[];
  certificates?: CertificateLink[];
  columns?: string[];
  statusReports?: StatusReportRow[];
};

export type SubtitlePart = { label: string; value: string };

export const entrySections = detailSections as (entry: MdsEntry | null) => DetailSection[];
export const entryTitle = detailTitle as (entry: MdsEntry | null) => string;
export const entrySubtitle = detailSubtitleParts as (entry: MdsEntry | null) => SubtitlePart[];
export const entrySubtitleText = formatDetailSubtitle as (entry: MdsEntry | null) => string;

export type ResolveAnswer = { entry: MdsEntry | null; failure?: { status: number; message: string } };
export const resolveEntry = requestResolvedEntry as (
  query: Record<string, string>,
  options?: { signal?: AbortSignal },
) => Promise<ResolveAnswer>;
export const resolveQuery = resolveQueryForEntry as (entry: MdsEntry | null) => Record<string, string>;
export const aaguidEntryId = entryIdForAaguid as (aaguid: unknown) => string;
export const hasDetail = hasInlineDetail as (entry: MdsEntry | null | undefined) => boolean;

export const rawData = getAuthenticatorRawData as (entry: MdsEntry | null) => Record<string, unknown> | null;
export const rawText = stringifyAuthenticatorRawData as (value: unknown) => string;
export const rawTitle = authenticatorRawTitle as (entry: MdsEntry | null) => string;

/** One line of a certificate's summary. */
export type SummaryItem = { label: string; value?: string; lines?: string[]; primary: boolean; code: boolean };
export type CertificateSummary = { items: SummaryItem[]; sections: { title: string; items: SummaryItem[] }[] };
export type CertificateView = {
  title: string;
  subtitle: string;
  summary: CertificateSummary | null;
  message: string;
  output: string;
  failed: boolean;
  reason: string;
};

export const cleanCertificate = normaliseCertificateBase64 as (value: unknown) => string;
export const decodeCertificate = requestCertificateDecode as (certificate: string) => Promise<unknown>;
export const certificateView = describeCertificateJs as (outcome: { details?: unknown; error?: unknown }) => CertificateView;
