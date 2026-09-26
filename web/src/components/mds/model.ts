// The MDS explorer's logic comes from the modules both UIs share
// (docs/UI_MIGRATION.md): frontend/static/scripts/advanced/mds/explorer/*.js and
// the leaves they stand on. These are the types web/ reads them through, and the
// template's own words the logic does not hold: the columns' headers and the
// filters' labels and placeholders.
import { FILTER_CONFIG } from '@legacy/advanced/mds/constants.js';
import {
  classifyExplorerAnswer,
  fetchExplorerInfo,
  indexEntriesByAaguid,
  prepareSnapshotEntries,
  requestExplorerSnapshot,
} from '@legacy/advanced/mds/explorer/loading.js';
import {
  countActiveExplorerFilters,
  defaultExplorerSort,
  filterAndSortExplorerEntries,
  matchesExplorerFilters,
  nextExplorerSort,
  sortExplorerEntries,
} from '@legacy/advanced/mds/explorer/filter-sort.js';
import { explorerFilterOptionLists, matchingFilterOptions } from '@legacy/advanced/mds/explorer/options.js';
import { certificationParts, identifierLabel } from '@legacy/advanced/mds/explorer/rows.js';
import { explorerLoadedStatus } from '@legacy/advanced/mds/explorer/status.js';
import { createExplorerSource } from '@legacy/advanced/mds/metadata/explorer-source.js';

/** One authenticator as the server lists it: every column's text is already there. */
export type MdsEntry = {
  entryId: string;
  index?: number;
  name: string;
  icon?: string | null;
  protocol: string;
  certification: string;
  certificationStatus: string;
  id: string;
  aaguid?: string;
  userVerification: string;
  userVerificationList: string[];
  attachment: string;
  attachmentList: string[];
  transports: string;
  transportsList: string[];
  keyProtection: string;
  keyProtectionList: string[];
  algorithms: string;
  algorithmsList: string[];
  algorithmInfo: string;
  certificateAlgorithmInfoList: string[];
  commonName: string;
  certificateCommonNameList: string[];
  dateUpdated: string;
  dateTooltip?: string;
  source?: string;
  [key: string]: unknown;
};

export type MdsSnapshot = { meta?: { [key: string]: unknown }; entries: MdsEntry[] };

/** What GET /api/mds/metadata/info answers: the packaged summary, snapshotUrl and customEntriesState. */
export type MdsInfo = { [key: string]: unknown };

export type StatusVariant = 'info' | 'success' | 'error';
export type ExplorerStatus = { text: string; variant: StatusVariant; title: string };

export type SortDirection = 'none' | 'asc' | 'desc';
export type ExplorerSort = { key: string; direction: SortDirection };

export type ExplorerSource = {
  resolve: (options?: { forceReload?: boolean }) => { url: string; cache: string; kind: string };
  fallback: (options?: { forceReload?: boolean }) => { url: string; cache: string; kind: string };
  noteSnapshotMeta: (meta: unknown) => void;
};

export type ExplorerAnswer = { response: Response; payload: unknown };
export type ExplorerOutcome =
  | { kind: 'missing'; message: string }
  | { kind: 'failed'; message: string }
  | { kind: 'snapshot'; payload: MdsSnapshot };

export const makeExplorerSource = createExplorerSource as (info: MdsInfo | null) => ExplorerSource;
export const askExplorerInfo = fetchExplorerInfo as (options?: { signal?: AbortSignal }) => Promise<MdsInfo | null>;
export const askExplorerSnapshot = requestExplorerSnapshot as (
  source: ExplorerSource | null,
  options?: { forceReload?: boolean; signal?: AbortSignal },
) => Promise<ExplorerAnswer>;
export const readExplorerAnswer = classifyExplorerAnswer as (answer: ExplorerAnswer) => ExplorerOutcome;
export const snapshotEntries = prepareSnapshotEntries as (snapshot: MdsSnapshot) => MdsEntry[];
export const entriesByAaguid = indexEntriesByAaguid as (entries: MdsEntry[]) => Map<string, MdsEntry>;
export const loadedStatus = explorerLoadedStatus as (snapshot: MdsSnapshot, note: string, entryCount: number) => ExplorerStatus;

export const initialSort = defaultExplorerSort as () => ExplorerSort;
export const sortAfterClick = nextExplorerSort as (sort: ExplorerSort, key: string) => ExplorerSort | null;
export const sortEntries = sortExplorerEntries as (entries: MdsEntry[], sort: ExplorerSort) => MdsEntry[];
export const entryMatches = matchesExplorerFilters as (
  entry: MdsEntry,
  filters: Record<string, string>,
  certificationOptions: string[],
) => boolean;
export const filterAndSort = filterAndSortExplorerEntries as (
  entries: MdsEntry[],
  filters: Record<string, string>,
  sort: ExplorerSort,
  certificationOptions: string[],
) => MdsEntry[];
export const activeFilterCount = countActiveExplorerFilters as (filters: Record<string, string>) => number;
export const optionLists = explorerFilterOptionLists as (entries: MdsEntry[]) => Record<string, string[]>;
export const optionsMatching = matchingFilterOptions as (options: string[], query: string) => string[];
export const certificationBadge = certificationParts as (entry: MdsEntry) => {
  level: string;
  detail: string;
  tone: 'success' | 'danger' | 'neutral';
};
export const identifierName = identifierLabel as (entry: MdsEntry) => string;

// The 13 columns, in the current UI's order, with its headers; `list` names the
// entry's list a tag column shows. The widths are where each column starts (the
// ID column fits a whole AAGUID and its copy button); a person can resize them.
export const EXPLORER_COLUMNS = [
  { key: 'icon', header: 'Icon', width: 72 },
  { key: 'name', header: 'Name', width: 280 },
  { key: 'protocol', header: 'Protocol', width: 104 },
  { key: 'certification', header: 'Certification', width: 300 },
  { key: 'id', header: 'ID', width: 352, min: 320 },
  { key: 'userVerification', header: 'User Verification', width: 240, list: 'userVerificationList' },
  { key: 'attachment', header: 'Attachment', width: 180, list: 'attachmentList' },
  { key: 'transports', header: 'Transports', width: 160, list: 'transportsList' },
  { key: 'keyProtection', header: 'Key Protection', width: 180, list: 'keyProtectionList' },
  { key: 'algorithms', header: 'Algorithms', width: 260, list: 'algorithmsList' },
  { key: 'algorithmInfo', header: 'Algorithm Info', width: 220, list: 'certificateAlgorithmInfoList' },
  { key: 'commonName', header: 'CN', width: 260, list: 'certificateCommonNameList' },
  { key: 'dateUpdated', header: 'Date Updated', width: 132 },
] as const satisfies readonly { key: string; header: string; width: number; min?: number; list?: keyof MdsEntry }[];

export type ExplorerColumn = (typeof EXPLORER_COLUMNS)[number];
export type ColumnKey = ExplorerColumn['key'];

type FilterConfig = { key: string; optionsKey?: string; expandDropdown?: boolean };

// The 11 filters: the column each one reads, the current template's placeholder,
// and, from the shared configuration, whether it offers a list (and shows that
// list whole).
const PLACEHOLDERS: Record<string, string> = {
  name: 'Search name',
  protocol: 'Protocol',
  certification: 'Certification',
  id: 'AAGUID or AAID',
  userVerification: 'User verification',
  attachment: 'Attachment',
  transports: 'Transports',
  keyProtection: 'Key protection',
  algorithms: 'Algorithms',
  algorithmInfo: 'Algorithm info',
  commonName: 'CN',
};

export const EXPLORER_FILTERS = (FILTER_CONFIG as FilterConfig[]).map((config) => ({
  key: config.key,
  label: EXPLORER_COLUMNS.find((column) => column.key === config.key)!.header,
  placeholder: PLACEHOLDERS[config.key],
  offersOptions: Boolean(config.optionsKey),
  showsWholeList: Boolean(config.expandDropdown),
}));

export type ExplorerFilter = (typeof EXPLORER_FILTERS)[number];

export function emptyFilters(): Record<string, string> {
  return Object.fromEntries(EXPLORER_FILTERS.map((filter) => [filter.key, '']));
}
