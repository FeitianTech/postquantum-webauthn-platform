// The explorer table's words the logic does not hold: the columns' headers, and
// the filters' labels and placeholders.
import { FILTER_CONFIG } from '@/logic/mds/constants.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';

// The 14 columns, in order, with their headers; `list` names the entry's list a
// tag column shows.
export const EXPLORER_COLUMNS = [
  { key: 'icon', header: 'Icon' },
  { key: 'name', header: 'Name' },
  { key: 'protocol', header: 'Protocol' },
  { key: 'certification', header: 'Certification' },
  { key: 'latestStatus', header: 'Status' },
  { key: 'id', header: 'ID' },
  { key: 'userVerification', header: 'User Verification', list: 'userVerificationList' },
  { key: 'attachment', header: 'Attachment', list: 'attachmentList' },
  { key: 'transports', header: 'Transports', list: 'transportsList' },
  { key: 'keyProtection', header: 'Key Protection', list: 'keyProtectionList' },
  { key: 'algorithms', header: 'Algorithms', list: 'algorithmsList' },
  { key: 'algorithmInfo', header: 'Algorithm Info', list: 'certificateAlgorithmInfoList' },
  { key: 'commonName', header: 'CN', list: 'certificateCommonNameList' },
  { key: 'dateUpdated', header: 'Date Updated' },
] as const satisfies readonly { key: string; header: string; list?: keyof MdsEntry }[];

export type ExplorerColumn = (typeof EXPLORER_COLUMNS)[number];

// The 11 filters: each labelled with the column it reads (the search reads two,
// and has its own label), its placeholder, and, from the shared configuration,
// whether it offers a list (and shows that list whole).
const LABELS: Record<string, string> = { search: 'Search' };
const PLACEHOLDERS: Record<string, string> = {
  search: 'Search name or ID',
  protocol: 'Protocol',
  certification: 'Certification',
  latestStatus: 'Status',
  userVerification: 'User verification',
  attachment: 'Attachment',
  transports: 'Transports',
  keyProtection: 'Key protection',
  algorithms: 'Algorithms',
  algorithmInfo: 'Algorithm info',
  commonName: 'CN',
};

export const EXPLORER_FILTERS = FILTER_CONFIG.map((config) => ({
  key: config.key,
  label: LABELS[config.key] ?? EXPLORER_COLUMNS.find((column) => column.key === config.key)!.header,
  placeholder: PLACEHOLDERS[config.key],
  offersOptions: Boolean(config.optionsKey),
  showsWholeList: Boolean(config.expandDropdown),
}));

export type ExplorerFilter = (typeof EXPLORER_FILTERS)[number];

export function emptyFilters(): Record<string, string> {
  return Object.fromEntries(EXPLORER_FILTERS.map((filter) => [filter.key, '']));
}
