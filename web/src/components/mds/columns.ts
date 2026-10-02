// The explorer table's layout, the words the logic does not hold: the columns'
// headers and widths, and the filters' labels and placeholders.
import { FILTER_CONFIG } from '@/logic/mds/constants.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';

// The 13 columns, in order, with their headers; `list` names the
// entry's list a tag column shows. The widths are where each column starts (the
// ID column fits a whole AAGUID and its copy button; on a phone the Icon column
// starts narrower, only as wide as its icon); a person can resize them.
export const EXPLORER_COLUMNS = [
  { key: 'icon', header: 'Icon', width: 72, phoneWidth: 44, min: 40 },
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
] as const satisfies readonly { key: string; header: string; width: number; phoneWidth?: number; min?: number; list?: keyof MdsEntry }[];

export type ExplorerColumn = (typeof EXPLORER_COLUMNS)[number];

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

export const EXPLORER_FILTERS = FILTER_CONFIG.map((config) => ({
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
