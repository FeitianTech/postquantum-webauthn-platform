// The explorer table's words the logic does not hold, and its layout: the
// columns' headers and where each sits in a row's two lines, and the filters'
// labels and placeholders.
import { FILTER_CONFIG } from '@/logic/mds/constants.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';

// Not shown, but still read by a screen reader as its row's cell: a cell taken out
// of the page would shift the ones after it under the wrong header.
export const HIDDEN = 'sr-only';
// A header not shown: its sort button out of the tab order too.
const HIDDEN_HEAD = 'sr-only *:invisible';

export type ExplorerColumn = {
  key: string;
  header: string;
  /** The entry's list a tag column shows. */
  list?: keyof MdsEntry;
  /** Its cell in a collapsed row: where it sits in the two lines, hidden at the widths that give it no column. */
  cell: string;
  /** An expanded row shows it as a labelled line under the two lines. */
  detail?: true;
  /** Its list runs onto the row's second line. */
  clamp?: true;
  /** Its header: where its cell sits, hidden where that is. */
  head: string;
};

// The 14 columns, in order. Every class is written whole: Tailwind reads this
// file's text.
export const EXPLORER_COLUMNS = [
  { key: 'icon', header: 'Icon', cell: 'row-start-1 col-start-1 self-center pr-0 md:row-span-2', head: HIDDEN_HEAD },
  { key: 'name', header: 'Name', cell: 'row-start-1 col-[2/-1] font-medium md:col-[2/3]', head: 'row-start-1 col-start-2 pl-10' },
  {
    key: 'protocol',
    header: 'Protocol',
    cell: 'row-start-3 col-start-3 text-caption text-ink-muted md:row-start-2',
    head: 'row-start-2 col-start-3',
  },
  { key: 'certification', header: 'Certification', cell: HIDDEN, detail: true, head: HIDDEN_HEAD },
  { key: 'latestStatus', header: 'Status', cell: 'row-start-3 col-[1/3] md:row-start-1 md:col-[3/4]', head: 'row-start-1 col-start-3' },
  {
    key: 'id',
    header: 'ID',
    cell: 'row-start-2 col-span-full font-mono text-caption text-ink-muted md:col-[2/3] md:pl-10',
    head: 'row-start-2 col-start-2 pl-10',
  },
  {
    key: 'userVerification',
    header: 'User Verification',
    list: 'userVerificationList',
    cell: 'text-caption max-[88rem]:sr-only min-[88rem]:col-start-5 min-[88rem]:row-span-2 min-[88rem]:row-start-1',
    detail: true,
    clamp: true,
    head: 'max-[88rem]:sr-only max-[88rem]:*:invisible min-[88rem]:col-start-5 min-[88rem]:row-start-1',
  },
  {
    key: 'attachment',
    header: 'Attachment',
    list: 'attachmentList',
    cell: 'text-caption text-ink-muted max-lg:sr-only lg:col-start-4 lg:row-start-2',
    detail: true,
    head: 'max-lg:sr-only max-lg:*:invisible lg:col-start-4 lg:row-start-2',
  },
  {
    key: 'transports',
    header: 'Transports',
    list: 'transportsList',
    cell: 'max-lg:sr-only lg:col-start-4 lg:row-start-1',
    detail: true,
    head: 'max-lg:sr-only max-lg:*:invisible lg:col-start-4 lg:row-start-1',
  },
  { key: 'keyProtection', header: 'Key Protection', list: 'keyProtectionList', cell: HIDDEN, detail: true, head: HIDDEN_HEAD },
  {
    key: 'algorithms',
    header: 'Algorithms',
    list: 'algorithmsList',
    cell: 'text-caption max-[72rem]:sr-only min-[72rem]:col-[-3/-2] min-[72rem]:row-span-2 min-[72rem]:row-start-1',
    detail: true,
    clamp: true,
    head: 'max-[72rem]:sr-only max-[72rem]:*:invisible min-[72rem]:col-[-3/-2] min-[72rem]:row-start-1',
  },
  { key: 'algorithmInfo', header: 'Algorithm Info', list: 'certificateAlgorithmInfoList', cell: HIDDEN, detail: true, head: HIDDEN_HEAD },
  { key: 'commonName', header: 'CN', list: 'certificateCommonNameList', cell: HIDDEN, detail: true, head: HIDDEN_HEAD },
  {
    key: 'dateUpdated',
    header: 'Date Updated',
    cell: 'row-start-3 col-[-2/-1] justify-self-end text-label text-ink-muted tabular-nums md:row-start-1 md:justify-self-auto',
    head: 'col-[-2/-1] row-start-1',
  },
] as const satisfies readonly ExplorerColumn[];

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
