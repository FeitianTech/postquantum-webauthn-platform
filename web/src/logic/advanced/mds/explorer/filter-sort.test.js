import { describe, expect, it } from 'vitest';

import {
  DEFAULT_SORT_DIRECTION,
  DEFAULT_SORT_KEY,
  MDS_SORT_ACCESSORS,
  SORT_ASCENDING,
  SORT_DESCENDING,
  SORT_NONE,
  compareExplorerSortValues,
  countActiveExplorerFilters,
  defaultExplorerSort,
  filterAndSortExplorerEntries,
  isExplorerSortKey,
  matchesExplorerFilters,
  nextExplorerSort,
  nextExplorerSortDirection,
  sortExplorerEntries,
} from './filter-sort.js';

const CERTIFICATION_OPTIONS = ['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2', 'NOT FIDO Certified', 'Revoked'];

const L1 = { name: 'Key L1', certification: 'FIDO Certified L1 • Key • (FIDO2)', certificationStatus: 'FIDO_CERTIFIED_L1' };
const L2 = { name: 'Key L2', certification: 'FIDO Certified L2', certificationStatus: 'FIDO_CERTIFIED_L2' };
const NOT = { name: 'Plain', certification: 'NOT FIDO Certified', certificationStatus: 'NOT_FIDO_CERTIFIED' };
const DISPLAY_ONLY = { name: 'Display', certification: 'FIDO Certified L2 • Old' };

describe('sort order', () => {
  it('names the directions and the default', () => {
    expect([SORT_NONE, SORT_ASCENDING, SORT_DESCENDING]).toEqual(['none', 'asc', 'desc']);
    expect(defaultExplorerSort()).toEqual({ key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION });
    expect(defaultExplorerSort()).toEqual({ key: 'dateUpdated', direction: 'desc' });
  });

  it('reads each column the way it sorts', () => {
    const entry = {
      icon: 'data:image/png;base64,AA',
      name: 'Name',
      protocol: 'FIDO2',
      certification: 'C',
      id: 'I',
      userVerification: 'U',
      attachment: 'A',
      transports: 'T',
      keyProtection: 'K',
      algorithms: 'G',
      algorithmInfo: 'AI',
      commonName: 'CN',
      dateTooltip: '2023-09-18',
    };
    expect(MDS_SORT_ACCESSORS.icon(entry)).toBe('1_Name');
    expect(MDS_SORT_ACCESSORS.icon({ name: 7 })).toBe('0_');
    expect(Object.keys(MDS_SORT_ACCESSORS).filter(key => !['icon', 'dateUpdated'].includes(key))
      .map(key => MDS_SORT_ACCESSORS[key](entry))).toEqual(['Name', 'FIDO2', 'C', 'I', 'U', 'A', 'T', 'K', 'G', 'AI', 'CN']);
    expect(MDS_SORT_ACCESSORS.dateUpdated(entry)).toBe(Date.parse('2023-09-18'));
    expect(MDS_SORT_ACCESSORS.dateUpdated({ dateTooltip: 'someday' })).toBe('someday');
    expect(MDS_SORT_ACCESSORS.dateUpdated({ dateUpdated: 'Sep 18, 2023' })).toBe('Sep 18, 2023');
  });

  it('falls back to the joined certificate text, then to nothing', () => {
    expect(MDS_SORT_ACCESSORS.algorithmInfo({ certificateAlgorithmInfo: 'X' })).toBe('X');
    expect(MDS_SORT_ACCESSORS.commonName({ certificateCommonNames: 'Y' })).toBe('Y');
    for (const accessor of Object.values(MDS_SORT_ACCESSORS)) {
      expect(accessor(undefined)).toEqual(expect.any(String));
    }
  });

  it('compares by value, then lower-cased text, then text, then index', () => {
    const byName = MDS_SORT_ACCESSORS.name;
    expect(compareExplorerSortValues({ name: 'a' }, { name: 'b' }, byName)).toBe(-1);
    expect(compareExplorerSortValues({ name: 'b' }, { name: 'a' }, byName)).toBe(1);
    expect(compareExplorerSortValues({ name: '01' }, { name: '1' }, byName)).toBe(-1);
    expect(compareExplorerSortValues({ name: '1' }, { name: '01' }, byName)).toBe(1);
    expect(compareExplorerSortValues({ name: 'A' }, { name: 'a' }, byName)).toBe(-1);
    expect(compareExplorerSortValues({ name: 'a' }, { name: 'A' }, byName)).toBe(1);
    expect(compareExplorerSortValues({ name: 'a', index: 4 }, { name: 'a', index: 1 }, byName)).toBe(3);
    expect(compareExplorerSortValues({ name: 'a' }, { name: 'a', index: 2 }, byName)).toBe(-2);
    expect(compareExplorerSortValues({}, {}, () => null)).toBe(0);
  });

  it('sorts a copy, descending as ascending reversed', () => {
    const entries = [{ name: 'b', index: 0 }, { name: 'a', index: 1 }, { name: 'c', index: 2 }];
    expect(sortExplorerEntries(entries, { key: 'name', direction: 'asc' }).map(entry => entry.name)).toEqual(['a', 'b', 'c']);
    expect(sortExplorerEntries(entries, { key: 'name', direction: 'desc' }).map(entry => entry.name)).toEqual(['c', 'b', 'a']);
    expect(entries.map(entry => entry.name)).toEqual(['b', 'a', 'c']);
  });

  it('keeps the order when there is nothing to sort by', () => {
    const entries = [{ name: 'b' }, { name: 'a' }];
    expect(sortExplorerEntries('nope', null)).toEqual([]);
    for (const sort of [null, { key: '', direction: 'asc' }, { key: 'name', direction: 'none' }, { key: 'nope', direction: 'asc' }]) {
      const sorted = sortExplorerEntries(entries, sort);
      expect(sorted).toEqual(entries);
      expect(sorted).not.toBe(entries);
    }
  });
});

describe('sort clicks', () => {
  it('cycles a column none, ascending, descending, none', () => {
    expect(nextExplorerSortDirection('name', 'none')).toBe('asc');
    expect(nextExplorerSortDirection('name', 'asc')).toBe('desc');
    expect(nextExplorerSortDirection('name', 'desc')).toBe('none');
    expect(nextExplorerSortDirection('name', undefined)).toBe('asc');
    expect(nextExplorerSortDirection('name', 'sideways')).toBe('asc');
    expect(nextExplorerSortDirection(7, 'asc')).toBe('desc');
  });

  it('cycles Date Updated between descending and ascending', () => {
    expect(nextExplorerSortDirection('dateUpdated', 'none')).toBe('desc');
    expect(nextExplorerSortDirection('dateUpdated', 'asc')).toBe('desc');
    expect(nextExplorerSortDirection('dateUpdated', 'desc')).toBe('asc');
    expect(nextExplorerSortDirection('dateUpdated', 'sideways')).toBe('asc');
  });

  it('knows which columns sort', () => {
    expect(isExplorerSortKey('commonName')).toBe(true);
    expect(isExplorerSortKey('toString')).toBe(false);
    expect(isExplorerSortKey('')).toBe(false);
    expect(isExplorerSortKey(null)).toBe(false);
  });

  it('gives the sort after a click, restoring the default at none', () => {
    expect(nextExplorerSort(defaultExplorerSort(), 'name')).toEqual({ key: 'name', direction: 'asc' });
    expect(nextExplorerSort({ key: 'name', direction: 'asc' }, 'name')).toEqual({ key: 'name', direction: 'desc' });
    expect(nextExplorerSort({ key: 'name', direction: 'desc' }, 'name')).toEqual(defaultExplorerSort());
    expect(nextExplorerSort({ key: 'name', direction: undefined }, 'name')).toEqual({ key: 'name', direction: 'asc' });
    expect(nextExplorerSort(null, 'dateUpdated')).toEqual({ key: 'dateUpdated', direction: 'asc' });
    expect(nextExplorerSort(defaultExplorerSort(), 'nope')).toBeNull();
  });

});

describe('filters', () => {
  it('lets every entry through an empty filter', () => {
    expect(matchesExplorerFilters(NOT, { name: '', protocol: '' })).toBe(true);
  });

  it('finds the text in the column, ignoring case', () => {
    expect(matchesExplorerFilters({ commonName: 'Yubico U2F Root CA' }, { commonName: 'u2f root' })).toBe(true);
    expect(matchesExplorerFilters({ commonName: 'Yubico' }, { commonName: 'feitian' })).toBe(false);
    expect(matchesExplorerFilters({}, { commonName: 'x' })).toBe(false);
  });

  it('matches a named certification level exactly, and FIDO Certified to every level', () => {
    const match = value => [L1, L2, NOT].filter(entry => matchesExplorerFilters(entry, { certification: value }, CERTIFICATION_OPTIONS));
    expect(match('FIDO Certified L2')).toEqual([L2]);
    expect(match('fido certified')).toEqual([L1, L2]);
    expect(match('NOT FIDO Certified')).toEqual([NOT]);
  });

  it('reads the level from the text when the entry has no status', () => {
    expect(matchesExplorerFilters(DISPLAY_ONLY, { certification: 'FIDO Certified L2' }, CERTIFICATION_OPTIONS)).toBe(true);
    expect(matchesExplorerFilters(DISPLAY_ONLY, { certification: 'FIDO Certified' }, CERTIFICATION_OPTIONS)).toBe(true);
    expect(matchesExplorerFilters({}, { certification: 'FIDO Certified' }, CERTIFICATION_OPTIONS)).toBe(false);
    expect(matchesExplorerFilters({}, { certification: 'Revoked' }, CERTIFICATION_OPTIONS)).toBe(false);
  });

  it('finds other certification text anywhere in the text or the status', () => {
    expect(matchesExplorerFilters(L1, { certification: 'key •' }, CERTIFICATION_OPTIONS)).toBe(true);
    expect(matchesExplorerFilters(L1, { certification: 'certified_l1' })).toBe(true);
    expect(matchesExplorerFilters(L1, { certification: '•' })).toBe(true);
    expect(matchesExplorerFilters(L1, { certification: 'revoked' })).toBe(false);
    expect(matchesExplorerFilters({}, { certification: 'x' })).toBe(false);
  });

  it('filters, then sorts', () => {
    const entries = [{ name: 'b key' }, { name: 'a key' }, { name: 'other' }];
    expect(filterAndSortExplorerEntries(entries, { name: 'key' }, { key: 'name', direction: 'asc' })).toEqual([
      { name: 'a key' },
      { name: 'b key' },
    ]);
  });

  it('counts the filters in use', () => {
    expect(countActiveExplorerFilters({ name: 'x', id: ' ', protocol: 'FIDO2', other: 3 })).toBe(2);
    expect(countActiveExplorerFilters(null)).toBe(0);
  });
});
