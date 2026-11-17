import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { FILTER_CONFIG } from '../constants.js';
import {
  NO_MATCHING_OPTIONS,
  collectOptionSets,
  explorerFilterOptionLists,
  matchingFilterOptions,
  mergeFilterOptions,
  sortFilterOptions,
  staticFilterOptions,
} from './options.js';
import { repoFile } from '@/test/logic/repo-file.js';

// How the server spells each MDS value (tests/app/metadata/test_mds_statement_fields.py reads it too).
const { spellings } = JSON.parse(readFileSync(repoFile('tests/fixtures/mds-enum-spellings.json'), 'utf8'));

const filterConfig = (key) => FILTER_CONFIG.find((config) => config.key === key);

const ENTRY = {
  protocol: 'FIDO2',
  certification: 'FIDO Certified L3+ • Key • (FIDO3)',
  latestStatus: 'Update Available',
  userVerificationList: ['Presence Internal', 'None'],
  attachmentList: ['External'],
  transportsList: ['USB', 'NFC'],
  keyProtectionList: ['Hardware'],
  algorithmsList: ['Ed25519 EdDSA SHA512 Raw'],
};
const BARE = { ...ENTRY, protocol: '', certification: '', latestStatus: undefined };

const STATIC_CERTIFICATION = ['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2'];
const STATIC_STATUS = ['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2', 'Not FIDO Certified', 'Revoked'];

describe('filter options', () => {
  it('collects every value present, and the static statuses', () => {
    const sets = collectOptionSets([ENTRY, BARE]);
    expect([...sets.protocol]).toEqual(['FIDO2']);
    expect([...sets.certification]).toEqual([...STATIC_CERTIFICATION, 'FIDO Certified L3+']);
    expect([...sets.latestStatus]).toEqual([...STATIC_STATUS, 'Update Available']);
    expect([...sets.userVerification]).toEqual(['Presence Internal', 'None']);
    expect([...sets.attachment]).toEqual(['External']);
    expect([...sets.transports]).toEqual(['USB', 'NFC']);
    expect([...sets.keyProtection]).toEqual(['Hardware']);
    expect([...sets.algorithms]).toEqual(['Ed25519 EdDSA SHA512 Raw']);
  });

  it('gives a filter its static options', () => {
    expect(staticFilterOptions(filterConfig('certification'))).toEqual(STATIC_CERTIFICATION);
    expect(staticFilterOptions(filterConfig('latestStatus'))).toEqual(STATIC_STATUS);
    expect(staticFilterOptions(filterConfig('protocol'))).toEqual([]);
    expect(staticFilterOptions(undefined)).toEqual([]);
    expect(staticFilterOptions({ staticOptions: ['', 'Revoked'] })).toEqual(['Revoked']);
  });

  it('spells the static statuses as the server spells them', () => {
    const statuses = ['FIDO_CERTIFIED', 'FIDO_CERTIFIED_L1', 'FIDO_CERTIFIED_L2', 'NOT_FIDO_CERTIFIED', 'REVOKED'];
    expect(STATIC_STATUS).toEqual(statuses.map(status => spellings[status]));
    expect(STATIC_CERTIFICATION).toEqual(statuses.slice(0, 3).map(status => spellings[status]));
  });

  it('merges the values with the static options, once each', () => {
    expect(mergeFilterOptions(new Set(['Revoked', '', 'X']), filterConfig('latestStatus'))).toEqual([
      'Revoked',
      'X',
      'FIDO Certified',
      'FIDO Certified L1',
      'FIDO Certified L2',
      'Not FIDO Certified',
    ]);
    expect(mergeFilterOptions(new Set(['FIDO Certified L3']), filterConfig('certification'))).toEqual([
      'FIDO Certified L3',
      'FIDO Certified',
      'FIDO Certified L1',
      'FIDO Certified L2',
    ]);
    expect(mergeFilterOptions(['a'], undefined)).toEqual(['a']);
  });

  it('sorts the list ignoring case and accents, once each', () => {
    expect(sortFilterOptions(['b', 'A', '', 'a', 'É', 'e'])).toEqual(['A', 'a', 'b', 'É', 'e']);
  });

  it('narrows the list to the options containing the text', () => {
    const options = ['Fingerprint Internal', 'Passcode External', 'None'];
    expect(matchingFilterOptions(options, '')).toEqual(options);
    expect(matchingFilterOptions(options, undefined)).not.toBe(options);
    expect(matchingFilterOptions(options, ' TERN ')).toEqual(['Fingerprint Internal', 'Passcode External']);
    expect(NO_MATCHING_OPTIONS).toBe('No matches');
  });

  it('gives every option filter its list', () => {
    expect(explorerFilterOptionLists([])).toEqual({
      protocol: [],
      certification: STATIC_CERTIFICATION,
      latestStatus: STATIC_STATUS,
      userVerification: [],
      attachment: [],
      transports: [],
      keyProtection: [],
      algorithms: [],
    });
    const lists = explorerFilterOptionLists([ENTRY]);
    expect(lists.userVerification).toEqual(['None', 'Presence Internal']);
    expect(lists.certification).toContain('FIDO Certified L3+');
    expect(lists.latestStatus).toContain('Update Available');
    expect(Object.keys(lists)).toHaveLength(8);
  });
});
