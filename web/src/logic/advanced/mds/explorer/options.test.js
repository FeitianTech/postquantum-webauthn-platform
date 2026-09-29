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

const filterConfig = (key) => FILTER_CONFIG.find((config) => config.key === key);

const ENTRY = {
  protocol: 'FIDO2',
  certificationStatus: 'FIDO_CERTIFIED_L3PLUS',
  userVerificationList: ['Presence Internal', 'None'],
  attachmentList: ['External'],
  transportsList: ['Usb', 'Nfc'],
  keyProtectionList: ['Hardware'],
  algorithmsList: ['ED25519 Eddsa SHA512 Raw'],
};
const BARE = { ...ENTRY, protocol: '', certificationStatus: '' };

const STATIC_CERTIFICATION = ['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2', 'NOT FIDO Certified', 'Revoked'];

describe('filter options', () => {
  it('collects every value present, and the static statuses', () => {
    const sets = collectOptionSets([ENTRY, BARE]);
    expect([...sets.protocol]).toEqual(['FIDO2']);
    expect([...sets.certification]).toEqual([...STATIC_CERTIFICATION, 'FIDO Certified L3plus']);
    expect([...sets.userVerification]).toEqual(['Presence Internal', 'None']);
    expect([...sets.attachment]).toEqual(['External']);
    expect([...sets.transports]).toEqual(['Usb', 'Nfc']);
    expect([...sets.keyProtection]).toEqual(['Hardware']);
    expect([...sets.algorithms]).toEqual(['ED25519 Eddsa SHA512 Raw']);
  });

  it('formats a filter static options', () => {
    expect(staticFilterOptions(filterConfig('certification'))).toEqual(STATIC_CERTIFICATION);
    expect(staticFilterOptions(filterConfig('protocol'))).toEqual([]);
    expect(staticFilterOptions(undefined)).toEqual([]);
    expect(staticFilterOptions({ staticOptions: ['', 'REVOKED'] })).toEqual(['Revoked']);
  });

  it('merges the values with the static options, once each', () => {
    expect(mergeFilterOptions(new Set(['Revoked', '', 'X']), filterConfig('certification'))).toEqual([
      'Revoked',
      'X',
      'FIDO Certified',
      'FIDO Certified L1',
      'FIDO Certified L2',
      'NOT FIDO Certified',
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
      userVerification: [],
      attachment: [],
      transports: [],
      keyProtection: [],
      algorithms: [],
    });
    const lists = explorerFilterOptionLists([ENTRY]);
    expect(lists.userVerification).toEqual(['None', 'Presence Internal']);
    expect(lists.certification).toContain('FIDO Certified L3plus');
    expect(Object.keys(lists)).toHaveLength(7);
  });
});
