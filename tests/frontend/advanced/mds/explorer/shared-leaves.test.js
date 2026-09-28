// The modules the MDS explorer's logic stands on, which web/ imports through
// explorer/*.js: every branch.
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createExplorerSource } from '../../../../../frontend/static/scripts/advanced/mds/metadata/explorer-source.js';
import {
  cloneMetadataEntry,
  extractSnapshotTimestamp,
  formatInitialExplorerStatus,
  formatSnapshotTimestamp,
  normaliseFileList,
  normaliseSnapshotInfo,
} from '../../../../../frontend/static/scripts/advanced/mds/metadata/metadata-helpers.js';
import { normaliseSortValueInput } from '../../../../../frontend/static/scripts/advanced/mds/sort-filter-normalise.js';
import {
  extractAttestationKeyIdentifiers,
  extractUserVerification,
} from '../../../../../frontend/static/scripts/advanced/mds/utils/extractors.js';
import {
  formatCertificateDateDisplay,
  formatCertification,
  formatProtocol,
  formatSignatureHashName,
  formatUpv,
} from '../../../../../frontend/static/scripts/advanced/mds/utils/formatters.js';
import {
  formatGuidCandidate,
  normaliseAaguid,
  normaliseIcon,
  resolveName,
} from '../../../../../frontend/static/scripts/advanced/mds/utils/resolvers.js';
import { sortStatusReportsByEffectiveDateDesc } from '../../../../../frontend/static/scripts/advanced/mds/utils/status-reports.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('sort values', () => {
  it('reads a date as its time and a dash or blank as nothing', () => {
    const date = new Date('2023-09-18T00:00:00Z');
    expect(normaliseSortValueInput(date)).toBe(date.getTime());
    expect(normaliseSortValueInput('—')).toBe('');
    expect(normaliseSortValueInput('   ')).toBe('');
  });

  it('keeps a number as it is', () => {
    expect(normaliseSortValueInput(42)).toBe(42);
  });
});

describe('the explorer\'s source', () => {
  it('asks the API afresh for a reload, and when the page names no session state', () => {
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 42 });
    expect(source.resolve()).toEqual({ url: '/api/mds/metadata/explorer/full', cache: 'no-store', kind: 'api' });
    expect(source.resolve({ forceReload: true })).toEqual({ url: '/api/mds/metadata/explorer/full', cache: 'reload', kind: 'api' });
    expect(source.fallback({ forceReload: true }).cache).toBe('reload');
  });

  it('follows what a snapshot says of the session\'s uploads, and nothing else', () => {
    const source = createExplorerSource({ snapshotUrl: '/snap.json', customEntriesState: 'unknown' });
    source.noteSnapshotMeta({ hasCustomEntries: false });
    expect(source.resolve().kind).toBe('static');
    source.noteSnapshotMeta(null);
    source.noteSnapshotMeta({ hasCustomEntries: 'yes' });
    expect(source.resolve().kind).toBe('static');
    source.noteSnapshotMeta({ hasCustomEntries: true });
    expect(source.resolve().kind).toBe('api');
  });
});

describe('snapshot helpers', () => {
  it('reads nothing from what is not an object', () => {
    expect(normaliseSnapshotInfo('text')).toBeNull();
    expect(extractSnapshotTimestamp(null)).toBeNull();
    expect(formatInitialExplorerStatus(undefined)).toBe(
      'Packaged FIDO metadata is available. Explorer data is loading in the background.',
    );
  });

  it('keeps an entry that cannot be copied', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const entry = { name: 'loop' };
    entry.self = entry;
    expect(cloneMetadataEntry(entry)).toBe(entry);
    expect(warn).toHaveBeenCalled();
  });

  it('lists no files from nothing', () => {
    expect(normaliseFileList(null)).toEqual([]);
  });

  it('lists the files of a list, and nothing else in it', () => {
    const file = new File(['{}'], 'custom.json');
    expect(normaliseFileList([file, 'custom.json', null])).toEqual([file]);
  });

  it('trims a summary\'s text and keeps its other values', () => {
    expect(normaliseSnapshotInfo({ no: 7, generatedAt: ' 2025-01-02T03:04:05Z ' })).toEqual({ no: 7, generatedAt: '2025-01-02T03:04:05Z' });
  });

  it('says a snapshot\'s number, count and date, and a date it cannot read as it is', () => {
    expect(formatSnapshotTimestamp({})).toBeNull();
    expect(formatSnapshotTimestamp({ generatedAt: 'last Tuesday' })).toBe('last Tuesday');
    const sentence = formatInitialExplorerStatus({ no: 7, entryCount: 1234, generatedAt: '2025-01-02T03:04:05Z' });
    expect(sentence).toMatch(/^Snapshot 7 • 1,234 authenticators • last updated .+\. Explorer data is loading in the background\.$/);
    expect(formatInitialExplorerStatus({ fetchedAt: 'last Tuesday' })).toBe(
      'last updated last Tuesday. Explorer data is loading in the background.',
    );
    expect(formatInitialExplorerStatus({ entryCount: 'many' })).toBe(
      'Packaged FIDO metadata is available. Explorer data is loading in the background.',
    );
  });
});

describe('extractors', () => {
  it('skips key identifiers that are missing or blank', () => {
    expect(extractAttestationKeyIdentifiers({ attestationCertificateKeyIdentifiers: ['AB', ' ', 'ab'] }, { attestationCertificateKeyIdentifiers: 'cd' }))
      .toEqual(['AB', 'cd']);
    expect(extractAttestationKeyIdentifiers({ attestationCertificateKeyIdentifiers: [0] }, null)).toEqual([]);
  });

  it('reads user verification only from combinations of methods', () => {
    expect(extractUserVerification('none')).toEqual([]);
    expect(extractUserVerification(['not a group', [null, {}, { userVerificationMethod: 'passcode_internal' }]])).toEqual([
      'Passcode Internal',
    ]);
  });
});

describe('formatters', () => {
  it('writes the versions as major.minor', () => {
    expect(formatUpv([{ major: 1, minor: 2 }, null, { major: 1 }])).toEqual(['1.2']);
    expect(formatUpv({ Major: 1, Minor: 0 })).toEqual(['1.0']);
    expect(formatUpv(null)).toEqual([]);
  });

  it('writes no protocol for none', () => {
    expect(formatProtocol('')).toBe('');
  });

  it('writes the certification from what the latest report has', () => {
    expect(formatCertification([{ effectiveDate: '2024-01-01', status: 7 }])).toEqual({ display: '', status: '' });
    expect(formatCertification([{ effectiveDate: '2024-01-01', certificationDescriptor: 'Key', certificateNumber: 'N1' }])).toEqual({
      display: 'Key • (N1)',
      status: '',
    });
  });

  it('writes a certificate date, or nothing for what is not one', () => {
    expect(formatCertificateDateDisplay({})).toBe('');
    expect(formatCertificateDateDisplay('someday')).toBe('someday');
  });

  it('writes no hash name for a blank one', () => {
    expect(formatSignatureHashName('  ')).toBe('');
  });
});

describe('resolvers', () => {
  it('keeps no icon for a blank one and types a bare one as PNG', () => {
    expect(normaliseIcon('   ')).toBe('');
    expect(normaliseIcon('AAAA')).toBe('data:image/png;base64,AAAA');
    expect(normaliseIcon('AAAA', ' image/svg+xml ')).toBe('data:image/svg+xml;base64,AAAA');
  });

  it('looks past empty descriptions for a name', () => {
    expect(resolveName({ description: { en: '' }, alternativeDescriptions: 'plain' }, { statusReports: [] })).toBe('Unknown Authenticator');
    expect(resolveName({ alternativeDescriptions: { de: 3, fr: ' Clé ' } }, null)).toBe('Clé');
    expect(resolveName({ alternativeDescriptions: { de: '' } }, null)).toBe('Unknown Authenticator');
  });

  it('reads no GUID from a value with no text form', () => {
    expect(formatGuidCandidate(Object.create(null))).toBe('');
    expect(
      formatGuidCandidate({
        toString() {
          throw new Error('no');
        },
      }),
    ).toBe('');
  });
});

describe('status reports', () => {
  it('puts reports without a date last', () => {
    const sorted = sortStatusReportsByEffectiveDateDesc([{ status: 'A' }, { effectiveDate: '2024-01-01' }, null, { effectiveDate: 'soon' }]);
    expect(sorted[0]).toEqual({ effectiveDate: '2024-01-01' });
  });
});

describe('names and identifiers', () => {
  it('names no hash from what is not text, and reads a blank AAGUID as none', () => {
    expect(formatSignatureHashName(42)).toBe('');
    expect(normaliseAaguid('   ')).toBe('');
  });
});
