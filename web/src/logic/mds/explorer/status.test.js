import { describe, expect, it } from 'vitest';

import {
  buildLoadedStatus,
  explorerLoadedStatus,
  explorerLoadingStatus,
  extractSnapshotTimestamp,
  formatEntryCount,
  formatInitialExplorerStatus,
  formatSnapshotTimestamp,
  normaliseSnapshotInfo,
} from './status.js';

const noDate = () => null;

describe('explorer status sentences', () => {
  it('says what is loading', () => {
    expect(explorerLoadingStatus(false)).toBe('Loading authenticator explorer…');
    expect(explorerLoadingStatus(true)).toBe('Refreshing authenticator explorer…');
  });

});

describe('the loaded sentence', () => {
  it('counts the entries, then the date, the session entries and the note', () => {
    const snapshot = { meta: { customEntryCount: 1 }, entries: [{}, {}] };
    expect(buildLoadedStatus(snapshot, 'Custom metadata updated.', () => 'Sep 16, 2026')).toBe(
      'Loaded 2 authenticators. Last updated Sep 16, 2026. Including 1 session metadata entry. Custom metadata updated.',
    );
    expect(buildLoadedStatus({ meta: { customEntryCount: 3 }, entries: [] }, '', noDate)).toBe(
      'Loaded 0 authenticators. Including 3 session metadata entries.',
    );
  });

  it('leaves out what is not known', () => {
    expect(buildLoadedStatus(null, '', noDate)).toBe('Loaded 0 authenticators.');
    expect(buildLoadedStatus({ meta: 'x', entries: 'y' }, undefined, noDate)).toBe('Loaded 0 authenticators.');
    expect(buildLoadedStatus({ meta: { customEntryCount: 0 }, entries: [{}] }, '', noDate)).toBe('Loaded 1 authenticators.');
    expect(buildLoadedStatus({ meta: { customEntryCount: '2' }, entries: [] }, '', noDate)).toBe('Loaded 0 authenticators.');
  });

  it('reads the date from the snapshot by default', () => {
    const text = buildLoadedStatus({ meta: { generatedAt: 'not a date' }, entries: [{}] }, '');
    expect(text).toBe('Loaded 1 authenticators. Last updated not a date.');
  });

  it('gives the line its variant and the legal header as its title', () => {
    const snapshot = { meta: { legalHeader: 'Terms.' }, entries: [{}] };
    expect(explorerLoadedStatus(snapshot, '', 1, () => 'Text.')).toEqual({ text: 'Text.', variant: 'success', title: 'Terms.' });
    expect(explorerLoadedStatus({ meta: { legalHeader: 3 } }, '', 0, () => 'Empty.')).toEqual({
      text: 'Empty.',
      variant: 'info',
      title: '',
    });
    expect(explorerLoadedStatus(null, 'Note.', 0)).toEqual({ text: 'Loaded 0 authenticators. Note.', variant: 'info', title: '' });
  });
});

describe('the count', () => {
  it('shows the entries shown and, when there are any, the total', () => {
    expect(formatEntryCount(12, 517)).toEqual({ count: (12).toLocaleString(), total: `of ${(517).toLocaleString()} total` });
    expect(formatEntryCount(0, 0)).toEqual({ count: '0', total: '' });
  });
});

describe('the packaged snapshot\'s summary', () => {
  it('reads nothing from what is not an object', () => {
    expect(normaliseSnapshotInfo('text')).toBeNull();
    expect(extractSnapshotTimestamp(null)).toBeNull();
    expect(formatInitialExplorerStatus(undefined)).toBe(
      'Packaged FIDO metadata is available. Explorer data is loading in the background.',
    );
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
