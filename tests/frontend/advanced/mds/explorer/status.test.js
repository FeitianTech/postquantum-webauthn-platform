import { describe, expect, it } from 'vitest';

import {
  EXPLORER_BUSY_STATUS,
  EXPLORER_NO_MATCHES,
  EXPLORER_REFRESHED_NOTE,
  buildLoadedStatus,
  explorerLoadedStatus,
  explorerLoadingStatus,
  explorerRefreshFailure,
  formatEntryCount,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/status.js';

const noDate = () => null;

describe('explorer status sentences', () => {
  it('says what is loading', () => {
    expect(explorerLoadingStatus(false)).toBe('Loading authenticator explorer…');
    expect(explorerLoadingStatus(true)).toBe('Refreshing authenticator explorer…');
  });

  it('keeps the fixed sentences', () => {
    expect(EXPLORER_BUSY_STATUS).toBe('Metadata is currently loading. Please wait for the current operation to finish.');
    expect(EXPLORER_REFRESHED_NOTE).toBe('Explorer refreshed.');
    expect(EXPLORER_NO_MATCHES).toBe('No authenticators match the selected filters.');
  });

  it('words a refresh failure', () => {
    expect(explorerRefreshFailure(new Error('Down.'))).toBe('Down.');
    expect(explorerRefreshFailure(new Error(''))).toBe('Unable to refresh the packaged authenticator explorer.');
    expect(explorerRefreshFailure(undefined)).toBe('Unable to refresh the packaged authenticator explorer.');
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
