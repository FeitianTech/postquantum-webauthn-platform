import { describe, expect, it } from 'vitest';

import { createExplorerSource } from './explorer-source.js';

// Where the explorer's snapshot is asked for (mds/explorer-source.js).

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
