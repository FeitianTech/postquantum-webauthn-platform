import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CUSTOM_METADATA_DELETE_PATH,
  CUSTOM_METADATA_LIST_PATH,
  CUSTOM_METADATA_UPLOAD_PATH,
} from '../constants.js';
import {
  buildCustomMetadataForm,
  customMetadataItemLabel,
  describeCustomMetadataItem,
  describeDeleteAnswer,
  describeFileSelection,
  describeUploadAnswer,
  mergeCustomEntries,
  removedCustomMetadataMessage,
  removingCustomMetadataMessage,
  requestCustomMetadataDelete,
  requestCustomMetadataList,
  requestCustomMetadataUpload,
} from './custom-metadata.js';

function answer(body, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    json: async () => {
      if (body instanceof Error) {
        throw body;
      }
      return body;
    },
  };
}

const json = name => new File(['{}'], name, { type: 'application/json' });

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Manage Trusted Metadata: its words', () => {
  it('names a file being removed', () => {
    expect(customMetadataItemLabel('  statement.json ')).toBe('statement.json');
    expect(customMetadataItemLabel('')).toBe('metadata file');
    expect(customMetadataItemLabel(undefined)).toBe('metadata file');
    expect(removingCustomMetadataMessage('a.json')).toBe('Removing a.json…');
    expect(removedCustomMetadataMessage('a.json')).toBe('a.json removed.');
  });
});

describe('Manage Trusted Metadata: choosing files', () => {
  it('sends the JSON files and says nothing more', () => {
    const files = [json('a.json'), json('B.JSON')];
    expect(describeFileSelection(files)).toEqual({ accepted: files, message: null });
  });

  it('names the files refused', () => {
    const accepted = json('a.json');
    const result = describeFileSelection([accepted, new File(['x'], 'notes.txt'), { name: 7 }, null]);
    expect(result.accepted).toEqual([accepted]);
    expect(result.message).toEqual({ text: 'Ignored non-JSON files: notes.txt, Unnamed file', variant: 'warning' });
  });

  it('asks for files when there are none', () => {
    expect(describeFileSelection([])).toEqual({
      accepted: [],
      message: { text: 'Please select one or more JSON files.', variant: 'warning' },
    });
  });

  it('puts each file in the form under files, a nameless one as metadata.json', () => {
    const form = buildCustomMetadataForm([json('a.json'), new Blob(['{}'])]);
    const names = form.getAll('files').map(file => file.name);
    expect(names).toEqual(['a.json', 'metadata.json']);
  });
});

describe('Manage Trusted Metadata: uploading', () => {
  it('posts the files and reads the answer', async () => {
    globalThis.fetch = vi.fn(async () => answer({ items: [] }));
    const signal = new AbortController().signal;
    const result = await requestCustomMetadataUpload([json('a.json')], { signal });
    expect(globalThis.fetch).toHaveBeenCalledWith(CUSTOM_METADATA_UPLOAD_PATH, {
      method: 'POST',
      body: expect.any(FormData),
      signal,
    });
    expect(result.payload).toEqual({ items: [] });

    globalThis.fetch = vi.fn(async () => answer(new SyntaxError('html')));
    await expect(requestCustomMetadataUpload([], { path: '/other' })).resolves.toMatchObject({ payload: null });
    expect(globalThis.fetch).toHaveBeenCalledWith('/other', expect.objectContaining({ method: 'POST' }));
    await requestCustomMetadataUpload([]);
  });

  it('words a failed upload with the server reason when there is one', () => {
    const failed = { ok: false, status: 400 };
    expect(describeUploadAnswer(failed, { error: '  Too big. ' })).toEqual({ ok: false, message: 'Too big.', variant: 'error' });
    expect(describeUploadAnswer(failed, { errors: ['a.json: bad.', 'b.json: bad.'] })).toEqual({
      ok: false,
      message: 'a.json: bad. b.json: bad.',
      variant: 'error',
    });
    expect(describeUploadAnswer(failed, null)).toEqual({ ok: false, message: 'Failed to upload metadata files.', variant: 'error' });
  });

  it('words an upload that worked, with its warnings and the session\'s entries', () => {
    const custom = { meta: { customEntryCount: 1 }, entries: [{ entryId: 'aaguid:u' }] };
    expect(describeUploadAnswer({ ok: true }, { items: [{}], custom })).toEqual({
      ok: true,
      message: 'Metadata uploaded successfully.',
      variant: 'success',
      custom,
    });
    expect(describeUploadAnswer({ ok: true }, { errors: ['c.json is not a JSON file.'], custom: 'x' })).toEqual({
      ok: true,
      message: 'Metadata uploaded with warnings: c.json is not a JSON file.',
      variant: 'warning',
      custom: null,
    });
  });
});

describe('Manage Trusted Metadata: deleting', () => {
  it('deletes the stored file by its encoded name', async () => {
    globalThis.fetch = vi.fn(async () => answer({ deleted: true }));
    await requestCustomMetadataDelete('a b.json', { signal: null });
    expect(globalThis.fetch).toHaveBeenCalledWith(`${CUSTOM_METADATA_DELETE_PATH}/a%20b.json`, { method: 'DELETE', signal: null });
    await requestCustomMetadataDelete('c.json', { path: '/x' });
    expect(globalThis.fetch).toHaveBeenLastCalledWith('/x/c.json', { method: 'DELETE', signal: undefined });
    await requestCustomMetadataDelete('d.json');
  });

  it('treats a file already gone as a warning and other failures as errors', () => {
    expect(describeDeleteAnswer({ ok: false, status: 404 }, { deleted: false, message: 'Metadata entry not found.' })).toEqual({
      ok: false,
      message: 'Metadata entry not found.',
      variant: 'warning',
    });
    expect(describeDeleteAnswer({ ok: false, status: 400 }, { error: 'Invalid metadata filename.' })).toEqual({
      ok: false,
      message: 'Invalid metadata filename.',
      variant: 'error',
    });
    expect(describeDeleteAnswer({ ok: false, status: 500 }, null)).toEqual({
      ok: false,
      message: 'Failed to delete metadata file.',
      variant: 'error',
    });
  });

  it('keeps the session\'s entries a delete sends back', () => {
    const custom = { meta: { customEntryCount: 0 }, entries: [] };
    expect(describeDeleteAnswer({ ok: true }, { deleted: true, custom })).toEqual({ ok: true, custom });
    expect(describeDeleteAnswer({ ok: true }, null)).toEqual({ ok: true, custom: null });
  });
});

describe('the session\'s uploads merged with the packaged list', () => {
  const PACKAGED = {
    meta: { no: 7, legalHeader: 'Legal.', customEntryCount: 0, hasCustomEntries: false, entryCount: 3 },
    entries: [
      { entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000001', aaguid: 'f1d0f1d0-0000-4000-8000-000000000001', name: 'Packaged one' },
      { entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000002', aaguid: 'F1D0F1D0-0000-4000-8000-000000000002', name: 'Packaged two' },
      { entryId: 'akid:ab', aaguid: '', name: 'Packaged U2F' },
    ],
  };

  it('puts the uploads first, an upload in place of the packaged entry with its AAGUID', () => {
    const custom = {
      meta: { customEntryCount: 2, hasCustomEntries: true },
      entries: [
        { entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000002', aaguid: 'f1d0f1d0-0000-4000-8000-000000000002', name: 'Uploaded two' },
        { entryId: 'akid:ab~2', aaguid: '', name: 'Uploaded U2F' },
      ],
    };

    const merged = mergeCustomEntries(PACKAGED, custom);

    expect(merged.entries.map(entry => entry.name)).toEqual(['Uploaded two', 'Uploaded U2F', 'Packaged one', 'Packaged U2F']);
    expect(merged.meta).toEqual({ no: 7, legalHeader: 'Legal.', customEntryCount: 2, hasCustomEntries: true, entryCount: 4 });
    expect(PACKAGED.entries).toHaveLength(3);
  });

  it('shows the packaged list alone without uploads, and the uploads alone without a list', () => {
    expect(mergeCustomEntries(PACKAGED, null)).toEqual({ ...PACKAGED, meta: { ...PACKAGED.meta, entryCount: 3 } });
    expect(mergeCustomEntries(PACKAGED, { entries: 'none' }).entries).toHaveLength(3);
    const upload = { entryId: 'aaguid:u', aaguid: 'not a guid', name: 'Uploaded' };
    expect(mergeCustomEntries(null, { entries: [upload] })).toEqual({
      meta: { customEntryCount: 1, hasCustomEntries: true, entryCount: 1 },
      entries: [upload],
    });
    expect(mergeCustomEntries({ meta: 'not an object', entries: 'none' }, undefined)).toEqual({
      meta: { customEntryCount: 0, hasCustomEntries: false, entryCount: 0 },
      entries: [],
    });
  });
});

describe('Manage Trusted Metadata: the list', () => {
  it('asks for the session uploads, never from the cache', async () => {
    const items = [{ source: { storedFilename: 'a.json' } }];
    globalThis.fetch = vi.fn(async () => answer({ items }));
    const signal = new AbortController().signal;
    await expect(requestCustomMetadataList({ signal })).resolves.toEqual(items);
    expect(globalThis.fetch).toHaveBeenCalledWith(CUSTOM_METADATA_LIST_PATH, { cache: 'no-store', signal });
    await expect(requestCustomMetadataList()).resolves.toEqual(items);
  });

  it('shows none when the answer holds none', async () => {
    globalThis.fetch = vi.fn(async () => answer({ items: [] }, { ok: false, status: 500 }));
    await expect(requestCustomMetadataList({ path: '/x' })).resolves.toEqual([]);
    globalThis.fetch = vi.fn(async () => answer({ items: 'no' }));
    await expect(requestCustomMetadataList()).resolves.toEqual([]);
  });

  it('describes an uploaded file', () => {
    const uploadedAt = '2026-09-26T10:00:00+00:00';
    expect(
      describeCustomMetadataItem({
        source: { originalFilename: ' statement.json ', storedFilename: 'f00d.json', uploadedAt },
        hasLegalHeader: true,
      }),
    ).toEqual({
      name: 'statement.json',
      storedFilename: 'f00d.json',
      deleteLabel: 'Delete statement.json',
      details: `Uploaded ${new Date(uploadedAt).toLocaleString()} · Includes legal header`,
    });
  });

  it('falls back to the stored name, then metadata.json, and leaves out what is unknown', () => {
    expect(describeCustomMetadataItem({ source: { storedFilename: 'f00d.json', uploadedAt: 'someday' }, hasLegalHeader: false })).toEqual({
      name: 'f00d.json',
      storedFilename: 'f00d.json',
      deleteLabel: 'Delete f00d.json',
      details: '',
    });
    expect(describeCustomMetadataItem({ source: { uploadedAt: 5 } })).toEqual({
      name: 'metadata.json',
      storedFilename: '',
      deleteLabel: 'Delete metadata.json',
      details: '',
    });
    expect(describeCustomMetadataItem(null).name).toBe('metadata.json');
  });
});
