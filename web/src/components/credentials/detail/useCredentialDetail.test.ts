// A saved credential's details composed at each opening: an advanced record is
// completed from its server artifact once for the page's life, by the id the
// server keeps it under.
import { renderHook, waitFor } from '@testing-library/react';

import type { SavedCredential } from '@/logic/credentials/saved-list.js';
import { artifactAnswer, decodeRoute, keepRecords, savedRecord } from '@/test/credentials';
import { json, stubFetch } from '@/test/fetch';

import { forgetCompletedRecords, useCredentialDetail } from './useCredentialDetail';

const ARTIFACT = artifactAnswer('advanced-register-packed-x5c-everything');
const ADVANCED = savedRecord('advanced-register-packed-x5c-everything') as SavedCredential;
const ARTIFACT_PATH = `/api/advanced/credential-artifacts/${encodeURIComponent(ARTIFACT.storageId)}`;

function openTwice(record: SavedCredential) {
  keepRecords([]);
  const fetch = stubFetch({ [ARTIFACT_PATH]: () => json(ARTIFACT), '/api/codec': decodeRoute() });
  const hook = renderHook(({ key }) => useCredentialDetail(record, key, () => {}), { initialProps: { key: 'first' } });
  const asked = () => fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/advanced/credential-artifacts/')).length;
  return {
    asked,
    async open(key: string) {
      hook.rerender({ key });
      await waitFor(() => expect(hook.result.current.phase).toBe('ready'));
      return hook.result.current;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  forgetCompletedRecords();
});

describe('a saved credential\'s details', () => {
  it('complete an advanced record from its artifact at the first opening, and from what that brought at the next', async () => {
    const details = openTwice(ADVANCED);

    await details.open('first');
    expect(details.asked()).toBe(1);
    const again = await details.open('second');
    expect(details.asked()).toBe(1);
    expect(again).toMatchObject({ phase: 'ready', hydrationFailed: false });
  });

  it('keep a record the server knows by its local storage id under that id', async () => {
    const { storageId, localStorageId: _localStorageId, ...rest } = ADVANCED;
    const details = openTwice({ ...rest, localStorageId: storageId } as SavedCredential);

    await details.open('first');
    await details.open('second');
    expect(details.asked()).toBe(1);
  });

  it('compose a record kept under no id from what this browser holds, asking nothing', async () => {
    const { storageId: _storageId, localStorageId: _localStorageId, ...rest } = ADVANCED;
    const details = openTwice(rest as SavedCredential);

    expect(await details.open('first')).toMatchObject({ phase: 'ready', hydrationFailed: false });
    await details.open('second');
    expect(details.asked()).toBe(0);
  });
});
