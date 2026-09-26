// The explorer's certificate decodes: once for each certificate, shared while
// running, asked again after a failure.
import { act, renderHook, waitFor } from '@testing-library/react';

import { json, stubFetch } from '@/test/mds';

import { useCertificateDecode } from './useCertificateDecode';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('decoding an attestation certificate', () => {
  it('asks once, shares a decode still running, and keeps the answer by its base64', async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetch = stubFetch({
      '/api/mds/decode-certificate': async () => {
        await held;
        return json({ details: { subject: 'CN=Root' } });
      },
    });
    const { result } = renderHook(() => useCertificateDecode());

    let first!: Promise<unknown>;
    let second!: Promise<unknown>;
    act(() => {
      first = result.current.decode('MIIB\nAAA=');
      second = result.current.decode('MIIBAAA=');
    });
    expect(second).toBe(first);
    expect(result.current.viewFor('MIIBAAA=')).toBeNull();
    await act(async () => {
      release();
      await first;
    });
    expect(result.current.viewFor(' MIIB AAA= ')).toMatchObject({ title: 'CN=Root', failed: false });
    await act(async () => {
      await result.current.decode('MIIBAAA=');
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('asks again after a failure', async () => {
    let answer = () => json({ error: 'Invalid certificate encoding.' }, 400);
    const fetch = stubFetch({ '/api/mds/decode-certificate': () => answer() });
    const { result } = renderHook(() => useCertificateDecode());
    await act(async () => {
      await result.current.decode('!!');
    });
    expect(result.current.viewFor('!!')).toMatchObject({ failed: true, reason: 'Invalid certificate encoding.' });
    answer = () => json({ details: { subject: 'CN=Root' } });
    await act(async () => {
      await result.current.decode('!!');
    });
    await waitFor(() => expect(result.current.viewFor('!!')).toMatchObject({ failed: false }));
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
