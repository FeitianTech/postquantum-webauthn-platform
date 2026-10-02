// The Advanced tab's registration request: the values the form draws at random,
// on request and again after a registration, where only a value the person left
// filled is drawn again.
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';

import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { ToastProvider } from '@/components/ui/Toast';
import { keepRecords, warmUpRoutes } from '@/test/credentials';
import { stubFetch } from '@/test/fetch';

import { useAdvancedRequest } from './useAdvancedRequest';

const HEX_32_BYTES = /^[0-9a-f]{64}$/;

function wrapper({ children }: { children: ReactNode }) {
  return (
    <ToastProvider>
      <SavedCredentialsProvider>{children}</SavedCredentialsProvider>
    </ToastProvider>
  );
}

async function renderRequest() {
  keepRecords([]);
  stubFetch(warmUpRoutes());
  const hook = renderHook(() => useAdvancedRequest(), { wrapper });
  await waitFor(() => expect(hook.result.current.settings.challenge).toMatch(HEX_32_BYTES));
  return hook;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the registration request\'s random values', () => {
  it('are drawn again on request: the identity, the challenge and each PRF input', async () => {
    const { result } = await renderRequest();
    const before = result.current.settings;

    act(() => result.current.randomizeIdentity());
    expect(result.current.settings.userId).toMatch(HEX_32_BYTES);
    expect(result.current.settings.userId).not.toBe(before.userId);
    expect(result.current.settings.displayName).toBe(result.current.settings.userName);
    act(() => result.current.randomizeChallenge());
    expect(result.current.settings.challenge).not.toBe(before.challenge);
    act(() => result.current.randomizePrf('prfFirst'));
    act(() => result.current.randomizePrf('prfSecond'));
    expect(result.current.settings.prfFirst).toMatch(HEX_32_BYTES);
    expect(result.current.settings.prfSecond).toMatch(HEX_32_BYTES);
  });

  it('are drawn again after a registration where the person left them filled', async () => {
    const { result } = await renderRequest();
    act(() => result.current.randomizePrf('prfFirst'));
    const before = result.current.settings;

    act(() => result.current.redraw());
    const after = result.current.settings;
    expect(after.userId).not.toBe(before.userId);
    expect(after.userName).not.toBe(before.userName);
    expect(after.challenge).not.toBe(before.challenge);
    expect(after.prfFirst).not.toBe(before.prfFirst);
    expect(after.prfSecond).toBe('');
  });

  it('stay empty after a registration where the person emptied them', async () => {
    const { result } = await renderRequest();
    act(() => {
      result.current.change('userId', '');
      result.current.change('userName', '');
      result.current.change('challenge', '');
    });

    act(() => result.current.redraw());
    expect(result.current.settings).toMatchObject({ userId: '', userName: '', challenge: '', prfFirst: '', prfSecond: '' });
  });
});
