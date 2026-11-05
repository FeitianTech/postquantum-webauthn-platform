// What another section hands the Advanced tab's registration: an MDS statement's
// settings, set with the form's own setter, the editor following.
import { act, renderHook, waitFor } from '@testing-library/react';
import { type ReactNode, StrictMode, useState } from 'react';

import { SavedCredentialsProvider } from '@/components/credentials/useSavedCredentials';
import { ToastProvider } from '@/components/ui/Toast';
import { CLOSED_ROUTE, type SectionRoute } from '@/lib/useSection';
import { keepRecords, warmUpRoutes } from '@/test/credentials';
import { stubFetch } from '@/test/fetch';

import { useAdvancedRequest } from './useAdvancedRequest';
import { useRegistrationHandoff } from './useRegistrationHandoff';

const HANDED: SectionRoute = {
  ...CLOSED_ROUTE,
  handoff: { kind: 'registration', settings: { algorithms: [-8, -7], userVerification: 'required', attachment: 'cross-platform' } },
};

function wrapper({ children }: { children: ReactNode }) {
  return (
    <ToastProvider>
      <SavedCredentialsProvider>{children}</SavedCredentialsProvider>
    </ToastProvider>
  );
}

function useAdvancedRegistration(route: SectionRoute) {
  const request = useAdvancedRequest();
  const [ceremony, setCeremony] = useState<'registration' | 'authentication'>('authentication');
  useRegistrationHandoff(route, request, setCeremony);
  return { request, ceremony };
}

function renderRegistration(route: SectionRoute = CLOSED_ROUTE) {
  keepRecords([]);
  stubFetch(warmUpRoutes());
  return renderHook(({ at }) => useAdvancedRegistration(at), { wrapper, initialProps: { at: route } });
}

const sent = (text: string) => JSON.parse(text).publicKey;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('a registration another section hands the Advanced tab', () => {
  it('shows Registration from the top, and sets each setting, the editor rewriting what changed', async () => {
    const scrollTo = vi.spyOn(window, 'scrollTo');
    const { result, rerender } = renderRegistration();
    await waitFor(() => expect(result.current.request.text).toContain('"publicKey"'));
    const before = sent(result.current.request.text);

    rerender({ at: HANDED });
    await waitFor(() => expect(result.current.request.settings.algorithms).toEqual([-8, -7]));
    expect(result.current.ceremony).toBe('registration');
    expect(scrollTo).toHaveBeenCalledWith({ top: 0 });
    expect(result.current.request.settings).toMatchObject({ userVerification: 'required', attachment: 'cross-platform' });
    const after = sent(result.current.request.text);
    expect(after.pubKeyCredParams).toEqual([
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -7 },
    ]);
    expect(after.authenticatorSelection).toMatchObject({ userVerification: 'required', authenticatorAttachment: 'cross-platform' });
    // Everything else in the text is as it was.
    expect({ ...after, pubKeyCredParams: null, authenticatorSelection: null }).toEqual({
      ...before,
      pubKeyCredParams: null,
      authenticatorSelection: null,
    });
  });

  it('drops a hint the attachment contradicts', async () => {
    const { result, rerender } = renderRegistration();
    await waitFor(() => expect(result.current.request.text).toContain('"publicKey"'));
    act(() => result.current.request.change('hints', ['client-device']));

    rerender({ at: HANDED });
    await waitFor(() => expect(result.current.request.settings.attachment).toBe('cross-platform'));
    expect(result.current.request.settings.hints).toEqual([]);
    expect(sent(result.current.request.text).hints).toBeUndefined();
  });

  it('holds once the request has started, when the tab mounts with it', async () => {
    const { result } = renderRegistration(HANDED);
    await waitFor(() => expect(result.current.request.text).toContain('"publicKey"'));
    await waitFor(() => expect(result.current.request.settings.algorithms).toEqual([-8, -7]));
    expect(result.current.request.settings.userName).not.toBe('');
    expect(sent(result.current.request.text).pubKeyCredParams.map(({ alg }: { alg: number }) => alg)).toEqual([-8, -7]);
  });

  it('holds under Strict Mode, which runs the start and the hand-off twice on a mount', async () => {
    keepRecords([]);
    stubFetch(warmUpRoutes());
    const strict = ({ children }: { children: ReactNode }) => <StrictMode>{wrapper({ children })}</StrictMode>;
    const { result } = renderHook(() => useAdvancedRegistration(HANDED), { wrapper: strict });
    await waitFor(() => expect(result.current.request.text).toContain('"publicKey"'));
    await waitFor(() => expect(result.current.request.settings.algorithms).toEqual([-8, -7]));
    expect(result.current.request.settings.userVerification).toBe('required');
  });

  it('leaves the form alone for another section\'s hand-off, and for none', async () => {
    const { result, rerender } = renderRegistration();
    await waitFor(() => expect(result.current.request.text).toContain('"publicKey"'));
    const settings = result.current.request.settings;
    rerender({ at: { ...CLOSED_ROUTE, handoff: { kind: 'decode', payload: 'o2Nm' } } });
    expect(result.current.request.settings).toBe(settings);
    expect(result.current.ceremony).toBe('authentication');
  });
});
