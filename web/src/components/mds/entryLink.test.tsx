// The link other surfaces use to open an AAGUID's MDS entry.
import { act, renderHook } from '@testing-library/react';

import { SectionNavigationProvider, useSection } from '@/lib/useSection';

import { openMdsEntryForAaguid, useOpenMdsEntry } from './entryLink';

const AAGUID = 'F1D0F1D0-0000-4000-8000-000000000001';

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
});

describe('opening an AAGUID\'s MDS entry', () => {
  it('opens it, or says it cannot', () => {
    const go = vi.fn();
    expect(openMdsEntryForAaguid(AAGUID, go)).toBeNull();
    expect(go).toHaveBeenCalledWith('mds', ['aaguid:f1d0f1d0-0000-4000-8000-000000000001']);
    expect(openMdsEntryForAaguid('', go)).toBe('Authenticator metadata entry unavailable.');
    expect(go).toHaveBeenCalledTimes(1);
  });

  it('opens it from another section as one history entry, which Back leaves', () => {
    window.history.replaceState({ fromNext: true }, '', '/#simple');
    const { result } = renderHook(() => {
      const [section, , route, go] = useSection();
      return { section, route, open: (aaguid: string) => openMdsEntryForAaguid(aaguid, go) };
    });
    const length = window.history.length;
    act(() => {
      result.current.open(AAGUID);
    });
    expect(result.current.section).toBe('mds');
    expect(result.current.route.path).toEqual(['aaguid:f1d0f1d0-0000-4000-8000-000000000001']);
    expect(window.location.hash).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(window.history.length).toBe(length + 1);
  });

  it('gives a component inside the shell the function', () => {
    const go = vi.fn();
    const { result } = renderHook(() => useOpenMdsEntry(), {
      wrapper: ({ children }) => <SectionNavigationProvider value={go}>{children}</SectionNavigationProvider>,
    });
    expect(result.current(AAGUID)).toBeNull();
    expect(go).toHaveBeenCalledWith('mds', ['aaguid:f1d0f1d0-0000-4000-8000-000000000001']);
  });
});
