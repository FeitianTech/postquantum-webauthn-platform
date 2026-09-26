// The link other surfaces use to open an AAGUID's MDS entry (MDS-J1..J3).
import { act, renderHook, screen } from '@testing-library/react';

import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';
import { fixtureRoutes, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';
import { SectionNavigationProvider, useSection } from '@/lib/useSection';

import { mdsEntryPath, openMdsEntryForAaguid, useOpenMdsEntry } from './entryLink';

const AAGUID = 'F1D0F1D0-0000-4000-8000-000000000001';

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/beta');
});

describe('opening an AAGUID\'s MDS entry', () => {
  it('names the entry\'s URL, the AAGUID as the server writes it', () => {
    expect(mdsEntryPath(AAGUID)).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(mdsEntryPath('f1d0f1d000004000800000000000000A')).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-00000000000a');
    expect(mdsEntryPath('no')).toBe('');
  });

  it('opens it, or says it cannot', () => {
    const go = vi.fn();
    expect(openMdsEntryForAaguid(AAGUID, go)).toBeNull();
    expect(go).toHaveBeenCalledWith('mds', ['aaguid:f1d0f1d0-0000-4000-8000-000000000001']);
    expect(openMdsEntryForAaguid('', go)).toBe('Authenticator metadata entry unavailable.');
    expect(go).toHaveBeenCalledTimes(1);
  });

  it('opens it from another section as one history entry, which Back leaves', () => {
    window.history.replaceState({ fromNext: true }, '', '/beta#simple');
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

  it('shows the entry at its URL', async () => {
    window.history.replaceState({ fromNext: true }, '', `/beta${mdsEntryPath(AAGUID)}`);
    stubFetch(fixtureRoutes());
    renderPage(
      <ToastProvider>
        <AppShell />
      </ToastProvider>,
    );
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeInTheDocument();
  });
});
