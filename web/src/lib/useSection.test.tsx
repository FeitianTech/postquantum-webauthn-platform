import { act, renderHook, waitFor } from '@testing-library/react';

const beforePopState = vi.fn();
vi.mock('next/router', () => ({ default: { beforePopState } }));

const { CLOSED_ROUTE, SectionNavigationProvider, useSection, useSectionNavigation } = await import('./useSection');

afterEach(() => {
  window.history.replaceState(null, '', '/beta');
});

describe('the first section', () => {
  // The exported HTML is the same for every hash: its render chooses no section,
  // and the hash is read before the hydrated page's first frame.
  function renders() {
    const seen: Array<string | null> = [];
    const hook = renderHook(() => {
      const result = useSection();
      seen.push(result[0]);
      return result;
    });
    return { seen, ...hook };
  }

  it('is none in the first render, then the section the hash names, before the frame is painted', () => {
    window.history.replaceState(null, '', '/beta#advanced');
    const { seen, result } = renders();
    expect(seen[0]).toBeNull();
    expect(result.current[0]).toBe('advanced');
    expect(seen.filter((section) => section === 'simple')).toEqual([]);
  });

  it('is the default with no hash, or with a hash that names no section', () => {
    expect(renders().result.current[0]).toBe('simple');
    window.history.replaceState(null, '', '/beta#nothing');
    const { result } = renders();
    expect(result.current[0]).toBe('simple');
    expect(window.location.hash).toBe('#nothing');
  });
});

describe('the section in the URL, inside Next', () => {
  it('leaves Back to the page while it is shown, and gives it back to Next after', () => {
    const { unmount } = renderHook(() => useSection());
    expect(beforePopState).toHaveBeenCalledTimes(1);
    expect(beforePopState.mock.calls[0][0]({})).toBe(false);
    unmount();
    expect(beforePopState).toHaveBeenCalledTimes(2);
    expect(beforePopState.mock.calls[1][0]({})).toBe(true);
  });

  it('leaves Back to Next for a URL whose path is not this page', () => {
    window.history.replaceState(null, '', '/beta#mds');
    const { unmount } = renderHook(() => useSection());
    const decide = beforePopState.mock.calls.at(-1)![0];

    // Next asks once the URL has changed: another entry of this page's hash, or another page.
    window.history.replaceState(null, '', '/beta#codec');
    expect(decide({})).toBe(false);
    window.history.replaceState(null, '', '/beta/no-such-page');
    expect(decide({})).toBe(true);
    unmount();
    window.history.replaceState(null, '', '/beta');
  });

  it('opens a level at a time and goes back one level, by the browser or to the parent', () => {
    window.history.replaceState(null, '', '/beta#mds');
    const { result } = renderHook(() => useSection());
    expect(result.current[0]).toBe('mds');

    act(() => result.current[2].open(['aaguid:x']));
    act(() => result.current[2].open(['aaguid:x', 'certificate', '1']));
    expect(window.location.hash).toBe('#mds/aaguid:x/certificate/1');
    expect(result.current[2].path).toEqual(['aaguid:x', 'certificate', '1']);
    expect(window.history.state).toEqual({ pqcOpened: 2 });

    // A link to the certificate: Back replaces it with its entry, then the list.
    window.history.replaceState(null, '', '/beta#mds/aaguid:y/certificate/2');
    act(() => result.current[2].close(['aaguid:y']));
    expect(window.location.hash).toBe('#mds/aaguid:y');
    expect(result.current[2].path).toEqual(['aaguid:y']);
    act(() => result.current[2].close());
    expect(window.location.hash).toBe('#mds');
    expect(result.current[2].path).toEqual([]);

    // A path the page does not know is replaced, leaving no entry behind.
    const length = window.history.length;
    act(() => result.current[2].replace(['aaguid:z']));
    expect(window.location.hash).toBe('#mds/aaguid:z');
    expect(result.current[2].path).toEqual(['aaguid:z']);
    expect(window.history.length).toBe(length);
  });

  it('opens something in another section as an entry Back returns from', () => {
    window.history.replaceState({ fromNext: true }, '', '/beta#simple');
    const { result } = renderHook(() => useSection());
    const length = window.history.length;

    act(() => result.current[3]('mds', ['aaguid:f1d0f1d0-0000-4000-8000-000000000001']));
    expect(result.current[0]).toBe('mds');
    expect(result.current[2].path).toEqual(['aaguid:f1d0f1d0-0000-4000-8000-000000000001']);
    expect(window.location.hash).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: 1 });
    expect(window.history.length).toBe(length + 1);
  });

  it('shows the default section for the page\'s URL without a hash, and leaves a hash naming no section alone', () => {
    window.history.replaceState({ fromNext: true }, '', '/beta#codec');
    const { result } = renderHook(() => useSection());
    expect(result.current[0]).toBe('codec');

    act(() => {
      window.history.replaceState(null, '', '/beta#elsewhere');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(result.current[0]).toBe('codec');

    act(() => {
      window.history.replaceState(null, '', '/beta');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(result.current[0]).toBe('simple');
    expect(result.current[2].path).toEqual([]);
  });

  it('gives a section the shell\'s way to open something in another, and nothing outside the shell', () => {
    const go = vi.fn();
    const inside = renderHook(() => useSectionNavigation(), {
      wrapper: ({ children }) => <SectionNavigationProvider value={go}>{children}</SectionNavigationProvider>,
    });
    inside.result.current('mds', ['aaguid:x']);
    expect(go).toHaveBeenCalledWith('mds', ['aaguid:x']);
    const outside = renderHook(() => useSectionNavigation());
    expect(() => outside.result.current('mds', [])).not.toThrow();
  });
});

describe('closing every level at once', () => {
  it('goes back as many entries as levels were opened, to the list', async () => {
    window.history.replaceState(null, '', '/beta#simple');
    const { result } = renderHook(() => useSection());
    act(() => result.current[2].open(['credential', 'k']));
    act(() => result.current[2].open(['credential', 'k', 'registration']));
    act(() => result.current[2].open(['credential', 'k', 'registration', 'certificate', '1']));
    expect(window.history.state).toEqual({ pqcOpened: 3 });

    act(() => result.current[2].closeAll());
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(result.current[2].path).toEqual([]);
    expect(window.history.state).toBeNull();
  });

  it('replaces a first level reached by a link with the list, after going back past the rest', async () => {
    window.history.replaceState(null, '', '/beta#simple/credential/k/registration');
    const { result } = renderHook(() => useSection());
    act(() => result.current[2].open(['credential', 'k', 'registration', 'authenticator-data']));

    act(() => result.current[2].closeAll());
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(result.current[2].path).toEqual([]);
  });

  it('replaces a level reached by a link with the list, adding no entry', () => {
    window.history.replaceState({ fromNext: true }, '', '/beta#simple/credential/k');
    const { result } = renderHook(() => useSection());
    const length = window.history.length;

    act(() => result.current[2].closeAll());
    expect(window.location.hash).toBe('#simple');
    expect(result.current[2].path).toEqual([]);
    expect(window.history.length).toBe(length);
  });

  it('forgets the levels of an entry another section takes the place of', () => {
    window.history.replaceState({ fromNext: true, pqcOpened: 2 }, '', '/beta#mds/aaguid:x/certificate/1');
    const { result } = renderHook(() => useSection());

    act(() => result.current[1]('simple'));
    expect(window.history.state).toEqual({ fromNext: true });
    expect(window.location.hash).toBe('#simple');
  });

  it('has nothing to close in a section not shown', () => {
    expect(() => CLOSED_ROUTE.closeAll()).not.toThrow();
  });
});
