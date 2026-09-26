import { act, renderHook } from '@testing-library/react';

const beforePopState = vi.fn();
vi.mock('next/router', () => ({ default: { beforePopState } }));

const { SectionNavigationProvider, useSection, useSectionNavigation } = await import('./useSection');

afterEach(() => {
  window.history.replaceState(null, '', '/beta');
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
    expect(window.history.state).toEqual({ pqcOpened: true });

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
    expect(window.history.state).toEqual({ fromNext: true, pqcOpened: true });
    expect(window.history.length).toBe(length + 1);
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

