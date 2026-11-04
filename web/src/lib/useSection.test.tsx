import { act, renderHook, waitFor } from '@testing-library/react';

const beforePopState = vi.fn();
vi.mock('next/router', () => ({ default: { beforePopState } }));

const { SectionNavigationProvider, useSection, useSectionNavigation } = await import('./useSection');

afterEach(() => {
  window.history.replaceState(null, '', '/');
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
    window.history.replaceState(null, '', '/#advanced');
    const { seen, result } = renders();
    expect(seen[0]).toBeNull();
    expect(result.current[0]).toBe('advanced');
    expect(seen.filter((section) => section === 'simple')).toEqual([]);
  });

  it('is the default with no hash, or with a hash that names no section', () => {
    expect(renders().result.current[0]).toBe('simple');
    window.history.replaceState(null, '', '/#nothing');
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
    window.history.replaceState(null, '', '/#mds');
    const { unmount } = renderHook(() => useSection());
    const decide = beforePopState.mock.calls.at(-1)![0];

    // Next asks once the URL has changed: another entry of this page's hash, or another page.
    window.history.replaceState(null, '', '/#codec');
    expect(decide({})).toBe(false);
    window.history.replaceState(null, '', '/no-such-page');
    expect(decide({})).toBe(true);
    unmount();
    window.history.replaceState(null, '', '/');
  });

  it('opens a level at a time and goes back one level, by the browser or to the parent', () => {
    window.history.replaceState(null, '', '/#mds');
    const { result } = renderHook(() => useSection());
    expect(result.current[0]).toBe('mds');

    act(() => result.current[2].open(['aaguid:x']));
    act(() => result.current[2].open(['aaguid:x', 'certificate', '1']));
    expect(window.location.hash).toBe('#mds/aaguid:x/certificate/1');
    expect(result.current[2].path).toEqual(['aaguid:x', 'certificate', '1']);
    expect(window.history.state).toEqual({ pqcOpened: 2 });

    // A link to the certificate: Back replaces it with its entry, then the list.
    window.history.replaceState(null, '', '/#mds/aaguid:y/certificate/2');
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
    window.history.replaceState({ fromNext: true }, '', '/#simple');
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
    window.history.replaceState({ fromNext: true }, '', '/#codec');
    const { result } = renderHook(() => useSection());
    expect(result.current[0]).toBe('codec');

    act(() => {
      window.history.replaceState(null, '', '/#elsewhere');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(result.current[0]).toBe('codec');

    act(() => {
      window.history.replaceState(null, '', '/');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(result.current[0]).toBe('simple');
    expect(result.current[2].path).toEqual([]);
  });

  it('gives a section the shell\'s way to open something in another', () => {
    const go = vi.fn();
    const inside = renderHook(() => useSectionNavigation(), {
      wrapper: ({ children }) => <SectionNavigationProvider value={go}>{children}</SectionNavigationProvider>,
    });
    inside.result.current('mds', ['aaguid:x']);
    expect(go).toHaveBeenCalledWith('mds', ['aaguid:x']);
  });
});

describe('what a section hands the one it opens', () => {
  const DECODE = { kind: 'decode', payload: 'o2NmbXRkbm9uZQ' } as const;

  it('reaches the section opened, beside its path, and is gone on Back and Forward', async () => {
    window.history.replaceState(null, '', '/#simple/credential/k');
    const { result } = renderHook(() => useSection());

    act(() => result.current[3]('codec', [], DECODE));
    expect(result.current[0]).toBe('codec');
    expect(result.current[2].handoff).toBe(DECODE);
    // The URL carries the section only.
    expect(window.location.hash).toBe('#codec');

    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(window.location.hash).toBe('#simple/credential/k'));
    expect(result.current[2].handoff).toBeNull();
    await act(async () => {
      window.history.forward();
    });
    await waitFor(() => expect(result.current[0]).toBe('codec'));
    expect(result.current[2].handoff).toBeNull();
  });

  it('is gone once a tab is chosen, a level opened or the list shown', () => {
    window.history.replaceState(null, '', '/#mds/aaguid:x');
    const { result } = renderHook(() => useSection());

    act(() => result.current[3]('codec', [], DECODE));
    act(() => result.current[1]('simple'));
    expect(result.current[2].handoff).toBeNull();

    act(() => result.current[3]('codec', [], DECODE));
    act(() => result.current[2].open(['elsewhere']));
    expect(result.current[2].handoff).toBeNull();

    act(() => result.current[3]('codec', [], DECODE));
    // Reached by a link: closing shows the list in its place.
    window.history.replaceState(null, '', '/#codec');
    act(() => result.current[2].close());
    expect(result.current[2].handoff).toBeNull();
  });

  it('is nothing for a section opened without one', () => {
    window.history.replaceState(null, '', '/#simple');
    const { result } = renderHook(() => useSection());
    act(() => result.current[3]('mds', ['aaguid:x']));
    expect(result.current[2].handoff).toBeNull();
  });
});

describe('the focus, once Back returns from another section', () => {
  function focusedButton(parent: HTMLElement = document.body) {
    const button = document.createElement('button');
    parent.append(button);
    button.focus();
    return button;
  }

  async function goAndComeBack(result: { current: ReturnType<typeof useSection> }) {
    act(() => result.current[3]('codec', []));
    (document.activeElement as HTMLElement | null)?.blur();
    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(result.current[0]).toBe('simple'));
    await act(async () => {
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });
  }

  it('goes back to what had it when the other section was opened', async () => {
    window.history.replaceState(null, '', '/#simple');
    const button = focusedButton();
    const { result } = renderHook(() => useSection());

    await goAndComeBack(result);
    expect(button).toHaveFocus();
    button.remove();
  });

  it('stays where it is when that control has left the page, or is under a dialog', async () => {
    window.history.replaceState(null, '', '/#simple');
    const gone = focusedButton();
    const { result } = renderHook(() => useSection());
    act(() => result.current[3]('codec', []));
    gone.remove();
    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(result.current[0]).toBe('simple'));
    expect(document.activeElement).toBe(document.body);

    const under = document.createElement('div');
    under.setAttribute('inert', '');
    document.body.append(under);
    const covered = focusedButton(under);
    await goAndComeBack(result);
    expect(covered).not.toHaveFocus();
    under.remove();
  });

  it('is not moved by Back within a section', async () => {
    window.history.replaceState(null, '', '/#simple');
    const button = focusedButton();
    const { result } = renderHook(() => useSection());
    act(() => result.current[2].open(['credential', 'k']));
    button.blur();
    await act(async () => {
      window.history.back();
    });
    await waitFor(() => expect(result.current[2].path).toEqual([]));
    await act(async () => {
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });
    expect(button).not.toHaveFocus();
    button.remove();
  });
});

describe('closing every level at once', () => {
  it('goes back as many entries as levels were opened, to the list', async () => {
    window.history.replaceState(null, '', '/#simple');
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

  it('goes back only the levels asked for, to the entry another section opened', async () => {
    window.history.replaceState(null, '', '/#mds/aaguid:x');
    const { result } = renderHook(() => useSection());
    act(() => result.current[3]('advanced', []));
    act(() => result.current[2].open(['credential', 'k']));
    act(() => result.current[2].open(['credential', 'k', 'registration']));
    expect(window.history.state).toEqual({ pqcOpened: 3 });

    act(() => result.current[2].closeAll([], 2));
    await waitFor(() => expect(window.location.hash).toBe('#advanced'));
    expect(result.current[0]).toBe('advanced');
    expect(result.current[2].path).toEqual([]);
    expect(window.history.state).toEqual({ pqcOpened: 1 });
  });

  it('replaces a first level reached by a link with the list, after going back past the rest', async () => {
    window.history.replaceState(null, '', '/#simple/credential/k/registration');
    const { result } = renderHook(() => useSection());
    act(() => result.current[2].open(['credential', 'k', 'registration', 'authenticator-data']));

    act(() => result.current[2].closeAll());
    await waitFor(() => expect(window.location.hash).toBe('#simple'));
    expect(result.current[2].path).toEqual([]);
  });

  it('replaces a level reached by a link with the list, adding no entry', () => {
    window.history.replaceState({ fromNext: true }, '', '/#simple/credential/k');
    const { result } = renderHook(() => useSection());
    const length = window.history.length;

    act(() => result.current[2].closeAll());
    expect(window.location.hash).toBe('#simple');
    expect(result.current[2].path).toEqual([]);
    expect(window.history.length).toBe(length);
  });

  it('forgets the levels of an entry another section takes the place of', () => {
    window.history.replaceState({ fromNext: true, pqcOpened: 2 }, '', '/#mds/aaguid:x/certificate/1');
    const { result } = renderHook(() => useSection());

    act(() => result.current[1]('simple'));
    expect(window.history.state).toEqual({ fromNext: true });
    expect(window.location.hash).toBe('#simple');
  });
});
