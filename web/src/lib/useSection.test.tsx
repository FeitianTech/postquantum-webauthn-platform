import { renderHook } from '@testing-library/react';

const beforePopState = vi.fn();
vi.mock('next/router', () => ({ default: { beforePopState } }));

const { useSection } = await import('./useSection');

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
});
