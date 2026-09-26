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
});
