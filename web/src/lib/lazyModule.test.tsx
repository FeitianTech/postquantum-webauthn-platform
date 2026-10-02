import { act, renderHook, waitFor } from '@testing-library/react';

import { lazyModule, useLazyModule, whenInteractive } from './lazyModule';

function Part() {
  return null;
}

describe('a lazy module', () => {
  it('loads once, however often it is asked for', async () => {
    const loader = vi.fn(async () => ({ Part }));
    const lazy = lazyModule(loader);

    const [first, second] = await Promise.all([lazy.load(), lazy.load()]);
    expect(first).toBe(second);
    expect(await lazy.load()).toBe(first);
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it('forgets a failed load, so the next ask loads it again', async () => {
    const loader = vi.fn().mockRejectedValueOnce(new Error('chunk failed')).mockResolvedValue({ Part });
    const lazy = lazyModule(loader);

    await expect(lazy.load()).rejects.toThrow('chunk failed');
    expect(await lazy.load()).toEqual({ Part });
    expect(loader).toHaveBeenCalledTimes(2);
  });
});

describe('a lazy module in a component', () => {
  it('is nothing on the first render, and nothing until it is wanted', async () => {
    const lazy = lazyModule(async () => ({ Part }));
    const { result, rerender } = renderHook(({ wanted }) => useLazyModule(lazy, wanted), { initialProps: { wanted: false } });

    expect(result.current.module).toBeNull();
    await act(async () => {});
    expect(result.current.module).toBeNull();
    rerender({ wanted: true });
    expect(result.current.module).toBeNull();
    await waitFor(() => expect(result.current.module).toEqual({ Part }));
  });

  it('holds a module that is itself a function', async () => {
    const lazy = lazyModule(async () => Part);
    const { result } = renderHook(() => useLazyModule(lazy, true));

    await waitFor(() => expect(result.current.module).toBe(Part));
  });

  it('says it failed, and loads again when asked to', async () => {
    const lazy = lazyModule(vi.fn().mockRejectedValueOnce(new Error('chunk failed')).mockResolvedValue({ Part }));
    const { result } = renderHook(() => useLazyModule(lazy, true));

    await waitFor(() => expect(result.current.failed).toBe(true));
    act(() => result.current.retry());
    expect(result.current.failed).toBe(false);
    await waitFor(() => expect(result.current.module).toEqual({ Part }));
  });

  it('drops what arrives after the component has gone', async () => {
    let arrive!: (value: { Part: typeof Part }) => void;
    let refuse!: (error: Error) => void;
    const arriving = lazyModule(() => new Promise<{ Part: typeof Part }>((resolve) => (arrive = resolve)));
    const refused = lazyModule(() => new Promise<{ Part: typeof Part }>((_resolve, reject) => (refuse = reject)));
    const first = renderHook(() => useLazyModule(arriving, true));
    const second = renderHook(() => useLazyModule(refused, true));

    first.unmount();
    second.unmount();
    await act(async () => {
      arrive({ Part });
      refuse(new Error('chunk failed'));
    });
    expect(first.result.current).toMatchObject({ module: null, failed: false });
    expect(second.result.current).toMatchObject({ module: null, failed: false });
  });
});

describe('once the page is interactive', () => {
  it('runs when the browser is idle, at most two seconds after, and can be called off', () => {
    const requestIdleCallback = vi.fn(() => 7);
    const cancelIdleCallback = vi.fn();
    vi.stubGlobal('requestIdleCallback', requestIdleCallback);
    vi.stubGlobal('cancelIdleCallback', cancelIdleCallback);
    const callback = vi.fn();

    const cancel = whenInteractive(callback);
    expect(requestIdleCallback).toHaveBeenCalledWith(callback, { timeout: 2000 });
    cancel();
    expect(cancelIdleCallback).toHaveBeenCalledWith(7);
    vi.unstubAllGlobals();
  });

  it('runs shortly after where the browser cannot say when it is idle, and can be called off', () => {
    vi.useFakeTimers();
    const callback = vi.fn();

    whenInteractive(callback);
    vi.advanceTimersByTime(200);
    expect(callback).toHaveBeenCalledTimes(1);
    const cancel = whenInteractive(callback);
    cancel();
    vi.advanceTimersByTime(1000);
    expect(callback).toHaveBeenCalledTimes(1);
  });
});
