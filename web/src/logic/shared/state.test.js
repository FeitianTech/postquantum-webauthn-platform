import { afterEach, describe, expect, it, vi } from 'vitest';

const STATE = './state.js';

describe('the shared state', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('holds a UTF-8 decoder where the platform has TextDecoder', async () => {
    const { state } = await import(STATE);

    expect(state.utf8Decoder.encoding).toBe('utf-8');
  });

  it('holds no decoder where the platform has no TextDecoder', async () => {
    vi.stubGlobal('TextDecoder', undefined);
    vi.resetModules();
    const { state } = await import(STATE);

    expect(state.utf8Decoder).toBeNull();
  });
});
