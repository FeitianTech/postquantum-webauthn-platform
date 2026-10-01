import { describe, expect, it } from 'vitest';

import { writeToClipboard } from './clipboard.js';

// Text written to the clipboard (shared/clipboard.js).

describe('writeToClipboard', () => {
  it('writes the text and says nothing went wrong', async () => {
    const written = [];
    const nav = { clipboard: { writeText: async (text) => written.push(text) } };

    expect(await writeToClipboard('hello', nav)).toBeNull();
    expect(written).toEqual(['hello']);
  });

  it('says the clipboard is not available when there is none, or it cannot be read', async () => {
    expect(await writeToClipboard('x', {})).toBe('the clipboard is not available on this page');
    expect(await writeToClipboard('x', { clipboard: {} })).toBe('the clipboard is not available on this page');
    expect(await writeToClipboard('x', undefined)).toBe('the clipboard is not available on this page');
    const throwing = {};
    Object.defineProperty(throwing, 'clipboard', {
      get() {
        throw new Error('denied');
      },
    });
    expect(await writeToClipboard('x', throwing)).toBe('the clipboard is not available on this page');
  });

  it('gives the error when writing is refused', async () => {
    const nav = {
      clipboard: {
        writeText: async () => {
          throw new DOMException('Write permission denied.', 'NotAllowedError');
        },
      },
    };

    expect(await writeToClipboard('x', nav)).toBe('NotAllowedError: Write permission denied.');
  });
});
