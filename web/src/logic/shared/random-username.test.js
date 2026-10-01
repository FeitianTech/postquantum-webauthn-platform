import { afterEach, describe, expect, it, vi } from 'vitest';

import { generateRandom10DigitUsername } from './random-username.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a random username', () => {
  it('is ten characters from A–Z, a–z and 0–9', () => {
    expect(generateRandom10DigitUsername()).toMatch(/^[A-Za-z0-9]{10}$/);
  });

  it('draws each character from the whole set', () => {
    vi.spyOn(Math, 'random').mockReturnValueOnce(0).mockReturnValueOnce(0.9999).mockReturnValue(0.5);
    expect(generateRandom10DigitUsername()).toBe('A9ffffffff');
  });
});
