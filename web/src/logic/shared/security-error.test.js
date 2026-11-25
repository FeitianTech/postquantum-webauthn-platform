import { describe, expect, it } from 'vitest';
import { RP_ID_REFUSED_TEXT, securityErrorText } from './security-error.js';

describe('securityErrorText', () => {
  it('says the browser refused the RP ID, then the browser\'s own message', () => {
    const refusal = new DOMException('The relying party ID is not a registrable domain suffix of, nor equal to the current domain.', 'SecurityError');
    expect(securityErrorText(refusal)).toBe(
      `${RP_ID_REFUSED_TEXT}: The relying party ID is not a registrable domain suffix of, nor equal to the current domain.`,
    );
  });

  it('says the sentence alone when the browser gave no message', () => {
    expect([securityErrorText(new DOMException('', 'SecurityError')), securityErrorText({ name: 'SecurityError' })]).toEqual([
      RP_ID_REFUSED_TEXT,
      RP_ID_REFUSED_TEXT,
    ]);
  });
});
