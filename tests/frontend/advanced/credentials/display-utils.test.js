import { describe, expect, it } from 'vitest';

import {
  describeCoseAlgorithm,
  describeCoseKeyType,
  describeMldsaParameterSet,
} from '../../../../frontend/static/scripts/advanced/ui/display-utils.js';

describe('display-utils', () => {
  it('labels COSE algorithms, key types and ML-DSA parameter sets', () => {
    expect(describeCoseAlgorithm(-7)).toBe('ES256 (-7)');
    expect(describeCoseAlgorithm(null)).toBe('Unknown');
    expect(describeCoseAlgorithm(12345)).toBe('Algorithm (12345)');

    expect(describeCoseKeyType(1)).toBe('OKP (1)');
    expect(describeCoseKeyType(undefined)).toBe('Unknown');

    expect(describeMldsaParameterSet(-48)).toBe('ML-DSA-44');
    expect(describeMldsaParameterSet(-49)).toBe('ML-DSA-65');
    expect(describeMldsaParameterSet('-50')).toBe('ML-DSA-87');
    expect(describeMldsaParameterSet('unknown')).toBe('');
  });

  it('labels COSE key types from the IANA registry', () => {
    // 7 is AKP, the key type ML-DSA keys use; the parameter set comes from alg.
    expect(describeCoseKeyType(5)).toBe('HSS-LMS (5)');
    expect(describeCoseKeyType(6)).toBe('WalnutDSA (6)');
    expect(describeCoseKeyType(7)).toBe('AKP (7)');
  });
});
