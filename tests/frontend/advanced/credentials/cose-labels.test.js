import { describe, expect, it } from 'vitest';

import {
  describeCoseAlgorithm,
  describeCoseKeyType,
  describeMldsaParameterSet,
} from '../../../../frontend/static/scripts/advanced/cose-labels.js';

describe('describeCoseAlgorithm', () => {
  it('names a registered algorithm with its identifier', () => {
    expect(describeCoseAlgorithm(-49)).toBe('ML-DSA-65 (PQC) (-49)');
  });

  it('names an identifier written as text the same way', () => {
    expect(describeCoseAlgorithm('-8')).toBe('EdDSA (-8)');
  });

  it('calls an unregistered identifier an algorithm', () => {
    expect(describeCoseAlgorithm(-46)).toBe('Algorithm (-46)');
  });

  it('calls a missing identifier Unknown', () => {
    expect(describeCoseAlgorithm(Number.NaN)).toBe('Unknown');
  });
});

describe('describeCoseKeyType', () => {
  it('names a registered key type with its identifier', () => {
    expect(describeCoseKeyType(2)).toBe('EC2 (2)');
  });

  it('gives an unregistered key type as it is', () => {
    expect(describeCoseKeyType(8)).toBe('8');
  });

  it('calls a missing key type Unknown', () => {
    expect(describeCoseKeyType(Number.NaN)).toBe('Unknown');
  });
});

describe('describeMldsaParameterSet', () => {
  it('names the parameter set of each ML-DSA algorithm', () => {
    expect([-48, '-49', -50].map(describeMldsaParameterSet)).toEqual(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);
  });

  it('names none for another algorithm', () => {
    expect(describeMldsaParameterSet(-7)).toBe('');
  });
});
