import { describe, expect, it } from 'vitest';

import {
  describeCoseAlgorithm,
  describeCoseKeyType,
  describeMldsaParameterSet,
  escapeHtml,
  formatBoolean,
  renderAttestationResultRow,
} from '../../../../frontend/static/scripts/advanced/ui/display-utils.js';

describe('display-utils', () => {
  it('formats booleans and fallback values safely', () => {
    expect(formatBoolean(true)).toContain('true');
    expect(formatBoolean(false)).toContain('false');
    expect(formatBoolean(' true ')).toContain('true');
    expect(formatBoolean(' FALSE ')).toContain('false');
    expect(formatBoolean(null)).toContain('N/A');
    expect(formatBoolean('<unsafe>')).toContain('&lt;unsafe&gt;');
  });

  it('renders attestation rows and metadata labels', () => {
    const row = renderAttestationResultRow('<Label>', true, '<em>extra</em>');
    expect(row).toContain('&lt;Label&gt;');
    expect(row).toContain('<em>extra</em>');

    expect(describeCoseAlgorithm(-7)).toBe('ES256 (-7)');
    expect(describeCoseAlgorithm(null)).toBe('Unknown');
    expect(describeCoseAlgorithm(12345)).toBe('Algorithm (12345)');

    expect(describeCoseKeyType(1)).toBe('OKP (1)');
    expect(describeCoseKeyType(undefined)).toBe('Unknown');

    expect(describeMldsaParameterSet(-48)).toBe('ML-DSA-44');
    expect(describeMldsaParameterSet(-49)).toBe('ML-DSA-65');
    expect(describeMldsaParameterSet('-50')).toBe('ML-DSA-87');
    expect(describeMldsaParameterSet('unknown')).toBe('');
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(`'"<&>`)).toBe('&#39;&quot;&lt;&amp;&gt;');
  });
});
