import { describe, expect, it } from 'vitest';

import {
  attestationResultRow,
  booleanValue,
  labelledLine,
} from '../../../../frontend/static/scripts/advanced/credential-display/detail-nodes.js';

const PAYLOAD = '<img src=x onerror="window.__xss=1">';

describe('detail nodes', () => {
  it.each([
    [true, 'true', '#11b66d'],
    [' TRUE ', 'true', '#11b66d'],
    [false, 'false', '#c62828'],
    ['false', 'false', '#c62828'],
    [null, 'N/A', '#6c757d'],
    [undefined, 'N/A', '#6c757d'],
    [PAYLOAD, PAYLOAD, '#6c757d'],
  ])('shows %j as %s', (value, text, colour) => {
    const node = booleanValue(value);

    expect(node.textContent).toBe(text);
    expect(node.getAttribute('style')).toContain(colour);
    expect(node.querySelector('img')).toBeNull();
  });

  it('puts a label, the value and what follows it in one row', () => {
    const extra = document.createElement('em');
    extra.textContent = '(chain)';

    const row = attestationResultRow(PAYLOAD, true, extra);

    expect(row.querySelector('strong').textContent).toBe(`${PAYLOAD}:`);
    expect(row.textContent).toBe(`${PAYLOAD}:true(chain)`);
    expect(row.querySelector('img')).toBeNull();
  });

  it('writes a labelled line with its value as text', () => {
    const line = labelledLine('Name:', PAYLOAD, { style: 'margin-bottom: 0.5rem;' });

    expect(line.textContent).toBe(`Name: ${PAYLOAD}`);
    expect(line.getAttribute('style')).toBe('margin-bottom: 0.5rem;');
    expect(line.querySelector('img')).toBeNull();
  });
});
