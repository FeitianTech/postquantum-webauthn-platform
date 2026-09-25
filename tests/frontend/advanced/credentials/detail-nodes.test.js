import { describe, expect, it } from 'vitest';

import {
  attestationResultRow,
  booleanValue,
  labelledLine,
} from '../../../../frontend/static/scripts/advanced/credential-display/detail-nodes.js';

const PAYLOAD = '<img src=x onerror="window.__xss=1">';

describe('detail nodes', () => {
  it.each([
    [true, 'true', 'rgb(17, 182, 109)'],
    [' TRUE ', 'true', 'rgb(17, 182, 109)'],
    [false, 'false', 'rgb(198, 40, 40)'],
    ['false', 'false', 'rgb(198, 40, 40)'],
    [null, 'N/A', 'rgb(108, 117, 125)'],
    [undefined, 'N/A', 'rgb(108, 117, 125)'],
    [PAYLOAD, PAYLOAD, 'rgb(108, 117, 125)'],
  ])('shows %j as %s', (value, text, colour) => {
    const node = booleanValue(value);

    expect(node.textContent).toBe(text);
    expect(node.style.color).toBe(colour);
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
    expect(line.style.marginBottom).toBe('0.5rem');
    expect(line.querySelector('img')).toBeNull();
  });
});
