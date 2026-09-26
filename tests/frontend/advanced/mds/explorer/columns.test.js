import { describe, expect, it } from 'vitest';

import {
  MDS_MIN_COLUMN_WIDTH,
  normaliseExplorerColumnWidths,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/columns.js';

describe('column widths', () => {
  it('keeps whole pixels, never under the minimum', () => {
    expect(MDS_MIN_COLUMN_WIDTH).toBe(64);
    expect(normaliseExplorerColumnWidths([120.4, 10, 0, -5, Number.NaN, Infinity])).toEqual([120, 64, 64, 64, 64, 64]);
    expect(normaliseExplorerColumnWidths([50, 99.6], 40)).toEqual([50, 100]);
  });

  it('reads nothing that is not a list', () => {
    expect(normaliseExplorerColumnWidths(null)).toEqual([]);
  });
});
