import { MDS_MIN_COLUMN_WIDTH, normaliseExplorerColumnWidths } from '@/logic/mds/explorer/columns.js';
import { type RefObject, useCallback, useLayoutEffect, useState } from 'react';

import { EXPLORER_COLUMNS, type ExplorerColumn } from './columns';

// The columns' widths, set on the table and read by every row's grid.
const COLUMNS_PROPERTY = '--mds-columns';

// Below the `sm` breakpoint.
const PHONE = '(max-width: 639px)';

export function minimumWidth(column: ExplorerColumn) {
  return 'min' in column ? column.min : MDS_MIN_COLUMN_WIDTH;
}

// The explorer table's column widths, set on the table through the CSSOM (the
// CSP refuses style attributes), and resize(index, width), never under a
// column's minimum. A phone has the narrower columns, and the table follows the
// window as it narrows to a phone's width or widens from one (after hydration:
// the exported page has the wide columns, and a width is in its markup). A width
// a person set is kept.
export function useColumnWidths(tableRef: RefObject<HTMLTableElement | null>) {
  const [widths, setWidths] = useState<number[]>(() => EXPLORER_COLUMNS.map((column) => column.width));

  useLayoutEffect(() => {
    const table = tableRef.current;
    if (!table) return;
    table.style.setProperty(COLUMNS_PROPERTY, widths.map((width) => `${width}px`).join(' '));
    table.style.width = `${widths.reduce((sum, width) => sum + width, 0)}px`;
  }, [widths, tableRef]);

  useLayoutEffect(() => {
    const phone = window.matchMedia(PHONE);
    const follow = (narrow: boolean) =>
      setWidths((current) =>
        current.map((width, index) => {
          const column = EXPLORER_COLUMNS[index];
          if (!('phoneWidth' in column)) return width;
          if (narrow && width === column.width) return column.phoneWidth;
          if (!narrow && width === column.phoneWidth) return column.width;
          return width;
        }),
      );
    if (phone.matches) follow(true);
    const onChange = (event: MediaQueryListEvent) => follow(event.matches);
    phone.addEventListener('change', onChange);
    return () => phone.removeEventListener('change', onChange);
  }, []);

  const resize = useCallback((index: number, width: number) => {
    setWidths((current) => {
      const next = [...current];
      [next[index]] = normaliseExplorerColumnWidths([width], minimumWidth(EXPLORER_COLUMNS[index]));
      return next;
    });
  }, []);

  return { widths, resize };
}
