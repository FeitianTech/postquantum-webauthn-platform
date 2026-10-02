import {
  type ExplorerSort,
  countActiveExplorerFilters,
  defaultExplorerSort,
  matchesExplorerFilters,
  nextExplorerSort,
  sortExplorerEntries,
} from '@/logic/mds/explorer/filter-sort.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { explorerFilterOptionLists } from '@/logic/mds/explorer/options.js';
import { useCallback, useDeferredValue, useEffect, useMemo, useState } from 'react';

import { emptyFilters } from './columns';

// How the list is looked at: the filters as typed, their options, the sort (reset
// to the default, newest first, whenever a snapshot is shown; the filters stay),
// and the rows expanded to show every word. Filtering reads the typed text
// trimmed, and follows the typing
// through React's deferred value, so a keystroke is never kept waiting for the
// rows.
export function useExplorerView(entries: MdsEntry[], version: number) {
  const [filters, setFilters] = useState<Record<string, string>>(emptyFilters);
  const [sort, setSort] = useState<ExplorerSort>(defaultExplorerSort);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    setSort(defaultExplorerSort());
  }, [version]);

  const setFilter = useCallback((key: string, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
  }, []);
  const clearFilters = useCallback(() => setFilters(emptyFilters()), []);

  const onSort = useCallback((key: string) => {
    setSort((current) => nextExplorerSort(current, key) ?? current);
  }, []);

  const onToggle = useCallback((entryId: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (!next.delete(entryId)) next.add(entryId);
      return next;
    });
  }, []);

  const options = useMemo(() => explorerFilterOptionLists(entries), [entries]);
  const applied = useDeferredValue(filters);
  const trimmed = useMemo(
    () => Object.fromEntries(Object.entries(applied).map(([key, value]) => [key, value.trim()])),
    [applied],
  );

  const rows = useMemo(() => sortExplorerEntries(entries, sort), [entries, sort]);
  const shown = useMemo(
    () => new Set(entries.filter((entry) => matchesExplorerFilters(entry, trimmed, options.certification)).map((entry) => entry.entryId)),
    [entries, trimmed, options],
  );
  const filteredColumns = useMemo(
    () => new Set(Object.entries(trimmed).filter(([, value]) => value).map(([key]) => key)),
    [trimmed],
  );

  return {
    filters,
    setFilter,
    clearFilters,
    activeFilters: countActiveExplorerFilters(filters),
    filteredColumns,
    options,
    sort,
    onSort,
    rows,
    shown,
    expanded,
    onToggle,
  };
}
