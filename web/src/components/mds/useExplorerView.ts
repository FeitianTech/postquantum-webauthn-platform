import { useCallback, useEffect, useMemo, useState } from 'react';

import { type ExplorerSort, type MdsEntry, initialSort, sortAfterClick, sortEntries } from './model';

// How the list is looked at: its sort (reset to the default, newest first,
// whenever a snapshot is shown, as the current UI does) and the rows expanded to
// show every word.
export function useExplorerView(entries: MdsEntry[], version: number) {
  const [sort, setSort] = useState<ExplorerSort>(initialSort);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    setSort(initialSort());
  }, [version]);

  const onSort = useCallback((key: string) => {
    setSort((current) => sortAfterClick(current, key) ?? current);
  }, []);

  const onToggle = useCallback((entryId: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (!next.delete(entryId)) next.add(entryId);
      return next;
    });
  }, []);

  const rows = useMemo(() => sortEntries(entries, sort), [entries, sort]);
  const shown = useMemo(() => new Set(entries.map((entry) => entry.entryId)), [entries]);

  return { sort, onSort, rows, shown, expanded, onToggle };
}
