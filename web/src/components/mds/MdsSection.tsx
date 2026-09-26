import { MISSING_METADATA_MESSAGE } from '@legacy/advanced/mds/constants.js';
import { EXPLORER_NO_MATCHES } from '@legacy/advanced/mds/explorer/status.js';
import { useCallback, useLayoutEffect, useRef, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { NAV_ID } from '@/components/shell/SectionPanel';
import { SECTIONS } from '@/lib/sections';
import type { SectionRoute } from '@/lib/useSection';

import { EntryView } from './EntryView';
import { EntryCount, StatusLine } from './ExplorerHeader';
import { ExplorerTable } from './ExplorerTable';
import { FilterBar } from './FilterBar';
import { ManageMetadataDialog } from './ManageMetadataDialog';
import { ListState } from './ListState';
import { useExplorerView } from './useExplorerView';
import { type Explorer, useMdsExplorer } from './useMdsExplorer';

function listState(explorer: Explorer, view: ReturnType<typeof useExplorerView>) {
  if (explorer.phase === 'failed' && !explorer.entries.length) {
    return (
      <ListState
        tone="danger"
        action={
          <Button variant="secondary" size="sm" onClick={explorer.retry}>
            Retry
          </Button>
        }
      >
        {explorer.status.text}
      </ListState>
    );
  }
  if (explorer.phase !== 'loaded' && !explorer.entries.length) {
    return <ListState busy>Authenticator metadata is loading…</ListState>;
  }
  if (explorer.missing) return <ListState>{MISSING_METADATA_MESSAGE}</ListState>;
  if (!view.shown.size) {
    return (
      <ListState
        action={
          <Button variant="secondary" size="sm" onClick={view.clearFilters}>
            Clear filters
          </Button>
        }
      >
        {EXPLORER_NO_MATCHES}
      </ListState>
    );
  }
  return null;
}

type ListPlace = { entryId: string; windowY: number; top: number; left: number };

const CLOSED: SectionRoute = { subPath: '', open: () => {}, close: () => {} };

// The FIDO MDS section: every authenticator the FIDO Metadata Service
// publishes, with what the current UI's explorer shows of each, in a table that
// sorts, filters, resizes and expands. A row opens its entry (#mds/<entryId>);
// the list stays in the page meanwhile, so going back finds it as it was: its
// filters, sort, widths and scroll, with the focus on the row.
export function MdsSection({ active, route = CLOSED }: { active: boolean; route?: SectionRoute }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'mds')!;
  const ids = segmentIds(NAV_ID, 'mds');
  const explorer = useMdsExplorer(active);
  const view = useExplorerView(explorer.entries, explorer.version);
  const frameRef = useRef<HTMLDivElement>(null);
  const manageRef = useRef<HTMLButtonElement>(null);
  const [managing, setManaging] = useState(false);
  const place = useRef<ListPlace | null>(null);
  const shownEntry = useRef('');
  const openEntryId = route.subPath;
  const { open } = route;

  const openEntry = useCallback(
    (entryId: string) => {
      const frame = frameRef.current;
      place.current = { entryId, windowY: window.scrollY, top: frame?.scrollTop ?? 0, left: frame?.scrollLeft ?? 0 };
      open(entryId);
    },
    [open],
  );

  // Back to the list: where it was, and the focus on the row that was opened (or
  // on the entry a link opened, brought into view).
  useLayoutEffect(() => {
    const closed = shownEntry.current;
    shownEntry.current = openEntryId;
    if (openEntryId) {
      window.scrollTo({ top: 0 });
      return;
    }
    if (!closed) return;
    const frame = frameRef.current;
    const saved = place.current?.entryId === closed ? place.current : null;
    place.current = null;
    const link = frame?.querySelector<HTMLElement>(`[data-entry-link="${CSS.escape(closed)}"]`);
    if (saved && frame) {
      window.scrollTo({ top: saved.windowY });
      frame.scrollTop = saved.top;
      frame.scrollLeft = saved.left;
    } else {
      link?.scrollIntoView({ block: 'center' });
    }
    link?.focus({ preventScroll: true });
  }, [openEntryId]);

  return (
    <section
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={!active}
      className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none"
    >
      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-5">
        <div className="min-w-0">
          <h2 className="text-display font-semibold text-ink">{section.label}</h2>
          <p className="mt-2 max-w-prose text-body-lg text-ink-muted">{section.description}</p>
          <div className="mt-3" hidden={Boolean(openEntryId)}>
            <EntryCount shown={view.shown.size} total={explorer.entries.length} />
          </div>
        </div>
        <Button
          ref={manageRef}
          variant="secondary"
          hidden={Boolean(openEntryId)}
          aria-haspopup="dialog"
          aria-expanded={managing}
          onClick={() => setManaging(true)}
        >
          Manage Metadata
        </Button>
      </div>
      {openEntryId ? (
        <div className="mt-8">
          <EntryView
            entryId={openEntryId}
            entry={explorer.entries.find((entry) => entry.entryId === openEntryId) ?? null}
            loading={explorer.phase === 'idle' || explorer.phase === 'loading'}
            onBack={route.close}
          />
        </div>
      ) : null}
      <div hidden={Boolean(openEntryId)} data-mds-list="">
        <div className="mt-5">
          <StatusLine
            status={explorer.status}
            loading={explorer.phase === 'loading'}
            failed={explorer.phase === 'failed'}
            onRetry={explorer.retry}
          />
        </div>
        <div className="mt-6">
          <FilterBar
            filters={view.filters}
            options={view.options}
            activeFilters={view.activeFilters}
            onChange={view.setFilter}
            onClear={view.clearFilters}
          />
        </div>
        <div className="mt-6">
          <ExplorerTable
            rows={view.rows}
            shown={view.shown}
            sort={view.sort}
            onSort={view.onSort}
            filteredColumns={view.filteredColumns}
            expanded={view.expanded}
            onToggle={view.onToggle}
            onOpen={openEntry}
            state={listState(explorer, view)}
            frameRef={frameRef}
          />
        </div>
      </div>
      <ManageMetadataDialog
        open={managing}
        onClose={() => setManaging(false)}
        returnFocusTo={() => manageRef.current}
        onSnapshot={explorer.applySnapshot}
        onReload={explorer.reload}
      />
    </section>
  );
}
