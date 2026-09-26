import { MISSING_METADATA_MESSAGE } from '@legacy/advanced/mds/constants.js';
import { EXPLORER_NO_MATCHES } from '@legacy/advanced/mds/explorer/status.js';
import { useRef, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { NAV_ID } from '@/components/shell/SectionPanel';
import { SECTIONS } from '@/lib/sections';

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

// The FIDO MDS section: every authenticator the FIDO Metadata Service
// publishes, with what the current UI's explorer shows of each, in a table that
// sorts, resizes and expands.
export function MdsSection({ active }: { active: boolean }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'mds')!;
  const ids = segmentIds(NAV_ID, 'mds');
  const explorer = useMdsExplorer(active);
  const view = useExplorerView(explorer.entries, explorer.version);
  const frameRef = useRef<HTMLDivElement>(null);
  const manageRef = useRef<HTMLButtonElement>(null);
  const [managing, setManaging] = useState(false);

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
          <div className="mt-3">
            <EntryCount shown={view.shown.size} total={explorer.entries.length} />
          </div>
        </div>
        <Button
          ref={manageRef}
          variant="secondary"
          aria-haspopup="dialog"
          aria-expanded={managing}
          onClick={() => setManaging(true)}
        >
          Manage Metadata
        </Button>
      </div>
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
          state={listState(explorer, view)}
          frameRef={frameRef}
        />
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
