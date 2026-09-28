import { useCallback, useEffect } from 'react';

import { CeremonyResult } from '@/components/ceremony/CeremonyResult';
import { CredentialDetailDialog } from '@/components/credentials/CredentialDetailDialog';
import { SavedCredentials } from '@/components/credentials/SavedCredentials';
import { Button, IconButton } from '@/components/ui/Button';
import { TextField } from '@/components/ui/Field';
import { RefreshIcon, Spinner } from '@/components/ui/icons';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { useEntrance } from '@/lib/entrance';
import { NAV_ID, SECTIONS } from '@/lib/sections';
import type { SectionRoute } from '@/lib/useSection';

import { useSimpleCeremony } from './useSimpleCeremony';

// The username, the two ceremonies' buttons (one height, one width), what the
// running step is doing, why the last one failed, and what the server made of
// it. A card of its own beside the saved credentials: no card in a card.
function CeremonyCard() {
  const ceremony = useSimpleCeremony();
  const running = ceremony.running !== null;
  return (
    <div className="flex min-w-0 flex-col gap-5 rounded-lg border border-line bg-surface p-5 sm:p-6" data-simple-ceremony="">
      <TextField
        label="Username"
        placeholder="Enter username"
        value={ceremony.username}
        onChange={(event) => ceremony.changeUsername(event.target.value)}
        error={ceremony.usernameError}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        trailing={<IconButton size="sm" label="Generate random username" icon={<RefreshIcon />} onClick={ceremony.randomize} />}
      />
      <div className="grid grid-cols-2 gap-2">
        <Button busy={ceremony.running === 'registration'} disabled={running} onClick={() => void ceremony.register()}>
          Register Passkey
        </Button>
        <Button
          variant="secondary"
          busy={ceremony.running === 'authentication'}
          disabled={running}
          onClick={() => void ceremony.authenticate()}
        >
          Authenticate
        </Button>
      </div>
      {ceremony.progress ? (
        <p role="status" className="flex items-center gap-2 text-body text-ink-muted" data-role="progress">
          <Spinner />
          {ceremony.progress}
        </p>
      ) : null}
      {ceremony.failure ? (
        <p role="alert" className="rounded-sm border border-danger-line bg-danger-tint px-4 py-3 text-body text-danger wrap-anywhere" data-role="failure">
          {ceremony.failure}
        </p>
      ) : null}
      <CeremonyResult result={ceremony.result} />
    </div>
  );
}

// The Simple tab: register and authenticate with passkeys using default presets,
// beside the saved credentials both tabs share. From 1024 px the form stays in
// view (under the measured header) while a long list scrolls.
export function SimpleSection({ active, route }: { active: boolean; route: SectionRoute }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'simple')!;
  const entrance = useEntrance(active);
  const ids = segmentIds(NAV_ID, 'simple');
  const { path, replace } = route;
  // What the URL may open here: a credential's details, #simple/credential/<key>,
  // and the levels inside them, which the dialog checks.
  const known = path.length === 0 || (path[0] === 'credential' && path.length >= 2);
  const backToList = useCallback(() => replace([]), [replace]);

  // A path this section does not know shows the list, and the URL says so.
  useEffect(() => {
    if (!known) backToList();
  }, [known, backToList]);

  return (
    <section
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={!active}
      className={entrance}
    >
      <h2 className="text-display font-semibold text-ink">{section.label}</h2>
      <p className="mt-2 max-w-prose text-body-lg text-ink-muted">{section.description}</p>
      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)] lg:gap-8">
        <div className="min-w-0 lg:sticky lg:top-[calc(var(--header-height)+1.5rem)] lg:self-start" data-simple-column="ceremony">
          <CeremonyCard />
        </div>
        <SavedCredentials onOpen={(key) => route.open(['credential', key])} />
      </div>
      <CredentialDetailDialog route={known ? route : { ...route, path: [] }} />
    </section>
  );
}
