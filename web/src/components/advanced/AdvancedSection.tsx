import { useCallback, useEffect, useRef, useState } from 'react';

import { CeremonyResult } from '@/components/ceremony/CeremonyResult';
import { UpdateBrowserNotice, useNativeWebAuthn } from '@/components/ceremony/UpdateBrowserNotice';
import { CredentialDetailDialog } from '@/components/credentials/CredentialDetailDialog';
import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/icons';
import { SegmentedControl, segmentIds } from '@/components/ui/SegmentedControl';
import { useEntrance } from '@/lib/entrance';
import { NAV_ID, SECTIONS } from '@/lib/sections';
import type { SectionRoute } from '@/lib/useSection';

import { AuthenticationForm } from './AuthenticationForm';
import { CredentialsDrawer, DRAWER_ID } from './CredentialsDrawer';
import { JsonEditor } from './JsonEditor';
import { RegistrationForm } from './RegistrationForm';
import { useAdvancedRequest } from './useAdvancedRequest';
import { useAuthenticationCeremony } from './useAuthenticationCeremony';
import { useAuthenticationRequest } from './useAuthenticationRequest';
import { useRegistrationCeremony } from './useRegistrationCeremony';

type Ceremony = 'registration' | 'authentication';

const CEREMONY_ID = 'advanced-ceremony';
const CEREMONIES = [
  { value: 'registration', label: 'Registration' },
  { value: 'authentication', label: 'Authentication' },
] as const;

// The Advanced tab: configure a WebAuthn registration or authentication request
// in detail and run it. A toolbar over everything (which ceremony, the saved
// credentials, Reset, the ceremony's button), what the last ceremony did, then
// the form and, from a wide screen, the JSON editor beside it in view (under the
// measured header) while the form scrolls; below it on narrower ones.
export function AdvancedSection({ active, route }: { active: boolean; route: SectionRoute }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'advanced')!;
  const entrance = useEntrance(active);
  const ids = segmentIds(NAV_ID, 'advanced');
  const [ceremony, setCeremony] = useState<Ceremony>('registration');
  const saved = useSavedCredentials();
  const request = useAdvancedRequest();
  const assertion = useAuthenticationRequest();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const drawerButton = useRef<HTMLButtonElement>(null);
  const createButton = useRef<HTMLButtonElement>(null);
  // Where the focus goes when a credential's details close: Create Credential
  // after a registration opened them, else what had it (a name in the drawer).
  const detailReturn = useRef<HTMLElement | null>(null);
  const activeRef = useRef(active);
  activeRef.current = active;
  const routeRef = useRef(route);
  routeRef.current = route;

  // A registration opens the new credential's details at its registration, the
  // detail under it (two history entries: Back goes to the detail, × closes
  // both), unless the person has left the section meanwhile.
  const openRegistration = useCallback((key: string) => {
    if (!activeRef.current) return;
    detailReturn.current = createButton.current;
    routeRef.current.open(['credential', key]);
    routeRef.current.open(['credential', key, 'registration']);
  }, []);
  const registration = useRegistrationCeremony(request, openRegistration);
  const authentication = useAuthenticationCeremony(assertion);
  // A browser without WebAuthn's JSON methods is told to update, and runs nothing.
  const supported = useNativeWebAuthn();

  const { path, replace } = route;
  // What the URL may open here: a credential's details, #advanced/credential/<key>,
  // and the levels inside them, which the dialog checks.
  const known = path.length === 0 || (path[0] === 'credential' && path.length >= 2);
  const backToForm = useCallback(() => replace([]), [replace]);
  useEffect(() => {
    if (!known) backToForm();
  }, [known, backToForm]);

  // Leaving the section closes the drawer: it is not a place of its own.
  useEffect(() => {
    if (!active) setDrawerOpen(false);
  }, [active]);

  // One ceremony at a time: the browser asks the authenticator one thing at once.
  const running = registration.running || authentication.running;
  const shown = ceremony === 'registration' ? registration : authentication;
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

      <div className="mt-8 flex flex-wrap items-center gap-3" data-advanced-toolbar="">
        <SegmentedControl label="Ceremony" options={CEREMONIES} value={ceremony} onChange={setCeremony} idBase={CEREMONY_ID} size="sm" />
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Button
            ref={drawerButton}
            variant="secondary"
            aria-haspopup="dialog"
            aria-controls={DRAWER_ID}
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            Saved Credentials{' '}
            {saved.loaded ? (
              <Badge tone="neutral" data-count="">
                {saved.rows.length}
              </Badge>
            ) : null}
          </Button>
          {ceremony === 'registration' ? (
            <>
              <Button variant="secondary" disabled={running} onClick={request.resetForm}>
                Reset
              </Button>
              <Button
                ref={createButton}
                busy={registration.running}
                disabled={authentication.running || !supported}
                onClick={() => void registration.register()}
              >
                Create Credential
              </Button>
            </>
          ) : (
            <>
              <Button variant="secondary" disabled={running} onClick={assertion.resetForm}>
                Reset
              </Button>
              <Button
                busy={authentication.running}
                disabled={registration.running || !supported}
                onClick={() => void authentication.assert()}
              >
                Assert Credential
              </Button>
            </>
          )}
        </div>
      </div>

      {/* What the ceremony of the segment shown is doing, or what stopped it. */}
      <div className="mt-5 flex flex-col gap-4 empty:hidden">
        {supported ? null : <UpdateBrowserNotice />}
        {shown.progress ? (
          <p role="status" className="flex items-center gap-2 text-body text-ink-muted" data-role="progress">
            <Spinner />
            {shown.progress}
          </p>
        ) : null}
        {shown.failure ? (
          <p role="alert" className="rounded-sm border border-danger-line bg-danger-tint px-4 py-3 text-body text-danger wrap-anywhere" data-role="failure">
            {shown.failure}
          </p>
        ) : null}
      </div>
      <div className="mt-4 empty:hidden">
        <CeremonyResult result={shown.result} />
      </div>

      <div
        role="tabpanel"
        id={segmentIds(CEREMONY_ID, 'registration').panel}
        aria-labelledby={segmentIds(CEREMONY_ID, 'registration').tab}
        hidden={ceremony !== 'registration'}
        className="mt-6 grid grid-cols-1 gap-6 wide:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] wide:gap-8"
      >
        <RegistrationForm request={request} />
        <div className="min-w-0 wide:sticky wide:top-[calc(var(--header-height)+1.5rem)] wide:h-[calc(100dvh-var(--header-height)-3rem)] wide:self-start">
          <JsonEditor scope="registration" request={request} />
        </div>
      </div>
      <div
        role="tabpanel"
        id={segmentIds(CEREMONY_ID, 'authentication').panel}
        aria-labelledby={segmentIds(CEREMONY_ID, 'authentication').tab}
        hidden={ceremony !== 'authentication'}
        className="mt-6 grid grid-cols-1 gap-6 wide:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] wide:gap-8"
      >
        <AuthenticationForm request={assertion} />
        <div className="min-w-0 wide:sticky wide:top-[calc(var(--header-height)+1.5rem)] wide:h-[calc(100dvh-var(--header-height)-3rem)] wide:self-start">
          <JsonEditor scope="authentication" request={assertion} />
        </div>
      </div>

      <CredentialsDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onOpen={(key) => {
          detailReturn.current = null;
          route.open(['credential', key]);
        }}
        returnFocusTo={() => drawerButton.current}
      />
      <CredentialDetailDialog route={known ? route : { ...route, path: [] }} returnFocusTo={() => detailReturn.current} />
    </section>
  );
}
