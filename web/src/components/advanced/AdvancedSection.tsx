import { type ReactNode, type RefObject, useCallback, useEffect, useRef, useState } from 'react';

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
import type { CeremonyResultInput } from '@/logic/shared/ceremony-result.js';

// The requests' hooks before the parts that show them: webpack lays the page's
// modules out in the order they are imported, and the requests' logic beside the
// editor's gzips about 2 KB smaller than with the forms between them.
import { useAdvancedRequest } from './useAdvancedRequest';
import { useAuthenticationCeremony } from './useAuthenticationCeremony';
import { useAuthenticationRequest } from './useAuthenticationRequest';
import { useRegistrationCeremony } from './useRegistrationCeremony';
import { AuthenticationForm } from './AuthenticationForm';
import { CredentialsDrawer, DRAWER_ID } from './CredentialsDrawer';
import { JsonEditor } from './JsonEditor';
import { RegistrationForm } from './RegistrationForm';
import type { RequestEditor } from './requestEditor';

type Ceremony = 'registration' | 'authentication';

const CEREMONY_ID = 'advanced-ceremony';
const CEREMONIES = [
  { value: 'registration', label: 'Registration' },
  { value: 'authentication', label: 'Authentication' },
] as const;

type Requests = { request: ReturnType<typeof useAdvancedRequest>; assertion: ReturnType<typeof useAuthenticationRequest> };
type Ceremonies = {
  registration: ReturnType<typeof useRegistrationCeremony>;
  authentication: ReturnType<typeof useAuthenticationCeremony>;
};

// Which ceremony, the saved credentials, Reset, and the ceremony's button: one
// ceremony at a time, as the browser asks the authenticator one thing at once.
function AdvancedToolbar({
  ceremony,
  onCeremony,
  drawerOpen,
  onOpenDrawer,
  drawerButton,
  createButton,
  requests: { request, assertion },
  ceremonies: { registration, authentication },
  supported,
}: {
  ceremony: Ceremony;
  onCeremony: (ceremony: Ceremony) => void;
  drawerOpen: boolean;
  onOpenDrawer: () => void;
  drawerButton: RefObject<HTMLButtonElement | null>;
  createButton: RefObject<HTMLButtonElement | null>;
  requests: Requests;
  ceremonies: Ceremonies;
  supported: boolean;
}) {
  const saved = useSavedCredentials();
  const running = registration.running || authentication.running;
  return (
    <div className="mt-8 flex flex-wrap items-center gap-3" data-advanced-toolbar="">
      <SegmentedControl label="Ceremony" options={CEREMONIES} value={ceremony} onChange={onCeremony} idBase={CEREMONY_ID} size="sm" />
      <div className="ml-auto flex flex-wrap items-center gap-2">
        <Button
          ref={drawerButton}
          variant="secondary"
          aria-haspopup="dialog"
          aria-controls={DRAWER_ID}
          aria-expanded={drawerOpen}
          onClick={onOpenDrawer}
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
  );
}

// What the ceremony of the segment shown is doing, or what stopped it, and what
// the last one did.
function CeremonyStatus({
  supported,
  shown,
}: {
  supported: boolean;
  shown: { progress: string | null; failure: string | null; result: CeremonyResultInput | null };
}) {
  return (
    <>
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
    </>
  );
}

// A ceremony's segment: its form and, from a wide screen, the JSON editor beside
// it in view (under the measured header) while the form scrolls.
function CeremonyPanel({ scope, hidden, form, request }: { scope: Ceremony; hidden: boolean; form: ReactNode; request: RequestEditor }) {
  const ids = segmentIds(CEREMONY_ID, scope);
  return (
    <div
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={hidden}
      className="mt-6 grid grid-cols-1 gap-6 wide:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] wide:gap-8"
    >
      {form}
      <div className="min-w-0 wide:sticky wide:top-[calc(var(--header-height)+1.5rem)] wide:h-[calc(100dvh-var(--header-height)-3rem)] wide:self-start">
        <JsonEditor scope={scope} request={request} />
      </div>
    </div>
  );
}

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

      <AdvancedToolbar
        ceremony={ceremony}
        onCeremony={setCeremony}
        drawerOpen={drawerOpen}
        onOpenDrawer={() => setDrawerOpen(true)}
        drawerButton={drawerButton}
        createButton={createButton}
        requests={{ request, assertion }}
        ceremonies={{ registration, authentication }}
        supported={supported}
      />
      <CeremonyStatus supported={supported} shown={shown} />
      <CeremonyPanel scope="registration" hidden={ceremony !== 'registration'} form={<RegistrationForm request={request} />} request={request} />
      <CeremonyPanel
        scope="authentication"
        hidden={ceremony !== 'authentication'}
        form={<AuthenticationForm request={assertion} />}
        request={assertion}
      />

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
