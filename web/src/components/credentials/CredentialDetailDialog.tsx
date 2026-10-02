import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';

import { Spinner } from '@/components/ui/icons';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';
import type { SectionRoute } from '@/lib/useSection';
import { HYDRATE_TEXT } from '@/logic/credentials/hydrate.js';
import { describeAttestationCertificate, describeAuthenticatorData } from '@/logic/credentials/registration/view.js';
import type { CredentialRowView } from '@/logic/credentials/saved-list.js';

import { DetailSections } from './detail/DetailSections';
import { AuthenticatorDataLevel, CertificateLevel, RegistrationLevel } from './detail/RegistrationLevels';
import { useCredentialDetail } from './detail/useCredentialDetail';
import { useSavedCredentials } from './useSavedCredentials';

// What the URL opens inside a credential's details, after #…/credential/<key>:
// nothing (the detail), registration, then one of its certificates (counted
// from 1, as their buttons are) or its authenticator data.
type Level =
  | { kind: 'detail'; depth: 0 }
  | { kind: 'registration'; depth: 1 }
  | { kind: 'certificate'; depth: 2; number: number }
  | { kind: 'authenticator-data'; depth: 2 };

const NUMBER = /^[1-9]\d*$/;

function levelOf(rest: string[]): Level | null {
  if (!rest.length) return { kind: 'detail', depth: 0 };
  if (rest[0] !== 'registration') return null;
  if (rest.length === 1) return { kind: 'registration', depth: 1 };
  if (rest.length === 3 && rest[1] === 'certificate' && NUMBER.test(rest[2])) {
    return { kind: 'certificate', depth: 2, number: Number(rest[2]) };
  }
  if (rest.length === 2 && rest[1] === 'authenticator-data') return { kind: 'authenticator-data', depth: 2 };
  return null;
}

function levelName(level: Level) {
  return level.kind === 'certificate' ? `certificate-${level.number}` : level.kind;
}

const TITLES = { detail: 'Credential Details', registration: 'Registration Details' } as const;

/**
 * A saved credential's details, in a dialog over its section at its own URL
 * (#simple/credential/<key>): the detail, then the registration's level
 * (…/registration) and under it a certificate's (…/certificate/<n>) or the
 * authenticator data's (…/authenticator-data). Each level is a history entry of
 * its own, so Back goes up one; a link or a reload opens any of them, and a
 * level the credential does not have is corrected to the one above it. Back in
 * the header goes up a level; ×, Escape and the backdrop close them all.
 */
export function CredentialDetailDialog({
  route,
  returnFocusTo,
}: {
  route: SectionRoute;
  /** Where the focus goes when the details close; by default what had it when they opened. */
  returnFocusTo?: () => HTMLElement | null;
}) {
  const saved = useSavedCredentials();
  const titleId = useId();
  const idBase = useId();
  const [, key = '', ...rest] = route.path;
  const open = route.path[0] === 'credential' && Boolean(key);
  const row = open ? saved.rows.find((candidate) => candidate.key === key) ?? null : null;
  // The last one shown stays while the dialog closes, so its words do not vanish.
  const [shown, setShown] = useState<CredentialRowView | null>(null);
  useEffect(() => {
    if (row) setShown(row);
  }, [row]);

  const { replace, open: openPath, close, closeAll } = route;
  useEffect(() => {
    if (open && saved.loaded && !row) replace([]);
  }, [open, saved.loaded, row, replace]);

  const refresh = saved.refresh;
  const detail = useCredentialDetail(row?.credential ?? null, row ? key : '', refresh);
  const ready = detail.phase === 'ready' ? detail : null;

  const base = ['credential', key];
  const registrationPath = [...base, 'registration'];
  const wanted = levelOf(rest);
  const certificate = ready && wanted?.kind === 'certificate' ? describeAttestationCertificate(ready.state, wanted.number - 1) : null;
  const authenticatorData = ready && wanted?.kind === 'authenticator-data' ? describeAuthenticatorData(ready.state) : null;
  const known =
    wanted !== null &&
    (wanted.kind === 'certificate' ? Boolean(certificate) : wanted.kind === 'authenticator-data' ? Boolean(authenticatorData) : true);
  // Until the details are composed a deeper level cannot be checked; then one
  // the credential does not have is corrected to the level above it.
  const level: Level = ready && !known ? (rest[0] === 'registration' ? { kind: 'registration', depth: 1 } : { kind: 'detail', depth: 0 }) : (wanted ?? { kind: 'detail', depth: 0 });
  const correction = open && row && (wanted === null || (ready && !known));
  useEffect(() => {
    if (correction) replace(level.depth ? ['credential', key, 'registration'] : ['credential', key]);
  }, [correction, level.depth, key, replace]);

  // Going deeper starts at the top; going back finds the level as it was, the
  // focus on what opened the one left.
  const levelRef = useRef<HTMLDivElement>(null);
  const previous = useRef<{ key: string; level: Level } | null>(null);
  const scrolls = useRef(new Map<string, number>());
  useLayoutEffect(() => {
    const before = previous.current;
    previous.current = open ? { key, level } : null;
    const scroller = levelRef.current?.closest<HTMLElement>('[data-overlay-scroll]');
    if (!before || before.key !== key || !scroller) return;
    if (level.depth > before.level.depth) {
      scrolls.current.set(levelName(before.level), scroller.scrollTop);
      scroller.scrollTop = 0;
      levelRef.current?.querySelector<HTMLElement>(`[data-level="${levelName(level)}"]`)?.focus({ preventScroll: true });
    } else if (level.depth < before.level.depth) {
      scroller.scrollTop = scrolls.current.get(levelName(level)) ?? 0;
      levelRef.current
        ?.querySelector<HTMLElement>(`[data-level="${levelName(level)}"] [data-level-open="${levelName(before.level)}"]`)
        ?.focus({ preventScroll: true });
    }
  });

  const onRegistration = useCallback(() => openPath(registrationPath), [openPath, registrationPath]);
  const title =
    level.kind === 'certificate'
      ? (certificate?.title ?? 'Attestation Certificate')
      : level.kind === 'authenticator-data'
        ? 'Authenticator Data'
        : TITLES[level.kind];
  const back =
    level.depth === 1
      ? { onBack: () => close(base), title: 'Return to credential details' }
      : level.depth === 2
        ? { onBack: () => close(registrationPath), title: 'Return to registration details' }
        : undefined;

  return (
    <Dialog
      open={Boolean(row)}
      onClose={() => closeAll()}
      labelledBy={titleId}
      returnFocusTo={returnFocusTo}
      className="max-sm:w-[calc(100vw-1rem)]"
    >
      <OverlayHeader
        titleId={titleId}
        title={title}
        closeLabel="Close credential details"
        onClose={() => closeAll()}
        back={back}
        className="max-sm:pl-4"
      />
      <OverlayBody className="max-sm:px-4">
        {shown ? (
          <div ref={levelRef} data-credential-detail={shown.key}>
            <div data-level="detail" tabIndex={-1} hidden={level.kind !== 'detail'} className="outline-none">
              <h3 className="text-heading font-semibold break-words text-ink">{shown.name}</h3>
              {ready?.hydrationFailed ? (
                <p role="note" className="mt-4 rounded-sm border border-warning-line bg-warning-tint px-4 py-3 text-body text-warning" data-hydration="failed">
                  {HYDRATE_TEXT.failed}
                </p>
              ) : null}
              <div className="mt-6">
                {ready ? (
                  <DetailSections detail={ready.detail} row={shown} idBase={idBase} onRegistration={onRegistration} />
                ) : (
                  <p role="status" className="flex items-center gap-2 text-body-lg text-ink-muted">
                    <Spinner />
                    Reading this credential&apos;s registration…
                  </p>
                )}
              </div>
            </div>
            {ready && level.depth >= 1 ? (
              <div data-level="registration" tabIndex={-1} hidden={level.kind !== 'registration'} className="outline-none">
                <RegistrationLevel
                  registration={ready.detail.registration}
                  idBase={`${idBase}-registration`}
                  onCertificate={(number) => openPath([...registrationPath, 'certificate', String(number)])}
                  onAuthenticatorData={() => openPath([...registrationPath, 'authenticator-data'])}
                />
              </div>
            ) : null}
            {certificate && level.kind === 'certificate' ? (
              <div data-level={levelName(level)} tabIndex={-1} className="outline-none">
                <CertificateLevel view={certificate} idBase={`${idBase}-certificate`} />
              </div>
            ) : null}
            {authenticatorData && level.kind === 'authenticator-data' ? (
              <div data-level="authenticator-data" tabIndex={-1} className="outline-none">
                <AuthenticatorDataLevel text={authenticatorData.text} />
              </div>
            ) : null}
          </div>
        ) : null}
      </OverlayBody>
    </Dialog>
  );
}
