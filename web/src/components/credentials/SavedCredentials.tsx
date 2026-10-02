import { type ReactNode, type RefObject, useEffect, useId, useRef, useState } from 'react';

import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Spinner } from '@/components/ui/icons';
import { cx } from '@/lib/cx';
import { CLEAR_ALL_CONFIRMATION, deleteConfirmation } from '@/logic/credentials/delete-flow.js';
import { type CredentialRowView, SAVED_LIST_TEXT } from '@/logic/credentials/saved-list.js';

import { CredentialRow } from './CredentialRow';
import { type SavedCredentialsState, useSavedCredentials } from './useSavedCredentials';

const NOTICE_TONES = {
  error: 'border-danger-line bg-danger-tint text-danger',
  warning: 'border-warning-line bg-warning-tint text-warning',
  info: 'border-line bg-surface text-ink',
} as const;

type Question = { kind: 'one'; row: CredentialRowView; from: HTMLButtonElement } | { kind: 'all'; from: HTMLButtonElement };

type CredentialDeletion = {
  saved: SavedCredentialsState;
  listRef: RefObject<HTMLUListElement | null>;
  /** Asks before deleting one credential, or all of them, from the button pressed. */
  ask: (question: Question) => void;
  /** The question's dialog, to render beside the list. */
  dialog: ReactNode;
};

/**
 * Deleting saved credentials, wherever the list is shown: the question asked
 * first in a dialog, then where the focus goes once the deletion has ended (the
 * button that asked may be gone with its row): that row's Delete if the row is
 * still there (the server refused), else the next row's name, else the previous
 * one's, else `fallback` (the list's heading).
 */
export function useCredentialDeletion(fallback: () => HTMLElement | null): CredentialDeletion {
  const saved = useSavedCredentials();
  // The last question stays while its dialog closes, so its words do not change.
  const [question, setQuestion] = useState<Question | null>(null);
  const [asking, setAsking] = useState(false);
  const listRef = useRef<HTMLUListElement>(null);
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;
  // The row a deletion left (by key and place), or none after Clear All.
  const [ended, setEnded] = useState<{ key: string | null; index: number } | null>(null);

  const ask = (next: Question) => {
    setQuestion(next);
    setAsking(true);
  };
  const answer = async () => {
    setAsking(false);
    if (question?.kind === 'one') {
      const index = saved.rows.findIndex((row) => row.key === question.row.key);
      await saved.remove(question.row.credential);
      setEnded({ key: question.row.key, index });
    } else {
      await saved.clearAll();
      setEnded({ key: null, index: 0 });
    }
  };

  useEffect(() => {
    if (!ended || saved.busy) return;
    setEnded(null);
    const rows = Array.from(listRef.current?.querySelectorAll<HTMLElement>('li[data-credential-key]') ?? []);
    const kept = ended.key ? rows.find((row) => row.dataset.credentialKey === ended.key) : undefined;
    const target = kept
      ? kept.querySelector<HTMLElement>('[data-role="delete"]')
      : (rows[ended.index] ?? rows[ended.index - 1])?.querySelector<HTMLElement>('[data-role="name"]');
    (target ?? fallbackRef.current())?.focus();
  }, [ended, saved.busy, saved.rows]);

  const dialog = (
    <ConfirmDialog
      open={asking}
      title={question?.kind === 'one' ? 'Delete credential' : 'Clear All'}
      question={question?.kind === 'one' ? deleteConfirmation(question.row.credential) : CLEAR_ALL_CONFIRMATION}
      confirmLabel={question?.kind === 'one' ? 'Delete' : 'Clear All'}
      onConfirm={() => void answer()}
      onCancel={() => setAsking(false)}
      returnFocusTo={() => question?.from ?? null}
    />
  );
  return { saved, listRef, ask, dialog };
}

/** How many there are, once the list has been read. */
export function CredentialCount({ saved }: { saved: SavedCredentialsState }) {
  return saved.loaded ? (
    <Badge tone="neutral" data-count="">
      {saved.rows.length}
    </Badge>
  ) : null;
}

/** What the list is doing (deleting, clearing), beside its heading. */
export function CredentialProgress({ saved }: { saved: SavedCredentialsState }) {
  return saved.progress ? (
    <span role="status" className="flex items-center gap-1.5 text-label text-ink-muted" data-role="progress">
      <Spinner />
      {saved.progress}
    </span>
  ) : null;
}

export function ClearAllButton({ deletion, className }: { deletion: CredentialDeletion; className?: string }) {
  const { saved, ask } = deletion;
  return (
    <Button
      variant="danger"
      size="sm"
      className={className}
      disabled={!saved.rows.length || saved.busy}
      onClick={(event) => ask({ kind: 'all', from: event.currentTarget })}
    >
      Clear All
    </Button>
  );
}

/**
 * The list itself: the notice of the last deletion, then a row per credential
 * separated by hairlines, or the empty sentence. `onOpen` opens a credential's
 * details.
 */
export function SavedCredentialList({
  deletion,
  labelledBy,
  onOpen,
  topRule = true,
}: {
  deletion: CredentialDeletion;
  labelledBy: string;
  onOpen: (key: string) => void;
  /** A hairline above the rows, when nothing above draws one. */
  topRule?: boolean;
}) {
  const { saved, listRef, ask } = deletion;
  return (
    <>
      {saved.notice ? (
        <p
          role={saved.notice.tone === 'error' ? 'alert' : 'status'}
          data-notice={saved.notice.tone}
          className={cx('mx-5 mb-4 rounded-sm border px-4 py-3 text-body', NOTICE_TONES[saved.notice.tone])}
        >
          {saved.notice.text}
        </p>
      ) : null}
      {saved.rows.length ? (
        <ul ref={listRef} aria-labelledby={labelledBy} className={cx(topRule && 'border-t border-line')}>
          {saved.rows.map((row) => (
            <CredentialRow
              key={row.key}
              row={row}
              busy={saved.busy}
              flash={saved.flash?.key && saved.flash.key === row.credentialIdHex ? saved.flash.variant : null}
              onOpen={() => onOpen(row.key)}
              onDelete={(from) => ask({ kind: 'one', row, from })}
            />
          ))}
        </ul>
      ) : (
        <p className={cx('px-5 py-8 text-body text-ink-muted', topRule && 'border-t border-line')} data-role="empty">
          {SAVED_LIST_TEXT.empty}
        </p>
      )}
    </>
  );
}

// Every saved credential, simple and advanced, as one card: the heading with how
// many there are and Clear All on one line, then the list. Deleting one, or all,
// asks first in a dialog. The Simple tab shows it beside its form; the Advanced
// tab's drawer shows the same list. `onOpen` opens a credential's details.
export function SavedCredentials({ onOpen }: { onOpen: (key: string) => void }) {
  const headingId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const deletion = useCredentialDeletion(() => headingRef.current);

  return (
    <section aria-labelledby={headingId} className="min-w-0 rounded-lg border border-line bg-surface" data-saved-credentials="">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-5 pt-5 pb-4">
        <h3 id={headingId} ref={headingRef} tabIndex={-1} className="text-title-sm font-semibold whitespace-nowrap text-ink outline-none">
          Saved Credentials
        </h3>
        <CredentialCount saved={deletion.saved} />
        <CredentialProgress saved={deletion.saved} />
        <ClearAllButton deletion={deletion} className="ml-auto" />
      </div>
      <SavedCredentialList deletion={deletion} labelledBy={headingId} onOpen={onOpen} />
      {deletion.dialog}
    </section>
  );
}
