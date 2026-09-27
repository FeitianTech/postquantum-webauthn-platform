import { useId, useState } from 'react';

import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Spinner } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { CredentialRow } from './CredentialRow';
import { CLEAR_ALL_QUESTION, type CredentialRowView, LIST_TEXT, deleteQuestion } from './model';
import { useSavedCredentials } from './useSavedCredentials';

const NOTICE_TONES = {
  error: 'border-danger-line bg-danger-tint text-danger',
  warning: 'border-warning-line bg-warning-tint text-warning',
  info: 'border-line bg-surface text-ink',
} as const;

type Question = { kind: 'one'; row: CredentialRowView; from: HTMLButtonElement } | { kind: 'all'; from: HTMLButtonElement };

// Every saved credential, simple and advanced, as one card: the heading with how
// many there are and Clear All on one line, then a row per credential separated
// by hairlines, or the empty sentence. Deleting one, or all, asks first in a
// dialog. The Simple tab shows it beside its form; the Advanced tab's drawer
// shows the same list (Phase 29). `onOpen` opens a credential's details.
export function SavedCredentials({ onOpen }: { onOpen: (key: string) => void }) {
  const saved = useSavedCredentials();
  const headingId = useId();
  // The last question stays while its dialog closes, so its words do not change.
  const [question, setQuestion] = useState<Question | null>(null);
  const [asking, setAsking] = useState(false);
  const count = saved.rows.length;

  const ask = (next: Question) => {
    setQuestion(next);
    setAsking(true);
  };
  const answer = () => {
    setAsking(false);
    if (question?.kind === 'one') void saved.remove(question.row.credential);
    else void saved.clearAll();
  };

  return (
    <section aria-labelledby={headingId} className="min-w-0 rounded-lg border border-line bg-surface" data-saved-credentials="">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-5 pt-5 pb-4">
        <h3 id={headingId} className="text-title-sm font-semibold whitespace-nowrap text-ink">
          Saved Credentials
        </h3>
        {saved.loaded ? (
          <Badge tone="neutral" data-count="">
            {count}
          </Badge>
        ) : null}
        {saved.progress ? (
          <span role="status" className="flex items-center gap-1.5 text-label text-ink-muted" data-role="progress">
            <Spinner />
            {saved.progress}
          </span>
        ) : null}
        <Button
          variant="danger"
          size="sm"
          className="ml-auto"
          disabled={!count || saved.busy}
          onClick={(event) => ask({ kind: 'all', from: event.currentTarget })}
        >
          Clear All
        </Button>
      </div>
      {saved.notice ? (
        <p
          role={saved.notice.tone === 'error' ? 'alert' : 'status'}
          data-notice={saved.notice.tone}
          className={cx('mx-5 mb-4 rounded-sm border px-4 py-3 text-body', NOTICE_TONES[saved.notice.tone])}
        >
          {saved.notice.text}
        </p>
      ) : null}
      {count ? (
        <ul aria-labelledby={headingId} className="border-t border-line">
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
        <p className="border-t border-line px-5 py-8 text-body text-ink-muted" data-role="empty">
          {LIST_TEXT.empty}
        </p>
      )}
      <ConfirmDialog
        open={asking}
        title={question?.kind === 'one' ? 'Delete credential' : 'Clear All'}
        question={question?.kind === 'one' ? deleteQuestion(question.row.credential) : CLEAR_ALL_QUESTION}
        confirmLabel={question?.kind === 'one' ? 'Delete' : 'Clear All'}
        onConfirm={answer}
        onCancel={() => setAsking(false)}
        returnFocusTo={() => question?.from ?? null}
      />
    </section>
  );
}
