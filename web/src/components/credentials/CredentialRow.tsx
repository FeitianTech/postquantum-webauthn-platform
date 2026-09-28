import { type MouseEvent, useState } from 'react';

import { useOpenMdsEntry } from '@/components/mds/entryLink';
import { Badge, StatusChip } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { MonoValue } from '@/components/ui/MonoValue';
import { cx } from '@/lib/cx';

import { type CredentialRowView, LIST_TEXT } from './model';
import type { RowFlash } from './useSavedCredentials';

const CHECK_TONES = { true: 'success', false: 'danger', null: 'neutral' } as const;
const CHECK_WORDS = { true: 'passed', false: 'failed', null: 'not known' } as const;

function checkKey(value: boolean | null) {
  return String(value) as keyof typeof CHECK_TONES;
}

type CredentialRowProps = {
  row: CredentialRowView;
  busy: boolean;
  flash: RowFlash['variant'] | null;
  onOpen: () => void;
  onDelete: (button: HTMLButtonElement) => void;
};

// A saved credential: its name (which opens its details, as a click anywhere in
// the row but its controls does), its four checks, its tags, its credential id
// and AAGUID in Geist Mono with copy, "FIDO MDS" when the AAGUID has an entry to
// open, and Delete. Separated from the next by a hairline, never a card in the
// list's card. After a ceremony the row it used is tinted green, or red.
export function CredentialRow({ row, busy, flash, onOpen, onDelete }: CredentialRowProps) {
  const openMdsEntry = useOpenMdsEntry();
  const [mdsMessage, setMdsMessage] = useState<string | null>(null);

  const openFromRow = (event: MouseEvent<HTMLLIElement>) => {
    if ((event.target as HTMLElement).closest('button, a, [data-row-values]')) return;
    onOpen();
  };

  return (
    <li
      data-credential-key={row.key}
      data-credential-id={row.credentialIdHex}
      data-flash={flash ?? undefined}
      onClick={openFromRow}
      className={cx(
        '@container cursor-pointer border-t border-line px-5 py-4 transition-colors duration-(--duration-base) first:border-t-0 motion-reduce:transition-none',
        'hover-or-demo:bg-accent-tint/40 data-[flash=failure]:bg-danger-tint data-[flash=success]:bg-success-tint',
      )}
    >
      <div className="flex flex-wrap items-start gap-x-4 gap-y-3">
        <div className="min-w-0 flex-1 basis-64">
          <button
            type="button"
            data-role="name"
            onClick={onOpen}
            className="max-w-full truncate rounded-xs text-left text-title-sm font-semibold text-ink hover-or-demo:underline"
          >
            {row.name}
          </button>
          <ul aria-label="Checks" className="mt-2 flex flex-wrap gap-1.5">
            {row.checks.map((check) => (
              <li key={check.label}>
                <StatusChip tone={CHECK_TONES[checkKey(check.value)]} data-check={check.label}>
                  {check.label}
                  <span className="sr-only"> {CHECK_WORDS[checkKey(check.value)]}</span>
                </StatusChip>
              </li>
            ))}
          </ul>
          {row.tags.length ? (
            <ul aria-label="Features" className="mt-2 flex flex-wrap gap-1.5">
              {row.tags.map((tag, index) => (
                <li key={tag}>
                  <Badge tone={index === 0 ? 'accent' : 'neutral'}>{tag}</Badge>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {row.mdsAaguid ? (
            <Button variant="secondary" size="sm" title={LIST_TEXT.openMetadata} onClick={() => setMdsMessage(openMdsEntry(row.mdsAaguid))}>
              FIDO MDS
            </Button>
          ) : null}
          <Button variant="danger" size="sm" data-role="delete" disabled={busy} onClick={(event) => onDelete(event.currentTarget)}>
            Delete
          </Button>
        </div>
      </div>
      {/* The identifiers under the row, across its width, so a whole one fits:
          one per line, side by side only where the row has room for both. */}
      <dl data-row-values="" className="mt-3 grid min-w-0 cursor-auto grid-cols-1 gap-x-6 gap-y-2 @3xl:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-caption text-ink-muted">Credential ID</dt>
          <dd className="mt-0.5 min-w-0">
            <MonoValue value={row.credentialId} label="credential ID" />
          </dd>
        </div>
        {row.aaguid ? (
          <div className="min-w-0">
            <dt className="text-caption text-ink-muted">AAGUID</dt>
            <dd className="mt-0.5 min-w-0">
              <MonoValue value={row.aaguid} label="AAGUID" />
            </dd>
          </div>
        ) : row.aaguidUnreadable ? (
          // Kept as stored, and said to be unreadable, rather than left out.
          <div className="min-w-0" data-unreadable="aaguid">
            <dt className="flex items-center gap-2 text-caption text-ink-muted">
              AAGUID
              <Badge tone="warning">Unreadable</Badge>
            </dt>
            <dd className="mt-0.5 min-w-0">
              <MonoValue value={row.aaguidUnreadable} label="stored AAGUID" />
            </dd>
          </div>
        ) : null}
      </dl>
      {mdsMessage ? (
        <p role="status" className="mt-2 text-caption text-warning">
          {mdsMessage}
        </p>
      ) : null}
    </li>
  );
}
