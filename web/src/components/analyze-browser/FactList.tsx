import { STATE_TEXT } from '@legacy/shared/browser/webauthn-facts.js';

import { StatusChip, type Tone } from '@/components/ui/Badge';
import { cx } from '@/lib/cx';

import type { Fact, FactState } from './types';

// Each state keeps its words (from the logic module) and gets a mark and a tone:
// yes ✓ green, no ✕ red, not available – neutral, could not be determined ! amber.
export const STATE_TONES: Record<FactState, Tone> = {
  yes: 'success',
  no: 'danger',
  unavailable: 'neutral',
  undetermined: 'warning',
};

const STATE_WORDS: Record<string, string> = STATE_TEXT;

export function FactState({ fact }: { fact: Fact }) {
  return (
    <StatusChip tone={STATE_TONES[fact.state]} data-state={fact.state}>
      {STATE_WORDS[fact.state]}
    </StatusChip>
  );
}

type FactRowProps = { id: string; label: string; api?: string | null; fact: Fact };

// One answer: what was asked, the API it came from, why when there is a reason,
// and the state.
export function FactRow({ id, label, api, fact }: FactRowProps) {
  return (
    <li data-fact={id} className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1.5 py-3">
      <div className="min-w-0 flex-1 basis-44">
        <span data-role="label" className="block text-body font-medium text-ink">
          {label}
        </span>
        {api ? (
          <code data-role="api" className="mt-0.5 block text-caption break-words text-ink-muted">
            {api}
          </code>
        ) : null}
        {fact.note ? (
          <span data-role="note" className="mt-1 block text-label text-ink-muted">
            {fact.note}
          </span>
        ) : null}
      </div>
      <FactState fact={fact} />
    </li>
  );
}

type Definition = { id: string; label: string; api: string };

export function FactList({ definitions, facts, className }: { definitions: Definition[]; facts: Record<string, Fact>; className?: string }) {
  return (
    <ul className={cx('divide-y divide-line', className)}>
      {definitions.map(({ id, label, api }) => (
        <FactRow key={id} id={id} label={label} api={api} fact={facts[id]} />
      ))}
    </ul>
  );
}
