import { NO_CAPABILITIES, groupCapabilities, omittedNote } from '@legacy/shared/browser/report.js';

import { cx } from '@/lib/cx';

import { FactRow, FactState } from './FactList';
import type { Capability, ClientCapabilities as Answer } from './types';

type Group = { kind: string; title: string; entries: Capability[] };

// What getClientCapabilities() returned, grouped as today: the keys WebAuthn
// Level 3 defines (with the key in code, in the spec's order), extensions, and
// keys this page does not recognise, as the browser wrote them.
export function ClientCapabilities({ answer }: { answer: Answer }) {
  if (answer.state !== 'yes') {
    return (
      <p data-role="capabilities-status" className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2">
        <FactState fact={answer} />
        <span className="text-label text-ink-muted">{answer.note}</span>
      </p>
    );
  }

  const groups: Group[] = groupCapabilities(answer.capabilities);
  const omitted = omittedNote(answer.omitted);
  return (
    <div className="flex flex-col gap-5">
      {answer.capabilities.length === 0 ? <p className="text-label text-ink-muted">{NO_CAPABILITIES}</p> : null}
      {groups.map((group) => (
        <div key={group.kind} data-group={group.kind}>
          <h4 className="text-label font-semibold text-ink">{group.title}</h4>
          <ul
            className={cx(
              'mt-1',
              group.kind === 'defined' ? 'divide-y divide-line' : 'grid gap-x-6 sm:grid-cols-2 lg:grid-cols-3',
            )}
          >
            {group.entries.map((entry) => (
              <FactRow
                key={entry.key}
                id={entry.key}
                label={entry.label}
                api={entry.kind === 'defined' ? entry.key : null}
                fact={entry}
              />
            ))}
          </ul>
        </div>
      ))}
      {omitted ? <p className="text-label text-ink-muted">{omitted}</p> : null}
    </div>
  );
}
