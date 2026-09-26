import { Badge, type Tone } from '@/components/ui/Badge';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { cx } from '@/lib/cx';

import { type MapEntryView, classifyValue } from './model';

// The interpretation badges, by the kind values.js gives them.
const BADGE_TONES: Record<string, Tone> = {
  unknown: 'neutral',
  'not-verified': 'warning',
  deprecated: 'danger',
};

const MONO = 'font-mono text-label wrap-anywhere';

function holdsMore(value: unknown) {
  const kind = classifyValue(value).kind;
  return kind === 'map' || kind === 'list';
}

// A key the decoder wrote as data ("1", "-2", "1 (fmt)", `"1" (text)`) is shown
// as written, in mono; a field name shown as a label ("Credential ID") is not.
function EntryLabel({ entry }: { entry: MapEntryView }) {
  return (
    <dt className={cx('min-w-0 text-label text-ink-muted wrap-anywhere', entry.label === entry.key && 'font-mono')}>
      {entry.label}
    </dt>
  );
}

// One decoded value, shown by the rules the current panel follows (values.js):
// muted text for null and empty containers, a string on its line or as a block,
// a list, or a map of labelled entries with its badges before them. Data is in
// Geist Mono; labels are not. A map or list inside a map goes under its label,
// indented behind a hairline; a label and a plain value sit side by side only
// where the map has room (a container query), so nothing deep is squeezed or cut.
export function ValueView({ value, label }: { value: unknown; label: string }) {
  const view = classifyValue(value);

  if (view.kind === 'empty') return <span className={cx(MONO, 'text-ink-faint')}>{view.text}</span>;
  if (view.kind === 'inline' || view.kind === 'primitive') return <span className={cx(MONO, 'text-ink')}>{view.text}</span>;
  if (view.kind === 'block') return <CodeBlock value={view.text} label={label} />;

  if (view.kind === 'list') {
    return (
      <ol className="flex min-w-0 list-disc flex-col gap-2 pl-4 marker:text-ink-faint">
        {view.items.map((item, index) => (
          <li key={index} className="min-w-0">
            <ValueView value={item} label={label} />
          </li>
        ))}
      </ol>
    );
  }

  return (
    <div className="@container flex min-w-0 flex-col gap-2">
      {view.badges.length > 0 ? (
        <div className="flex flex-wrap gap-1.5" data-role="badges">
          {view.badges.map(([kind, text]) => (
            <Badge key={kind} tone={BADGE_TONES[kind] ?? 'neutral'} data-badge={kind}>
              {text}
            </Badge>
          ))}
        </div>
      ) : null}
      <dl className="flex min-w-0 flex-col gap-2">
        {view.entries.map((entry) =>
          holdsMore(entry.value) ? (
            <div key={entry.key} className="min-w-0" data-entry="nested">
              <EntryLabel entry={entry} />
              <dd className="mt-1.5 min-w-0 border-l border-line pl-3">
                <ValueView value={entry.value} label={entry.label} />
              </dd>
            </div>
          ) : (
            <div key={entry.key} className="grid min-w-0 grid-cols-1 gap-x-4 gap-y-0.5 @md:grid-cols-[minmax(0,11rem)_minmax(0,1fr)]">
              <EntryLabel entry={entry} />
              <dd className="min-w-0">
                <ValueView value={entry.value} label={entry.label} />
              </dd>
            </div>
          ),
        )}
      </dl>
    </div>
  );
}
