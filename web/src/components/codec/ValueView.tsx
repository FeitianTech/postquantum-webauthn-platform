import { Badge, type Tone } from '@/components/ui/Badge';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { cx } from '@/lib/cx';

import { classifyValue } from './model';

// The interpretation badges, by the kind values.js gives them.
const BADGE_TONES: Record<string, Tone> = {
  unknown: 'neutral',
  'not-verified': 'warning',
  deprecated: 'danger',
};

const MONO = 'font-mono text-label wrap-anywhere';

// One decoded value, shown by the rules the current panel follows (values.js):
// muted text for null and empty containers, a string on its line or as a block,
// a list, or a map of labelled entries with its badges before them. Data is in
// Geist Mono; labels are not.
export function ValueView({ value, label, nested = false }: { value: unknown; label: string; nested?: boolean }) {
  const view = classifyValue(value);

  if (view.kind === 'empty') return <span className={cx(MONO, 'text-ink-faint')}>{view.text}</span>;
  if (view.kind === 'inline' || view.kind === 'primitive') return <span className={cx(MONO, 'text-ink')}>{view.text}</span>;
  if (view.kind === 'block') return <CodeBlock value={view.text} label={label} />;

  if (view.kind === 'list') {
    return (
      <ol className="flex list-disc flex-col gap-1.5 pl-5 marker:text-ink-faint">
        {view.items.map((item, index) => (
          <li key={index} className="min-w-0">
            <ValueView value={item} label={label} nested />
          </li>
        ))}
      </ol>
    );
  }

  return (
    <div className={cx('flex min-w-0 flex-col gap-2', nested && 'border-l border-line pl-3')}>
      {view.badges.length > 0 ? (
        <div className="flex flex-wrap gap-1.5" data-role="badges">
          {view.badges.map(([kind, text]) => (
            <Badge key={kind} tone={BADGE_TONES[kind] ?? 'neutral'} data-badge={kind}>
              {text}
            </Badge>
          ))}
        </div>
      ) : null}
      <dl className="grid min-w-0 grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[minmax(6rem,13rem)_minmax(0,1fr)] sm:gap-y-2">
        {view.entries.map((entry) => (
          <div key={entry.key} className="contents">
            <dt className="pt-px text-label text-ink-muted wrap-anywhere">{entry.label}</dt>
            <dd className="mb-2 min-w-0 sm:mb-0">
              <ValueView value={entry.value} label={entry.label} nested />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
