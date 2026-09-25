import { SOURCE_TEXT } from '@legacy/shared/browser/identity.js';
import { IDENTITY_FIELDS, NOT_REPORTED } from '@legacy/shared/browser/report.js';

import { KeyValueGrid } from '@/components/ui/KeyValueGrid';

import type { Analysis } from './types';

const LABELS: Record<string, string> = { name: 'Browser', version: 'Version', engine: 'Engine', system: 'System' };
const SOURCES: Record<string, string> = SOURCE_TEXT;

// Browser, version, engine and system, each with where the answer came from, or
// "Not reported" and why.
export function IdentitySummary({ identity }: { identity: Analysis['identity'] }) {
  const values: Record<string, unknown> = identity;
  const sources: Record<string, string> = identity.sources;
  return (
    <div className="flex flex-col gap-3">
      <KeyValueGrid
        columns={4}
        items={IDENTITY_FIELDS.map((field: string) => ({
          key: field,
          label: LABELS[field],
          value: (values[field] as string | null) ?? NOT_REPORTED,
          hint: SOURCES[sources[field]],
        }))}
      />
      {identity.onAppleWebKit ? (
        <p data-role="apple-webkit-note" className="rounded-md border border-accent-line bg-accent-tint px-4 py-3 text-label text-ink">
          On iOS and iPadOS every browser uses Apple&apos;s WebKit engine, so WebAuthn here is Safari&apos;s, whichever
          browser this is.
        </p>
      ) : null}
    </div>
  );
}
