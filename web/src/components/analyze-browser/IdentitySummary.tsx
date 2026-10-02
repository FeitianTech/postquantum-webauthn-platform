import { type Identity, SOURCE_TEXT } from '@/logic/browser/identity.js';
import { IDENTITY_FIELDS, NOT_REPORTED } from '@/logic/browser/report.js';

import { KeyValueGrid } from '@/components/ui/KeyValueGrid';

const LABELS: Record<string, string> = { name: 'Browser', version: 'Version', engine: 'Engine', system: 'System' };
const SOURCES: Record<string, string> = SOURCE_TEXT;

// Browser, version, engine and system, each with where the answer came from, or
// "Not reported" and why.
export function IdentitySummary({ identity }: { identity: Identity }) {
  return (
    <div className="flex flex-col gap-3">
      <KeyValueGrid
        columns={4}
        items={IDENTITY_FIELDS.map((field) => ({
          key: field,
          label: LABELS[field],
          value: identity[field] ?? NOT_REPORTED,
          hint: SOURCES[identity.sources[field]],
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
