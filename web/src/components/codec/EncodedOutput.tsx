import { CodeBlock } from '@/components/ui/CodeBlock';

import type { EncodedView } from './model';

// The encoded bytes: each view (Hex, Base64, Base64url, Colon Hex, then any
// other the answer gives) in a block with copy, and the byte length.
export function EncodedOutput({ encoded }: { encoded: EncodedView }) {
  return (
    <section aria-labelledby="codec-encoded-heading" className="flex flex-col gap-4" data-codec-section="encoded">
      <h4 id="codec-encoded-heading" className="text-title-sm font-semibold text-ink">
        {encoded.label}
      </h4>
      {encoded.formats.map((format) => (
        <div key={format.key} className="flex min-w-0 flex-col gap-1.5" data-encoded={format.key}>
          <span className="text-caption font-medium text-ink-muted">{format.label}</span>
          <CodeBlock value={format.value} label={format.label} />
        </div>
      ))}
      {encoded.byteLength !== null ? (
        <p className="text-label text-ink-muted" data-role="byte-length">
          Byte length: <span className="font-mono text-ink">{encoded.byteLength}</span>
        </p>
      ) : null}
    </section>
  );
}
