import { responseParts } from '@/logic/advanced/response-parts.js';
import { useId } from 'react';

import { DecodeInCodec } from '@/components/codec/DecodeInCodec';

// Under the result of the last ceremony: the parts of the browser's response,
// each a button that opens it in the Codec, decoded. Outside the result panel,
// which says what the server made of them. Nothing until the browser answers.
export function ResponseParts({ response }: { response: Record<string, unknown> | null }) {
  const labelId = useId();
  const parts = responseParts(response);
  if (!parts.length) return null;
  return (
    <div role="group" aria-labelledby={labelId} className="mt-3 flex flex-wrap items-center gap-2" data-response-parts="">
      <span id={labelId} className="mr-1 text-caption text-ink-muted">
        Decode in Codec
      </span>
      {parts.map(({ part, label, payload }) => (
        <DecodeInCodec key={part} part={part} label={label} payload={payload} />
      ))}
    </div>
  );
}
