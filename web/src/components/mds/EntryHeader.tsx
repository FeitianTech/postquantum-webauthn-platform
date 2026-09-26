import { RAW_DATA_BUTTON_TITLE, RAW_DATA_UNAVAILABLE_TITLE } from '@legacy/advanced/mds/raw-data.js';
import { type Ref, forwardRef } from 'react';

import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { MonoValue } from '@/components/ui/MonoValue';

import { entrySubtitle, entryTitle } from './entryModel';
import { type MdsEntry, identifierName } from './model';

export function BackButton({ onBack, title }: { onBack: () => void; title: string }) {
  return (
    <Button variant="secondary" size="sm" title={title} onClick={onBack} icon={<span aria-hidden="true">←</span>}>
      Back
    </Button>
  );
}

// The subtitle's parts: "AAGUID: …" and "ID: …" (copyable; on a phone the value
// takes its own line rather than being cut) and the protocol.
function Subtitle({ entry }: { entry: MdsEntry }) {
  const parts = entrySubtitle(entry);
  if (!parts.length) return null;
  return (
    <div data-entry-subtitle="" className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-body text-ink-muted">
      {parts.map((part) =>
        part.label ? (
          <span key={part.label} className="flex max-w-full min-w-0 flex-wrap items-center gap-x-1.5">
            <span className="shrink-0">{part.label}:</span>
            <MonoValue value={part.value} label={part.label === 'ID' ? identifierName(entry) : part.label} />
          </span>
        ) : (
          <Badge key="protocol">{part.value}</Badge>
        ),
      )}
    </div>
  );
}

type EntryHeaderProps = {
  entry: MdsEntry;
  hasRaw: boolean;
  onBack: () => void;
  onRaw: () => void;
  rawButtonRef: Ref<HTMLButtonElement>;
};

// Back, the entry's name (else "Authenticator"), its subtitle and Raw.
export const EntryHeader = forwardRef<HTMLHeadingElement, EntryHeaderProps>(function EntryHeader(
  { entry, hasRaw, onBack, onRaw, rawButtonRef },
  headingRef,
) {
  return (
    <div data-entry-header="">
      <BackButton onBack={onBack} title="Return to authenticator list" />
      <div className="mt-6 flex items-start justify-between gap-4">
        <h3 ref={headingRef} tabIndex={-1} className="min-w-0 text-heading font-semibold break-words text-ink outline-none">
          {entryTitle(entry)}
        </h3>
        <Button
          ref={rawButtonRef}
          className="shrink-0"
          variant="secondary"
          disabled={!hasRaw}
          title={hasRaw ? RAW_DATA_BUTTON_TITLE : RAW_DATA_UNAVAILABLE_TITLE}
          aria-haspopup="dialog"
          onClick={onRaw}
        >
          Raw
        </Button>
      </div>
      <Subtitle entry={entry} />
    </div>
  );
});
