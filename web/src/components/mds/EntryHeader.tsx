import { RAW_DATA_BUTTON_TITLE, RAW_DATA_UNAVAILABLE_TITLE } from '@legacy/advanced/mds/raw-data.js';
import { type Ref, forwardRef, Fragment } from 'react';

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

// The subtitle's parts: "AAGUID: …", "ID: …" (both copyable) and the protocol.
function Subtitle({ entry }: { entry: MdsEntry }) {
  const parts = entrySubtitle(entry);
  if (!parts.length) return null;
  return (
    <p data-entry-subtitle="" className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-body text-ink-muted">
      {parts.map((part, index) => (
        <Fragment key={`${part.label}-${part.value}`}>
          {index ? (
            <span aria-hidden="true" className="text-ink-faint">
              •
            </span>
          ) : null}
          {part.label ? (
            <span className="inline-flex max-w-full min-w-0 items-center gap-1.5">
              <span className="shrink-0">{part.label}:</span>
              <MonoValue value={part.value} label={part.label === 'ID' ? identifierName(entry) : part.label} />
            </span>
          ) : (
            <span>{part.value}</span>
          )}
        </Fragment>
      ))}
    </p>
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
      <div className="mt-6 flex flex-wrap items-start justify-between gap-x-6 gap-y-4">
        <div className="min-w-0 flex-1">
          <h3 ref={headingRef} tabIndex={-1} className="text-heading font-semibold break-words text-ink outline-none">
            {entryTitle(entry)}
          </h3>
          <Subtitle entry={entry} />
        </div>
        <Button
          ref={rawButtonRef}
          variant="secondary"
          disabled={!hasRaw}
          title={hasRaw ? RAW_DATA_BUTTON_TITLE : RAW_DATA_UNAVAILABLE_TITLE}
          aria-haspopup="dialog"
          onClick={onRaw}
        >
          Raw
        </Button>
      </div>
    </div>
  );
});
