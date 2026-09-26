import { codecEdnText, codecExpandedJson } from '@legacy/decoder/codec/values.js';
import { forwardRef } from 'react';

import { StatusChip } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';

import { EncodedOutput } from './EncodedOutput';
import { Findings } from './Findings';
import { type CodecAnswer, type CodecMode, type SectionView, describeResult } from './model';
import { rawDialogId } from './RawDialog';
import { ValueView } from './ValueView';

function DecodedSection({ section }: { section: SectionView }) {
  const headingId = `codec-section-${section.key.replace(/[^A-Za-z0-9_-]/g, '_')}`;
  return (
    <section aria-labelledby={headingId} className="flex min-w-0 flex-col gap-3 border-t border-line pt-5" data-codec-section={section.key}>
      <h4 id={headingId} className="text-title-sm font-semibold text-ink wrap-anywhere">
        {section.label}
      </h4>
      {section.kind === 'edn' ? (
        <CodeBlock value={codecEdnText(section.value)} label={section.label} />
      ) : section.kind === 'expandedJson' ? (
        <CodeBlock value={codecExpandedJson(section.value)} label={section.label} />
      ) : (
        <ValueView value={section.value} label={section.label} />
      )}
    </section>
  );
}

type CodecOutputProps = { mode: CodecMode; answer: CodecAnswer; onRaw: () => void; rawOpen: boolean };

// What the server made of the input: the header (Success or Error, the type and
// Raw), the lenient note, the findings, then the sections in the current panel's
// order (result.js), or the encoded bytes.
export const CodecOutput = forwardRef<HTMLButtonElement, CodecOutputProps>(function CodecOutput(
  { mode, answer, onRaw, rawOpen },
  rawButtonRef,
) {
  const view = describeResult(answer, mode);
  const headingId = `codec-output-heading-${mode}`;

  return (
    <section aria-labelledby={headingId} className="flex min-w-0 flex-col gap-5" data-codec-output={mode}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h3 id={headingId} className="text-title font-semibold text-ink">
          Codec Output
        </h3>
        {view.empty === null ? (
          <StatusChip tone={view.success ? 'success' : 'danger'} data-role="outcome">
            {view.pill}
          </StatusChip>
        ) : null}
        <Button
          ref={rawButtonRef}
          variant="secondary"
          size="sm"
          className="ml-auto"
          aria-haspopup="dialog"
          aria-controls={rawDialogId(mode)}
          aria-expanded={rawOpen}
          onClick={onRaw}
        >
          Raw
        </Button>
        {view.empty === null ? (
          <p className="w-full text-body-lg font-medium text-ink wrap-anywhere" data-role="type">
            {view.type}
          </p>
        ) : null}
      </div>

      {view.empty !== null ? (
        <p className="text-body text-ink-muted">{view.empty}</p>
      ) : (
        <>
          {view.lenientNote ? (
            <p className="rounded-sm border border-warning-line bg-warning-tint px-3.5 py-2.5 text-label text-warning" data-role="lenient-note">
              {view.lenientNote}
            </p>
          ) : null}
          {view.findingsHeading ? (
            <Findings heading={view.findingsHeading} findings={view.findings} />
          ) : view.malformed ? (
            <p className="rounded-sm border border-warning-line bg-warning-tint px-3.5 py-2.5 text-label text-warning wrap-anywhere" data-role="malformed">
              {view.malformed}
            </p>
          ) : null}
          {view.encoded ? (
            <EncodedOutput encoded={view.encoded} />
          ) : view.noSections ? (
            <p className="text-body text-ink-muted">{view.noSections}</p>
          ) : (
            view.sections.map((section) => <DecodedSection key={section.key} section={section} />)
          )}
        </>
      )}
    </section>
  );
});
