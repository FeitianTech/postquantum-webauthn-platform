import { codecProgressText } from '@legacy/decoder/codec/request.js';
import { type ReactNode, useCallback, useRef, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { Select, TextArea } from '@/components/ui/Field';
import { Spinner } from '@/components/ui/icons';
import { SegmentedControl, segmentIds } from '@/components/ui/SegmentedControl';
import { Switch } from '@/components/ui/Switch';
import { NAV_ID } from '@/components/shell/SectionPanel';
import { SECTIONS } from '@/lib/sections';

import { CodecOutput } from './CodecOutput';
import { FailureNotice } from './FailureNotice';
import { type CodecMode, ENCODER_FORMATS } from './model';
import { RawDialog } from './RawDialog';
import { SupportedInputs } from './SupportedInputs';
import { type CodecPanelState, useCodec } from './useCodec';

const MODE_ID = 'codec-mode';
const MODES = [
  { value: 'decode', label: 'Decode' },
  { value: 'encode', label: 'Encode' },
] as const;

// Grammar checkers and the browser's own helpers stay out of the input: it is data.
const DATA_INPUT = {
  spellCheck: false,
  autoCapitalize: 'off',
  autoComplete: 'off',
  'data-gramm': 'false',
  'data-gramm_editor': 'false',
  'data-enable-grammarly': 'false',
} as const;

// The input beside the output from 1280 px (the input stays in view while a
// long answer scrolls), one above the other below that.
function Workspace({ input, output }: { input: ReactNode; output: ReactNode }) {
  return (
    <div className="mt-8 grid grid-cols-1 gap-8 wide:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] wide:gap-10">
      <div className="min-w-0 wide:sticky wide:top-[calc(var(--header-height)+1.5rem)] wide:self-start" data-codec-column="input">
        {input}
      </div>
      <div className="min-w-0 self-start rounded-lg border border-line bg-surface p-4 sm:p-6" data-codec-column="output">
        {output}
      </div>
    </div>
  );
}

function ModePanel({ mode, active, codec }: { mode: CodecMode; active: boolean; codec: CodecPanelState }) {
  const [rawOpen, setRawOpen] = useState(false);
  const rawButtonRef = useRef<HTMLButtonElement>(null);
  const ids = segmentIds(MODE_ID, mode);
  const run = useCallback(() => {
    setRawOpen(false);
    void codec.run();
  }, [codec]);
  const clear = () => {
    setRawOpen(false);
    codec.clear();
  };

  const input = (
    <div className="flex flex-col gap-4">
      {mode === 'encode' ? (
        <Select label="Encoding format" value={codec.format} onChange={(event) => codec.setFormat(event.target.value)}>
          {ENCODER_FORMATS.map((format) => (
            <option key={format.value} value={format.value}>
              {format.text}
            </option>
          ))}
        </Select>
      ) : null}
      <TextArea
        label={mode === 'encode' ? 'Input to encode' : 'Input to decode'}
        mono
        rows={10}
        placeholder={mode === 'encode' ? 'Paste something here to encode...' : 'Paste something here to decode...'}
        value={codec.input}
        onChange={(event) => codec.setInput(event.target.value)}
        {...DATA_INPUT}
      />
      {mode === 'decode' ? (
        <Switch
          label="Best effort (lenient)"
          description="read CBOR that is not well-formed as far as it goes"
          checked={codec.lenient}
          onCheckedChange={codec.setLenient}
        />
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button busy={codec.running} onClick={run}>
          {mode === 'encode' ? 'Encode' : 'Decode'}
        </Button>
        <Button variant="secondary" onClick={clear}>
          Clear
        </Button>
      </div>
    </div>
  );

  const output = (
    <div className="flex min-w-0 flex-col gap-5" aria-busy={codec.running || undefined}>
      {codec.running ? (
        <p role="status" className="flex items-center gap-2 text-body text-ink-muted" data-role="progress">
          <Spinner />
          {codecProgressText(mode)}
        </p>
      ) : null}
      {codec.failure ? <FailureNotice failure={codec.failure} /> : null}
      {codec.answer ? (
        <CodecOutput ref={rawButtonRef} mode={mode} answer={codec.answer} rawOpen={rawOpen} onRaw={() => setRawOpen(!rawOpen)} />
      ) : !codec.running && !codec.failure ? (
        mode === 'decode' ? (
          <SupportedInputs />
        ) : (
          <p className="text-body text-ink-muted" data-role="empty">
            The encoded bytes appear here.
          </p>
        )
      ) : null}
    </div>
  );

  return (
    // Shown again, a panel comes in as a section does (the current panel fades in too).
    <div
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={!active}
      data-codec-mode={mode}
      className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none"
    >
      <Workspace input={input} output={output} />
      <RawDialog
        mode={mode}
        answer={codec.answer}
        open={rawOpen}
        onClose={() => setRawOpen(false)}
        returnFocusTo={() => rawButtonRef.current}
      />
    </div>
  );
}

// The Codec section: decode what a WebAuthn or CTAP payload holds, or encode a
// value back to bytes. Each mode keeps its own input and answer.
export function CodecSection({ active }: { active: boolean }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'codec')!;
  const ids = segmentIds(NAV_ID, 'codec');
  const [mode, setMode] = useState<CodecMode>('decode');
  const decode = useCodec('decode');
  const encode = useCodec('encode');

  return (
    <section
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={!active}
      className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none"
    >
      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-5">
        <div className="min-w-0">
          <h2 className="text-display font-semibold text-ink">{section.label}</h2>
          <p className="mt-2 max-w-prose text-body-lg text-ink-muted">{section.description}</p>
        </div>
        <SegmentedControl label="Codec mode" options={MODES} value={mode} onChange={setMode} idBase={MODE_ID} size="sm" />
      </div>
      <ModePanel mode="decode" active={mode === 'decode'} codec={decode} />
      <ModePanel mode="encode" active={mode === 'encode'} codec={encode} />
    </section>
  );
}
