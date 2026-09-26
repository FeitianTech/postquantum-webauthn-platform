// The Codec's logic comes from the modules both UIs share (docs/UI_MIGRATION.md):
// frontend/static/scripts/decoder/codec/{request,result,values}.js. These are
// the types web/ reads them through, and the one piece of the current template
// the logic needs: the encoder's formats.
import { buildCodecRequest } from '@legacy/decoder/codec/request.js';
import { describeCodecResult } from '@legacy/decoder/codec/result.js';
import { classifyCodecValue } from '@legacy/decoder/codec/values.js';

export type CodecMode = 'decode' | 'encode';

/** What POST /api/codec answered, as sent. */
export type CodecAnswer = { [key: string]: unknown };

/** Why the last run showed no answer: the sentence, and where the input stops being well-formed when the server says. */
export type CodecFailure = { text: string; offset: number | null; path: string | null };

export type FindingView = {
  source: string | null;
  offset: string | null;
  path: string;
  message: string;
  category: string | null;
  line: string;
  malformed: boolean;
};

export type EncodedFormatView = { key: string; label: string; value: string };
export type EncodedView = { label: string; formats: EncodedFormatView[]; byteLength: number | null };
export type SectionView = { key: string; label: string; kind: 'edn' | 'expandedJson' | 'value'; value: unknown };

export type ResultView = {
  empty: null;
  success: boolean;
  pill: string;
  type: string;
  lenientNote: string | null;
  findingsHeading: string | null;
  findings: FindingView[];
  malformed: string | null;
  encoded: EncodedView | null;
  sections: SectionView[];
  noSections: string | null;
};

export type CodecView = { empty: string } | ResultView;

export type BadgeView = [kind: string, text: string];
export type MapEntryView = { key: string; label: string; value: unknown };
type TextValueView<K extends string> = { kind: K; text: string };
export type ValueView =
  | TextValueView<'empty'>
  | TextValueView<'inline'>
  | TextValueView<'block'>
  | TextValueView<'primitive'>
  | { kind: 'list'; items: unknown[] }
  | { kind: 'map'; badges: BadgeView[]; entries: MapEntryView[] };

export const buildRequest = buildCodecRequest as (
  mode: CodecMode,
  input: string,
  options: { format?: string | null; lenient?: boolean },
) => Record<string, unknown>;
export const describeResult = describeCodecResult as (payload: unknown, mode: CodecMode) => CodecView;
export const classifyValue = classifyCodecValue as (value: unknown) => ValueView;

// The encoder's formats as the current UI's select lists them: the value sent,
// and the text shown.
export const ENCODER_FORMATS = [
  { value: 'CBOR (canonical)', text: 'CBOR (canonical)' },
  { value: 'EDN', text: 'EDN (exact bytes)' },
  { value: 'CBOR (CTAP/WebAuthn Data)', text: 'CBOR (CTAP/WebAuthn Data)' },
  { value: 'JSON (binary)', text: 'JSON (binary)' },
  { value: 'DER', text: 'DER' },
  { value: 'PEM', text: 'PEM' },
  { value: 'COSE', text: 'COSE' },
] as const;
