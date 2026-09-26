import { codecRawJson } from '@legacy/decoder/codec/request.js';

import { CodeBlock } from '@/components/ui/CodeBlock';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';

import type { CodecAnswer, CodecMode } from './model';

const TITLES: Record<CodecMode, { title: string; close: string }> = {
  decode: { title: 'Raw Codec Output', close: 'Close raw codec output' },
  encode: { title: 'Raw Encoder Output', close: 'Close raw encoder output' },
};

export function rawDialogId(mode: CodecMode) {
  return `codec-raw-${mode}`;
}

// The whole answer as the server sent it, indented JSON, whole, with copy.
export function RawDialog({
  mode,
  answer,
  open,
  onClose,
  returnFocusTo,
}: {
  mode: CodecMode;
  answer: CodecAnswer | null;
  open: boolean;
  onClose: () => void;
  returnFocusTo: () => HTMLElement | null;
}) {
  const { title, close } = TITLES[mode];
  const titleId = `${rawDialogId(mode)}-title`;
  return (
    <Dialog id={rawDialogId(mode)} open={open && answer !== null} onClose={onClose} labelledBy={titleId} returnFocusTo={returnFocusTo}>
      <OverlayHeader titleId={titleId} title={title} closeLabel={close} onClose={onClose} />
      <OverlayBody>{answer ? <CodeBlock value={codecRawJson(answer)} label={title} collapsible={false} /> : null}</OverlayBody>
    </Dialog>
  );
}
