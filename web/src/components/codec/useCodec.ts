import {
  type CodecAnswer,
  type CodecMode,
  ENCODER_FORMATS,
  buildCodecRequest,
  codecFailureText,
  codecSuccessText,
  requestCodec,
  validateCodecInput,
} from '@/logic/codec/request.js';
import { FailedResponseError } from '@/logic/shared/failed-response.js';
import { useCallback, useRef, useState } from 'react';

import { useToast } from '@/components/ui/Toast';

/** Why the last run showed no answer: the sentence, and where the input stops being well-formed when the server says. */
export type CodecFailure = { text: string; offset: number | null; path: string | null };

// One panel of the Codec (Decode or Encode): its input and options, and what the
// last run gave, in this order: a check that fails leaves the last answer where
// it was; a run clears the last answer before asking; a failure leaves none. The
// button is busy while a run is out (so a second click does nothing), and Clear
// drops the answer of a run still out.
export function useCodec(mode: CodecMode) {
  const toast = useToast();
  const [input, setInput] = useState('');
  const [lenient, setLenient] = useState(false);
  const [format, setFormat] = useState<string>(ENCODER_FORMATS[0].value);
  const [running, setRunning] = useState(false);
  const [answer, setAnswer] = useState<CodecAnswer | null>(null);
  const [failure, setFailure] = useState<CodecFailure | null>(null);
  // Counts runs and clears, so an answer that arrives after either is dropped.
  const generation = useRef(0);

  const run = useCallback(async () => {
    const invalid = validateCodecInput(mode, input, mode === 'encode' ? format : null);
    if (invalid) {
      setFailure({ text: invalid, offset: null, path: null });
      return;
    }

    const current = ++generation.current;
    setAnswer(null);
    setFailure(null);
    setRunning(true);
    try {
      const payload = await requestCodec(buildCodecRequest(mode, input, { format, lenient }));
      if (current !== generation.current) return;
      setAnswer(payload);
      toast({ tone: 'success', message: codecSuccessText(mode) });
    } catch (error) {
      if (current !== generation.current) return;
      const refusal = error instanceof FailedResponseError ? error.failure : null;
      setFailure({ text: codecFailureText(mode, error), offset: refusal?.offset ?? null, path: refusal?.path ?? null });
    } finally {
      if (current === generation.current) setRunning(false);
    }
  }, [mode, input, format, lenient, toast]);

  const clear = useCallback(() => {
    generation.current += 1;
    setInput('');
    setAnswer(null);
    setFailure(null);
    setRunning(false);
  }, []);

  return { input, setInput, lenient, setLenient, format, setFormat, running, answer, failure, run, clear };
}

export type CodecPanelState = ReturnType<typeof useCodec>;
