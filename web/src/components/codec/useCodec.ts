import {
  codecFailureText,
  codecSuccessText,
  requestCodec,
  validateCodecInput,
} from '@legacy/decoder/codec/request.js';
import { FailedResponseError } from '@legacy/shared/api/failed-response.js';
import { useCallback, useRef, useState } from 'react';

import { useToast } from '@/components/ui/Toast';

import { type CodecAnswer, type CodecFailure, type CodecMode, ENCODER_FORMATS, buildRequest } from './model';

// One panel of the Codec (Decode or Encode): its input and options, and what the
// last run gave. The steps are the current panel's (process.js), in its order:
// a check that fails leaves the last answer where it was; a run clears the last
// answer before asking; a failure leaves none. Unlike the current panel, the
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
      const payload = (await requestCodec(buildRequest(mode, input, { format, lenient }))) as CodecAnswer;
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
