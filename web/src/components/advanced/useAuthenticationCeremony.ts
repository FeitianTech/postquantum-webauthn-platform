import { useCallback, useRef, useState } from 'react';

import type { CeremonyResultInput } from '@/components/ceremony/model';
import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { useToast } from '@/components/ui/Toast';

import { ASSERTION_WORDS, assertionFailureText, authenticate, checkHints, keepAdvancedSignCount, recordsForServer } from './model';
import type { AuthenticationRequest } from './useAuthenticationRequest';

// The Advanced tab's authentication, in the current tab's steps and words
// (advanced/auth/assertion.js): the editor's text is the request; progress in a
// line, the success as a toast, a failure in place until the next ceremony, the
// result panel with the signature counter and where the challenge came from.
// The counter the server saw is kept in this browser and the credential's row
// tinted, green for a success and red for the credential a refusal names; the
// values the current tab draws again are drawn. There is no dialog after it.
// Unlike the current tab, Assert Credential is busy meanwhile.
export function useAuthenticationCeremony(request: AuthenticationRequest) {
  const toast = useToast();
  const saved = useSavedCredentials();
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [result, setResult] = useState<CeremonyResultInput | null>(null);
  const busy = useRef(false);
  const latest = useRef(request);
  latest.current = request;

  const assert = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    setRunning(true);
    try {
      const { text, storedCredentials } = latest.current;
      // The two form values are read when the ceremony gets to them, as the current tab reads its fields.
      const outcome = await authenticate(text, {
        ensureHints: (publicKey) => checkHints(publicKey, { storedCredentials }),
        prepareForServer: recordsForServer,
        hashAlgorithm: () => latest.current.settings.hashAlgorithm,
        fakeCredentialLength: () => parseInt(latest.current.settings.fakeCredLength) || 0,
        onStart: () => {
          setFailure(null);
          setResult(null);
        },
        onProgress: setProgress,
      });
      if (!outcome.authenticated) {
        if (outcome.failedCredentialId) saved.flashCredential(outcome.failedCredentialId, 'failure');
        if (outcome.result) setResult(outcome.result);
        setFailure(outcome.text);
        return;
      }

      toast({ tone: 'success', message: ASSERTION_WORDS.authenticated });
      setResult(outcome.result);
      const { authenticatedCredentialId, signCount } = outcome.answer;
      if (authenticatedCredentialId) {
        keepAdvancedSignCount(authenticatedCredentialId, typeof signCount === 'number' ? signCount : undefined);
        saved.flashCredential(authenticatedCredentialId, 'success');
        saved.refresh();
      }
      latest.current.redraw();
    } catch (error) {
      setFailure(assertionFailureText(error));
    } finally {
      busy.current = false;
      setRunning(false);
      setProgress(null);
    }
  }, [toast, saved]);

  return { running, progress, failure, result, assert };
}
