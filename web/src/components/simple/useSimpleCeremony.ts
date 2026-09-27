import { useCallback, useEffect, useRef, useState } from 'react';

import type { CeremonyResultInput } from '@/components/ceremony/model';
import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { useToast } from '@/components/ui/Toast';

import {
  CEREMONY_TEXT,
  type Ceremony,
  authenticateWithPasskey,
  failureText,
  keepRegistered,
  keepSignCount,
  randomUsername,
  registerPasskey,
  successText,
} from './model';

// The Simple tab's two ceremonies, in the current tab's steps and words
// (simple/ceremony.js): the username, what each step is doing, a success as a
// toast, a failure in place until the next ceremony, and the result panel. Unlike
// the current tab, the pressed button is busy and neither can be pressed again
// meanwhile. A registration keeps the server's record in this browser; an
// authentication keeps the server's counter and tints the credential it used.
export function useSimpleCeremony() {
  const toast = useToast();
  const saved = useSavedCredentials();
  const [username, setUsername] = useState('');
  const [usernameError, setUsernameError] = useState<string | null>(null);
  const [running, setRunning] = useState<Ceremony | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [result, setResult] = useState<CeremonyResultInput | null>(null);
  const busy = useRef(false);

  // Once, after hydration (the exported page has the field empty), as the
  // current tab fills it when the page has loaded.
  useEffect(() => setUsername(randomUsername()), []);

  const randomize = useCallback(() => {
    setUsername(randomUsername());
    setUsernameError(null);
  }, []);

  const changeUsername = useCallback((value: string) => {
    setUsername(value);
    setUsernameError(null);
  }, []);

  const begin = useCallback(
    (ceremony: Ceremony) => {
      if (busy.current) return false;
      if (!username) {
        setUsernameError(CEREMONY_TEXT.usernameRequired);
        return false;
      }
      busy.current = true;
      setRunning(ceremony);
      setFailure(null);
      setResult(null);
      return true;
    },
    [username],
  );

  const end = useCallback(() => {
    busy.current = false;
    setRunning(null);
    setProgress(null);
  }, []);

  const register = useCallback(async () => {
    if (!begin('registration')) return;
    try {
      const answer = await registerPasskey(username, { onProgress: setProgress });
      toast({ tone: 'success', message: successText(answer) });
      if (answer.storedCredential && typeof answer.storedCredential === 'object') {
        keepRegistered(answer.storedCredential, username);
        saved.refresh();
      }
    } catch (error) {
      setFailure(failureText(error, 'registration'));
    } finally {
      end();
    }
  }, [begin, end, username, toast, saved]);

  const authenticate = useCallback(async () => {
    if (!begin('authentication')) return;
    try {
      const outcome = await authenticateWithPasskey(username, { onProgress: setProgress });
      setResult(outcome.result);
      if (outcome.failure) {
        if (outcome.failure.failedCredentialId) saved.flashCredential(outcome.failure.failedCredentialId, 'failure');
        setFailure(outcome.failure.text);
        return;
      }
      toast({ tone: 'success', message: CEREMONY_TEXT.authenticated });
      const { authenticatedCredentialId, signCount } = outcome.answer;
      if (authenticatedCredentialId) {
        keepSignCount(username, authenticatedCredentialId, typeof signCount === 'number' ? signCount : undefined);
        saved.flashCredential(authenticatedCredentialId, 'success');
        saved.refresh();
      }
    } catch (error) {
      setFailure(failureText(error, 'authentication'));
    } finally {
      end();
    }
  }, [begin, end, username, toast, saved]);

  return { username, changeUsername, randomize, usernameError, running, progress, failure, result, register, authenticate };
}
