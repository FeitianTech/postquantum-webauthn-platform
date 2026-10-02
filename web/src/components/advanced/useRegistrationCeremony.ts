import { useCallback, useRef, useState } from 'react';

import { useSavedCredentials } from '@/components/credentials/useSavedCredentials';
import { useToast } from '@/components/ui/Toast';
import { keepRegistrationSnapshot } from '@/logic/credentials/registration/snapshot.js';
import { credentialKey } from '@/logic/credentials/saved-list.js';
import type { CeremonyResultInput } from '@/logic/shared/ceremony-result.js';
import {
  advancedRegisteredMessage,
  advancedRegistrationFailureText,
  registerAdvancedCredential,
} from '@/logic/advanced/registration/ceremony.js';
import { saveAdvancedCredential } from '@/logic/credentials/storage/local/advanced-credentials.js';

import type { AdvancedRequest } from './useAdvancedRequest';

// The Advanced tab's registration, in the steps and words of
// advanced/registration/ceremony.js: the editor's text is the request; progress in a
// line, the server's warnings and the success as toasts, a failure in place until
// the next ceremony, the result panel with where the challenge came from. The
// record the server stored is kept in this browser with the registration as its
// snapshot, then `openRegistration(key)` opens the credential's details at its
// registration. Create Credential is busy meanwhile.
export function useRegistrationCeremony(request: AdvancedRequest, openRegistration: (key: string) => void) {
  const toast = useToast();
  const saved = useSavedCredentials();
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [result, setResult] = useState<CeremonyResultInput | null>(null);
  const busy = useRef(false);
  const latest = useRef({ request, openRegistration });
  latest.current = { request, openRegistration };

  const register = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    setRunning(true);
    try {
      const { settings, text } = latest.current.request;
      const outcome = await registerAdvancedCredential(text, {
        minPinLength: () => settings.minPinLength,
        onStart: () => {
          setFailure(null);
          setResult(null);
        },
        onProgress: setProgress,
        onWarning: (message) => toast({ tone: 'warning', message }),
        onResult: setResult,
      });
      if (!outcome.registered) {
        setFailure(outcome.text);
        return;
      }

      const message = advancedRegisteredMessage(outcome.answer);
      toast({ tone: message.tone, message: message.text });
      latest.current.request.redraw();
      const kept = outcome.record ? saveAdvancedCredential(outcome.record) : null;
      await keepRegistrationSnapshot({
        credentialJson: outcome.credentialJson,
        relyingPartyInfo: outcome.answer.relyingParty ?? null,
        storageId: kept?.storageId ?? null,
      });
      saved.refresh();
      if (kept) latest.current.openRegistration(credentialKey(kept));
    } catch (error) {
      setFailure(advancedRegistrationFailureText(error));
    } finally {
      busy.current = false;
      setRunning(false);
      setProgress(null);
    }
  }, [toast, saved]);

  return { running, progress, failure, result, register };
}
