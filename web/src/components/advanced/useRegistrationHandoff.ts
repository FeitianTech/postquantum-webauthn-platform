import { statementChanges } from '@/logic/advanced/registration/statement-changes.js';
import { useEffect, useRef } from 'react';

import type { SectionRoute } from '@/lib/useSection';

import type { AdvancedRequest } from './useAdvancedRequest';

// What another section hands the Advanced tab (an MDS entry's Try in Advanced):
// the Registration segment shown, from the top, and each setting the statement
// gives set with the form's own setter, so the editor rewrites in its text only
// what changed. It is taken each time the router hands it, which is once a move
// (the next move takes it away). The form is read through a ref, at the time:
// on a first mount the request's own start, declared before, has run already.
export function useRegistrationHandoff(route: SectionRoute, request: AdvancedRequest, show: (ceremony: 'registration') => void) {
  const latest = useRef(request);
  latest.current = request;
  const { handoff } = route;
  useEffect(() => {
    if (handoff?.kind !== 'registration') return;
    show('registration');
    window.scrollTo({ top: 0 });
    const form = latest.current;
    for (const [field, value] of statementChanges(form.settings, handoff.settings)) form.change(field, value);
  }, [handoff, show]);
}
