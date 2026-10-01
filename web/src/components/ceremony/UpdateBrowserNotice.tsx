import { useLayoutEffect, useState } from 'react';

import { AlertIcon } from '@/components/ui/icons';
import { UPDATE_BROWSER_TEXT, nativeJsonSupported } from '@/logic/shared/native-json.js';

/**
 * Whether this browser reads and writes WebAuthn's JSON itself, which every
 * ceremony here needs. The export says yes (its HTML is the same for every
 * browser); the hydrated page reads the browser before its first frame.
 */
export function useNativeWebAuthn() {
  const [supported, setSupported] = useState(true);
  useLayoutEffect(() => setSupported(nativeJsonSupported()), []);
  return supported;
}

// In place of a ceremony in a browser that lacks WebAuthn's JSON methods: what
// to do, in words with a mark, in the warning tint (no grey).
export function UpdateBrowserNotice() {
  return (
    <p
      className="flex items-start gap-2 rounded-sm border border-warning-line bg-warning-tint px-4 py-3 text-body text-warning"
      data-role="update-browser"
    >
      <AlertIcon className="mt-0.5 shrink-0" />
      <span>{UPDATE_BROWSER_TEXT}</span>
    </p>
  );
}
