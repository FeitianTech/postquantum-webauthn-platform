import { ENTRY_LINK_MESSAGES, entryIdForAaguid } from '@/logic/mds/explorer/entry-link.js';
import { useCallback } from 'react';

import { type GoToSection, useSectionNavigation } from '@/lib/useSection';

// How another surface (a saved credential's "FIDO MDS" button) opens
// the MDS entry of an AAGUID. The entry's URL is #mds/aaguid:<the AAGUID dashed,
// in lower case>, the id the server gives that entry; the entry's page finds it
// in the list, or asks the server when the list does not hold it, and says so
// meanwhile ("Opening…", "Locating…") and after ("…not found.").

/**
 * Opens an AAGUID's entry as a history entry of its own, so Back returns to
 * the caller. Gives null when it opened, else what to say (for a value that is
 * no AAGUID).
 */
export function openMdsEntryForAaguid(aaguid: unknown, go: GoToSection): string | null {
  const entryId = entryIdForAaguid(aaguid);
  if (!entryId) return ENTRY_LINK_MESSAGES.unavailable;
  go('mds', [entryId]);
  return null;
}

/** openMdsEntryForAaguid for a component inside the app shell. */
export function useOpenMdsEntry() {
  const go = useSectionNavigation();
  return useCallback((aaguid: unknown) => openMdsEntryForAaguid(aaguid, go), [go]);
}
