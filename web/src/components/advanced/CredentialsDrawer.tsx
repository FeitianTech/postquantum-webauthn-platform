import { useId } from 'react';

import {
  ClearAllButton,
  CredentialCount,
  CredentialProgress,
  SavedCredentialList,
  useCredentialDeletion,
} from '@/components/credentials/SavedCredentials';
import { Drawer, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';

export const DRAWER_ID = 'advanced-saved-credentials';

// The saved credentials, in a drawer over the Advanced tab: the list both tabs
// share (Phase 28), with how many there are and Clear All in its header. A name
// opens the credential's details over the drawer; a question asked from it
// comes over it too, and closing either comes back to it.
export function CredentialsDrawer({
  open,
  onClose,
  onOpen,
  returnFocusTo,
}: {
  open: boolean;
  onClose: () => void;
  onOpen: (key: string) => void;
  returnFocusTo: () => HTMLElement | null;
}) {
  const titleId = useId();
  // After Clear All no row is left to take the focus: the drawer takes it.
  const deletion = useCredentialDeletion(() => document.getElementById(titleId)?.closest<HTMLElement>('[data-overlay-panel]') ?? null);

  return (
    <Drawer id={DRAWER_ID} open={open} onClose={onClose} label="Saved Credentials" returnFocusTo={returnFocusTo}>
      <OverlayHeader
        titleId={titleId}
        title={
          <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            Saved Credentials
            <CredentialCount saved={deletion.saved} />
          </span>
        }
        closeLabel="Close saved credentials"
        onClose={onClose}
        actions={<ClearAllButton deletion={deletion} />}
      />
      <OverlayBody className="px-0 py-0 sm:px-0">
        {deletion.saved.progress ? (
          <div className="px-5 pt-4">
            <CredentialProgress saved={deletion.saved} />
          </div>
        ) : null}
        <div className="pt-4">
          <SavedCredentialList deletion={deletion} labelledBy={titleId} onOpen={onOpen} />
        </div>
      </OverlayBody>
      {deletion.dialog}
    </Drawer>
  );
}
