import { useEffect, useId, useState } from 'react';

import { KeyValueGrid } from '@/components/ui/KeyValueGrid';
import { MonoValue } from '@/components/ui/MonoValue';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';

import type { CredentialRowView } from './model';
import { useSavedCredentials } from './useSavedCredentials';

type CredentialDetailDialogProps = {
  /** The key of the credential whose details are open (the URL's), or '' for none. */
  openKey: string;
  onClose: () => void;
  /** The URL names a credential this browser does not keep. */
  onUnknown: () => void;
};

// A saved credential's details, in a dialog over its section at its own URL
// (#simple/credential/<key>): a link or a reload opens it, and Back, Escape and
// × close it. Until Phase 28B moves the details themselves, it names the
// credential, gives its id, and leads to the current interface, which shows
// every detail.
export function CredentialDetailDialog({ openKey, onClose, onUnknown }: CredentialDetailDialogProps) {
  const saved = useSavedCredentials();
  const titleId = useId();
  const found = openKey ? saved.rows.find((row) => row.key === openKey) ?? null : null;
  // The last one shown stays while the dialog closes, so its words do not vanish.
  const [shown, setShown] = useState<CredentialRowView | null>(null);

  useEffect(() => {
    if (found) setShown(found);
  }, [found]);

  useEffect(() => {
    if (openKey && saved.loaded && !found) onUnknown();
  }, [openKey, saved.loaded, found, onUnknown]);

  return (
    <Dialog open={Boolean(found)} onClose={onClose} labelledBy={titleId}>
      <OverlayHeader titleId={titleId} title="Credential Details" closeLabel="Close credential details" onClose={onClose} />
      <OverlayBody>
        {shown ? (
          <div data-credential-detail={shown.key}>
            <h3 className="text-heading font-semibold break-words text-ink">{shown.name}</h3>
            <div className="mt-5">
              <KeyValueGrid
                columns={2}
                items={[
                  {
                    key: 'credentialId',
                    label: 'Credential ID',
                    value: <MonoValue value={shown.credentialId} label="credential ID" />,
                    identifier: true,
                  },
                ]}
              />
            </div>
            <p className="mt-6 border-t border-line pt-5 text-body text-ink-muted">
              The rest of this credential's details are shown in the current interface for now.{' '}
              <a href="/" className="font-medium text-accent-ink underline-offset-2 hover-or-demo:underline">
                Open the current interface
              </a>
            </p>
          </div>
        ) : null}
      </OverlayBody>
    </Dialog>
  );
}
