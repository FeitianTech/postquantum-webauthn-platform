import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { formatDetailSubtitle } from '@/logic/mds/explorer/detail.js';
import { RAW_DATA_LABEL, authenticatorRawTitle, getAuthenticatorRawData } from '@/logic/mds/raw-data.js';
import { stringifyAuthenticatorRawData } from '@/logic/mds/raw-stringify.js';
import { useMemo } from 'react';

import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';
import { downloadText, fileNameFor } from '@/lib/download';

const RAW_DIALOG_ID = 'mds-entry-raw';

// The entry as MDS publishes it, in a dialog (a popup window is blocked in some
// browsers): its title and subtitle, and the JSON,
// indented by four spaces, with copy, and as a .json file to save.
export function RawEntryDialog({
  entry,
  open,
  onClose,
  returnFocusTo,
}: {
  entry: MdsEntry;
  open: boolean;
  onClose: () => void;
  returnFocusTo: () => HTMLElement | null;
}) {
  const titleId = `${RAW_DIALOG_ID}-title`;
  const text = useMemo(() => {
    const data = getAuthenticatorRawData(entry);
    return data ? stringifyAuthenticatorRawData(data) : '';
  }, [entry]);
  const subtitle = formatDetailSubtitle(entry);

  return (
    <Dialog id={RAW_DIALOG_ID} open={open && Boolean(text)} onClose={onClose} labelledBy={titleId} returnFocusTo={returnFocusTo}>
      <OverlayHeader
        titleId={titleId}
        title={authenticatorRawTitle(entry)}
        closeLabel="Close raw authenticator data"
        onClose={onClose}
        actions={
          <Button variant="secondary" size="sm" onClick={() => downloadText(fileNameFor(entry.entryId, 'json'), text)}>
            Download JSON
          </Button>
        }
      />
      <OverlayBody>
        {subtitle ? <p className="mb-4 text-body break-words text-ink-muted">{subtitle}</p> : null}
        <CodeBlock value={text} label={RAW_DATA_LABEL} />
      </OverlayBody>
    </Dialog>
  );
}
