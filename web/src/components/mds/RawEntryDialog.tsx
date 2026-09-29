import { RAW_DATA_LABEL } from '@/logic/advanced/mds/raw-data.js';
import { useMemo } from 'react';

import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';
import { downloadText, fileNameFor } from '@/lib/download';

import { entrySubtitleText, rawData, rawText, rawTitle } from './entryModel';
import type { MdsEntry } from './model';

export const RAW_DIALOG_ID = 'mds-entry-raw';

// The entry as MDS publishes it (the current UI's popup window, as a dialog: a
// popup is blocked in some browsers): its title and subtitle, and the JSON,
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
    const data = rawData(entry);
    return data ? rawText(data) : '';
  }, [entry]);
  const subtitle = entrySubtitleText(entry);

  return (
    <Dialog id={RAW_DIALOG_ID} open={open && Boolean(text)} onClose={onClose} labelledBy={titleId} returnFocusTo={returnFocusTo}>
      <OverlayHeader
        titleId={titleId}
        title={rawTitle(entry)}
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
