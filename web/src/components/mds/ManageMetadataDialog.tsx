import type { MdsSnapshot } from '@/logic/mds/explorer/loading.js';
import { type MessageVariant, NO_CUSTOM_METADATA } from '@/logic/mds/explorer/custom-metadata.js';
import { type DragEvent, useEffect, useId, useRef, useState } from 'react';

import { Button } from '@/components/ui/Button';
import { FolderIcon, Spinner } from '@/components/ui/icons';
import { Dialog, OverlayBody, OverlayHeader } from '@/components/ui/Overlay';
import { cx } from '@/lib/cx';

import { useCustomMetadata } from './useCustomMetadata';

const MESSAGE_TONES: Record<MessageVariant, string> = {
  info: 'border border-line text-ink',
  success: 'bg-success-tint text-success',
  warning: 'bg-warning-tint text-warning',
  error: 'bg-danger-tint text-danger',
};

// Where files are dropped, or a button that opens the file chooser (.json only,
// several at once). The zone lights up while files are dragged over it.
function DropZone({ busy, onFiles }: { busy: boolean; onFiles: (files: File[]) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const hintId = `${useId()}-hint`;

  const onDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    setOver(true);
  };

  return (
    <div
      data-mds-dropzone=""
      data-active={over || undefined}
      onDragEnter={onDragOver}
      onDragOver={onDragOver}
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOver(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        setOver(false);
        onFiles([...event.dataTransfer.files]);
      }}
      className={cx(
        'flex flex-col items-center gap-2 rounded-md border border-dashed px-6 py-8 text-center transition-colors duration-(--duration-fast)',
        over ? 'border-accent bg-accent-tint' : 'border-line-strong',
      )}
    >
      <FolderIcon size={22} className="text-ink-muted" />
      <button
        type="button"
        disabled={busy}
        aria-describedby={hintId}
        onClick={() => inputRef.current?.click()}
        className="rounded-xs text-body-lg font-medium text-accent-ink hover:underline disabled:cursor-not-allowed disabled:opacity-60"
      >
        Drop JSON files here or click to browse
      </button>
      <p id={hintId} className="text-caption text-ink-muted">
        Only <code>.json</code> files are accepted.
      </p>
      <input
        ref={inputRef}
        type="file"
        accept=".json,application/json"
        multiple
        hidden
        data-mds-file-input=""
        onChange={(event) => {
          const files = [...(event.target.files ?? [])];
          event.target.value = '';
          onFiles(files);
        }}
      />
    </div>
  );
}

// Manage Trusted Metadata: upload MDS statements (JSON) that this browser session
// trusts, and remove them. Uploaded entries join the list at once.
export function ManageMetadataDialog({
  open,
  onClose,
  returnFocusTo,
  onSnapshot,
  onReload,
}: {
  open: boolean;
  onClose: () => void;
  returnFocusTo: () => HTMLElement | null;
  onSnapshot: (snapshot: MdsSnapshot) => void;
  onReload: () => Promise<void>;
}) {
  const metadata = useCustomMetadata({ onSnapshot, onReload });
  const titleId = `${useId()}-title`;
  const { refresh } = metadata;

  useEffect(() => {
    if (open) void refresh();
  }, [open, refresh]);

  return (
    <Dialog open={open} onClose={onClose} labelledBy={titleId} returnFocusTo={returnFocusTo} className="max-w-2xl">
      <OverlayHeader titleId={titleId} title="Manage Trusted Metadata" closeLabel="Close" onClose={onClose} />
      <OverlayBody className="flex flex-col gap-5 overscroll-contain">
        <p className="text-body text-ink-muted">
          Drop JSON metadata files here or select them from your device. Uploaded files are trusted only for this browser
          session.
        </p>
        <DropZone busy={metadata.busy} onFiles={(files) => void metadata.choose(files)} />
        <div aria-live="polite" className="flex flex-col gap-2">
          {metadata.progress ? (
            <p className="flex items-center gap-2 text-body text-ink-muted" data-mds-progress="">
              <Spinner />
              {metadata.progress}
            </p>
          ) : null}
          {metadata.message ? (
            <p
              className={cx('rounded-sm px-3 py-2 text-body', MESSAGE_TONES[metadata.message.variant])}
              data-variant={metadata.message.variant}
              data-mds-message=""
            >
              {metadata.message.text}
            </p>
          ) : null}
        </div>
        <section aria-labelledby={`${titleId}-files`}>
          <h3 id={`${titleId}-files`} className="text-label font-semibold text-ink">
            Uploaded files
          </h3>
          <ul aria-live="polite" className="mt-1">
            {metadata.items.length ? (
              metadata.items.map((item) => (
                <li
                  key={item.storedFilename || item.name}
                  className="flex items-start justify-between gap-3 border-b border-line py-3 last:border-b-0"
                >
                  <div className="min-w-0">
                    <p className="text-body font-medium break-words text-ink">{item.name}</p>
                    {item.details ? <p className="text-caption text-ink-muted">{item.details}</p> : null}
                  </div>
                  {item.storedFilename ? (
                    <Button
                      variant="danger"
                      size="sm"
                      aria-label={item.deleteLabel}
                      title={item.deleteLabel}
                      busy={metadata.removingFile === item.storedFilename}
                      disabled={metadata.busy}
                      onClick={() => void metadata.deleteItem(item)}
                    >
                      Delete
                    </Button>
                  ) : null}
                </li>
              ))
            ) : (
              <li className="py-3 text-body text-ink-muted">{NO_CUSTOM_METADATA}</li>
            )}
          </ul>
        </section>
      </OverlayBody>
    </Dialog>
  );
}
