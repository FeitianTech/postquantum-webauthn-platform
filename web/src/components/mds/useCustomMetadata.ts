import type { MdsSnapshot } from '@/logic/mds/explorer/loading.js';
import {
  CHOOSE_METADATA_FILES,
  type CustomItem,
  DELETE_METADATA_FAILED,
  DELETE_PROGRESS,
  type PanelMessage,
  UPLOADING_METADATA,
  UPLOAD_METADATA_FAILED,
  UPLOAD_PROGRESS,
  customMetadataItemLabel,
  describeCustomMetadataItem,
  describeDeleteAnswer,
  describeFileSelection,
  describeUploadAnswer,
  removedCustomMetadataMessage,
  removingCustomMetadataMessage,
  requestCustomMetadataDelete,
  requestCustomMetadataList,
  requestCustomMetadataUpload,
} from '@/logic/mds/explorer/custom-metadata.js';
import { useCallback, useEffect, useRef, useState } from 'react';

// How long the last progress sentence stays.
const SUCCESS_MS = 520;
const FAILURE_MS = 720;

// Manage Trusted Metadata's work, in the steps and words of
// explorer/custom-metadata.js: choosing files (only .json ones are sent),
// uploading, deleting, and the files uploaded in this session. An answer with the
// session's snapshot is shown at once; one without makes the explorer load the
// session's list again. A refusal keeps the server's reason, and the progress is a
// line in the dialog.
export function useCustomMetadata({
  onSnapshot,
  onReload,
}: {
  onSnapshot: (snapshot: MdsSnapshot) => void;
  onReload: () => Promise<void>;
}) {
  const [items, setItems] = useState<CustomItem[]>([]);
  const [message, setMessage] = useState<PanelMessage | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [removingFile, setRemovingFile] = useState<string | null>(null);
  const settle = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => clearTimeout(settle.current ?? undefined), []);

  const step = (text: string) => {
    clearTimeout(settle.current ?? undefined);
    setProgress(text);
  };
  const finish = (text: string, ms: number) => {
    setProgress(text);
    settle.current = setTimeout(() => setProgress(null), ms);
  };

  const refresh = useCallback(async () => {
    try {
      setItems((await requestCustomMetadataList()).map(describeCustomMetadataItem));
    } catch {
      // The list shown stays as it was.
    }
  }, []);

  const applyAnswer = async (snapshot: MdsSnapshot | null | undefined, progressSteps: { applying: string; later: string }) => {
    if (snapshot) {
      step(progressSteps.applying);
      onSnapshot(snapshot);
    } else {
      step(progressSteps.later);
      await onReload();
    }
  };

  const sendFiles = async (files: File[]) => {
    if (!files.length) {
      setMessage({ text: CHOOSE_METADATA_FILES, variant: 'warning' });
      return;
    }
    setBusy(true);
    setMessage({ text: UPLOADING_METADATA, variant: 'info' });
    step(UPLOAD_PROGRESS.start);
    try {
      step(UPLOAD_PROGRESS.uploading);
      const { response, payload } = await requestCustomMetadataUpload(files);
      const answer = describeUploadAnswer(response, payload);
      setMessage({ text: answer.message, variant: answer.variant });
      if (!answer.ok) {
        finish(UPLOAD_PROGRESS.failure, FAILURE_MS);
        return;
      }
      await applyAnswer(answer.snapshot, { applying: UPLOAD_PROGRESS.applying, later: UPLOAD_PROGRESS.reloading });
      finish(UPLOAD_PROGRESS.success, SUCCESS_MS);
      await refresh();
    } catch {
      setMessage({ text: UPLOAD_METADATA_FAILED, variant: 'error' });
      finish(UPLOAD_PROGRESS.failure, FAILURE_MS);
    } finally {
      setBusy(false);
    }
  };

  const choose = async (files: File[]) => {
    const { accepted, message: chosen } = describeFileSelection(files);
    if (chosen) setMessage(chosen);
    if (!accepted.length) return;
    await sendFiles(accepted);
  };

  const deleteItem = async (item: CustomItem) => {
    const label = customMetadataItemLabel(item.name);
    setBusy(true);
    setRemovingFile(item.storedFilename);
    setMessage({ text: removingCustomMetadataMessage(label), variant: 'info' });
    step(DELETE_PROGRESS.start);
    try {
      step(DELETE_PROGRESS.removing);
      const { response, payload } = await requestCustomMetadataDelete(item.storedFilename);
      const answer = describeDeleteAnswer(response, payload);
      if (!answer.ok) {
        setMessage({ text: answer.message!, variant: answer.variant! });
        finish(answer.variant === 'error' ? DELETE_PROGRESS.failure : DELETE_PROGRESS.unchanged, FAILURE_MS);
        await refresh();
        return;
      }
      await applyAnswer(answer.snapshot, { applying: DELETE_PROGRESS.applying, later: DELETE_PROGRESS.refreshing });
      setMessage({ text: removedCustomMetadataMessage(label), variant: 'success' });
      finish(DELETE_PROGRESS.success, SUCCESS_MS);
      await refresh();
    } catch {
      setMessage({ text: DELETE_METADATA_FAILED, variant: 'error' });
      finish(DELETE_PROGRESS.failure, FAILURE_MS);
    } finally {
      setBusy(false);
      setRemovingFile(null);
    }
  };

  return { items, message, progress, busy, removingFile, refresh, choose, deleteItem };
}
