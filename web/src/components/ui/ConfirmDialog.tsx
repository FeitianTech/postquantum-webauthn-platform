import { type ReactNode, useId, useRef } from 'react';

import { Button } from './Button';
import { Dialog, OverlayBody, OverlayHeader } from './Overlay';

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  /** The question, as the person should read it before acting. */
  question: ReactNode;
  /** The action's name on its button, e.g. "Delete". */
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  returnFocusTo?: () => HTMLElement | null;
};

// A question before something that cannot be undone: the question, Cancel and
// the action. Focus starts on Cancel, so Enter never destroys by accident;
// Escape, the backdrop and × cancel. It replaces the browser's confirm(), which
// some embedded browsers block and none lets the page style.
export function ConfirmDialog({ open, title, question, confirmLabel, onConfirm, onCancel, returnFocusTo }: ConfirmDialogProps) {
  const titleId = useId();
  const questionId = useId();
  const cancelRef = useRef<HTMLButtonElement>(null);

  return (
    <Dialog
      open={open}
      onClose={onCancel}
      role="alertdialog"
      labelledBy={titleId}
      describedBy={questionId}
      size="sm"
      initialFocus={() => cancelRef.current}
      returnFocusTo={returnFocusTo}
    >
      <OverlayHeader titleId={titleId} title={title} closeLabel="Close" onClose={onCancel} />
      <OverlayBody>
        <p id={questionId} className="text-body-lg text-ink">
          {question}
        </p>
        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <Button ref={cancelRef} variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </OverlayBody>
    </Dialog>
  );
}
