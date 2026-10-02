import { type KeyboardEvent, useId, useLayoutEffect, useRef } from 'react';

import { Button } from '@/components/ui/Button';
import { textControlClassName } from '@/components/ui/Field';
import { AlertIcon } from '@/components/ui/icons';
import { useToast } from '@/components/ui/Toast';
import { cx } from '@/lib/cx';
import {
  type EditorState,
  applyJsonEditorAutoIndent,
  applyTabIndentation,
  wrapSelectionWithPair,
} from '@/logic/advanced/editor/keys.js';
import { EDITOR_TEXT, type EditedRequest, type RequestScope, editorTitle } from '@/logic/advanced/editor/model.js';

import type { RequestEditor } from './requestEditor';

const PAIRS: Record<string, string> = { '{': '}', '[': ']' };
// The button that sends the request, which a refused edit's note names.
const SENDS: Record<RequestScope, string> = { registration: 'Create Credential', authentication: 'Assert Credential' };

// The editor's own edits (editor/keys.js): Tab, Shift+Tab, Enter, { and [ edit
// the text, the selection set once the edit is rendered; Escape lets the next
// Tab leave. Also where a parse error is: goTo(offset).
function useEditorKeys(request: RequestEditor) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  // Where the selection goes once a key's edit is rendered.
  const pendingSelection = useRef<[number, number] | null>(null);
  // Escape lets the next Tab leave the editor.
  const leaving = useRef(false);

  useLayoutEffect(() => {
    const selection = pendingSelection.current;
    const textarea = textareaRef.current;
    if (!selection || !textarea) return;
    pendingSelection.current = null;
    textarea.setSelectionRange(selection[0], selection[1]);
  });

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Escape') {
      leaving.current = true;
      return;
    }
    const leave = leaving.current;
    leaving.current = false;
    if (event.key === 'Tab' && leave) return;
    const pair = PAIRS[event.key];
    const modified = event.ctrlKey || event.metaKey || event.altKey;
    if (event.key !== 'Tab' && event.key !== 'Enter' && (!pair || modified)) return;

    event.preventDefault();
    const target = event.currentTarget;
    const typed: EditorState = { value: target.value, selectionStart: target.selectionStart, selectionEnd: target.selectionEnd };
    if (event.key === 'Tab') applyTabIndentation(typed, event.shiftKey);
    else if (event.key === 'Enter') applyJsonEditorAutoIndent(typed);
    else wrapSelectionWithPair(typed, event.key, pair);
    pendingSelection.current = [typed.selectionStart, typed.selectionEnd];
    request.editText(typed.value);
  };

  const goTo = (offset: number) => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    textarea.focus();
    textarea.setSelectionRange(offset, offset);
  };

  return { textareaRef, onKeyDown, goTo };
}

// Why the form does not follow the text: where it stops being JSON, or that
// the request is sent as it is.
function EditNote({
  edit,
  scope,
  noteId,
  goTo,
}: {
  edit: Exclude<EditedRequest, { status: 'accepted' }>;
  scope: RequestScope;
  noteId: string;
  goTo: (offset: number) => void;
}) {
  return (
    <div
      id={noteId}
      role={edit.status === 'unparsed' ? 'alert' : 'status'}
      data-edit={edit.status}
      className={cx(
        'flex flex-col gap-2 rounded-sm border px-4 py-3 text-body',
        edit.status === 'unparsed' ? 'border-danger-line bg-danger-tint text-danger' : 'border-warning-line bg-warning-tint text-warning',
      )}
    >
      <p className="flex items-start gap-2 wrap-anywhere">
        <AlertIcon size={14} className="mt-1 shrink-0" />
        {edit.message}
      </p>
      {edit.status === 'unparsed' && edit.location ? (
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-label">
          <span data-location="">
            Line {edit.location.line}, column {edit.location.column}
          </span>
          <Button variant="quiet" size="sm" onClick={() => goTo(edit.location!.offset)}>
            Go to line {edit.location.line}
          </Button>
        </p>
      ) : null}
      {edit.status === 'refused' ? (
        <p className="text-label">The form keeps the last request it could read; {SENDS[scope]} sends this JSON as it is.</p>
      ) : null}
    </div>
  );
}

// The JSON editor beside a ceremony's form: the request the ceremony sends, as
// text. An edit applies as it parses: the form follows at once; one that does
// not parse says why and where, and the form keeps the last request it could
// read. Tab, Shift+Tab, Enter, { and [ edit the text (editor/keys.js); Escape,
// then Tab, leaves it. Geist Mono for the JSON only.
export function JsonEditor({ scope, request }: { scope: RequestScope; request: RequestEditor }) {
  const headingId = useId();
  const noteId = useId();
  const { textareaRef, onKeyDown, goTo } = useEditorKeys(request);
  const title = editorTitle(scope);
  const { edit } = request;
  const toast = useToast();
  const reset = () => {
    request.resetEditor();
    toast({ tone: 'info', message: EDITOR_TEXT.reset });
  };

  return (
    <section
      aria-labelledby={headingId}
      className="flex min-w-0 flex-col gap-4 rounded-lg border border-line bg-surface p-5 sm:p-6 wide:h-full"
      data-json-editor=""
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 id={headingId} className="text-title-sm font-semibold break-words text-ink">
          {title}
        </h3>
        <Button variant="secondary" size="sm" title="Reset JSON to match current settings" onClick={reset}>
          Reset
        </Button>
      </div>
      <textarea
        ref={textareaRef}
        aria-labelledby={headingId}
        aria-describedby={edit && edit.status !== 'accepted' ? noteId : undefined}
        aria-invalid={edit?.status === 'unparsed' ? true : undefined}
        data-text-field=""
        className={cx(
          textControlClassName(edit?.status === 'unparsed'),
          'block min-h-[24rem] flex-1 resize-y px-3 py-2.5 font-mono text-[0.78125rem] leading-[1.65] wide:min-h-[16rem] wide:resize-none',
        )}
        rows={20}
        placeholder="JSON representation will appear here automatically..."
        value={request.text}
        onChange={(event) => request.editText(event.target.value)}
        onKeyDown={onKeyDown}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        data-gramm="false"
        data-gramm_editor="false"
        data-enable-grammarly="false"
      />
      {edit && edit.status !== 'accepted' ? <EditNote edit={edit} scope={scope} noteId={noteId} goTo={goTo} /> : null}
    </section>
  );
}
