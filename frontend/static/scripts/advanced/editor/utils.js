import {
    applyJsonEditorAutoIndent,
    applyTabIndentation,
    wrapSelectionWithPair,
} from './json-editing.js';

export { applyJsonEditorAutoIndent, applyTabIndentation, wrapSelectionWithPair };

export function handleJsonEditorKeydown(event) {
    const editor = event.target;
    if (!(editor instanceof HTMLTextAreaElement)) {
        return;
    }

    if (event.key === 'Tab') {
        event.preventDefault();
        applyTabIndentation(editor, event.shiftKey);
        return;
    }

    if (event.key === 'Enter') {
        event.preventDefault();
        applyJsonEditorAutoIndent(editor);
        return;
    }

    if (event.ctrlKey || event.metaKey || event.altKey) {
        return;
    }

    const pairMap = {
        '{': '}',
        '[': ']',
    };

    const closing = pairMap[event.key];
    if (closing) {
        event.preventDefault();
        wrapSelectionWithPair(editor, event.key, closing);
    }
}
