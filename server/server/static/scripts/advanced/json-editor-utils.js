import { JSON_EDITOR_INDENT_UNIT } from './constants.js';

export function wrapSelectionWithPair(editor, opening, closing) {
    const start = editor.selectionStart;
    const end = editor.selectionEnd;
    const value = editor.value;
    const before = value.slice(0, start);
    const selected = value.slice(start, end);
    const after = value.slice(end);
    editor.value = before + opening + selected + closing + after;

    if (selected.length > 0) {
        editor.selectionStart = start + opening.length;
        editor.selectionEnd = end + opening.length;
    } else {
        const caret = start + opening.length;
        editor.selectionStart = caret;
        editor.selectionEnd = caret;
    }
}

export function applyJsonEditorAutoIndent(editor) {
    const value = editor.value;
    const selectionStart = editor.selectionStart;
    const selectionEnd = editor.selectionEnd;
    const before = value.slice(0, selectionStart);
    const after = value.slice(selectionEnd);
    const lineStart = before.lastIndexOf('\n') + 1;
    const currentLine = before.slice(lineStart);
    const trimmedLine = currentLine.trimEnd();
    const baseIndentMatch = currentLine.match(/^\s*/);
    const baseIndent = baseIndentMatch ? baseIndentMatch[0] : '';
    const closesImmediately = /^\s*[\}\]]/.test(after);

    let extraIndent = '';
    if (trimmedLine.endsWith('{') || trimmedLine.endsWith('[')) {
        extraIndent = JSON_EDITOR_INDENT_UNIT;
    }

    if (closesImmediately && extraIndent) {
        const inserted = `\n${baseIndent}${extraIndent}\n${baseIndent}`;
        editor.value = before + inserted + after;
        const caretPosition = before.length + 1 + baseIndent.length + extraIndent.length;
        editor.selectionStart = caretPosition;
        editor.selectionEnd = caretPosition;
        return;
    }

    if (closesImmediately && currentLine.trim() === '') {
        const dedentLength = Math.max(0, baseIndent.length - JSON_EDITOR_INDENT_UNIT.length);
        const dedentIndent = baseIndent.slice(0, dedentLength);
        const inserted = `\n${dedentIndent}`;
        editor.value = before + inserted + after;
        const caretPosition = before.length + inserted.length;
        editor.selectionStart = caretPosition;
        editor.selectionEnd = caretPosition;
        return;
    }

    const inserted = `\n${baseIndent}${extraIndent}`;
    editor.value = before + inserted + after;
    const caretPosition = before.length + inserted.length;
    editor.selectionStart = caretPosition;
    editor.selectionEnd = caretPosition;
}

export function applyTabIndentation(editor, isShift) {
    const value = editor.value;
    const selectionStart = editor.selectionStart;
    const selectionEnd = editor.selectionEnd;
    const hasSelection = selectionStart !== selectionEnd;

    if (hasSelection && value.slice(selectionStart, selectionEnd).includes('\n')) {
        const selectedText = value.slice(selectionStart, selectionEnd);
        const lines = selectedText.split('\n');

        if (isShift) {
            const dedentedLines = lines.map(line => {
                if (line.startsWith(JSON_EDITOR_INDENT_UNIT)) {
                    return line.slice(JSON_EDITOR_INDENT_UNIT.length);
                }
                if (line.startsWith('\t')) {
                    return line.slice(1);
                }
                const match = line.match(/^ {1,2}/);
                if (match) {
                    return line.slice(match[0].length);
                }
                return line;
            });

            const dedentedText = dedentedLines.join('\n');
            const diff = selectedText.length - dedentedText.length;
            editor.value = value.slice(0, selectionStart) + dedentedText + value.slice(selectionEnd);
            editor.selectionStart = selectionStart;
            editor.selectionEnd = selectionEnd - diff;
        } else {
            const indentedText = lines.map(line => JSON_EDITOR_INDENT_UNIT + line).join('\n');
            const diff = indentedText.length - selectedText.length;
            editor.value = value.slice(0, selectionStart) + indentedText + value.slice(selectionEnd);
            editor.selectionStart = selectionStart;
            editor.selectionEnd = selectionEnd + diff;
        }
        return;
    }

    if (isShift) {
        const lineStart = value.lastIndexOf('\n', selectionStart - 1) + 1;
        if (value.slice(lineStart, lineStart + JSON_EDITOR_INDENT_UNIT.length) === JSON_EDITOR_INDENT_UNIT) {
            editor.value = value.slice(0, lineStart) + value.slice(lineStart + JSON_EDITOR_INDENT_UNIT.length);
            const newPos = Math.max(lineStart, selectionStart - JSON_EDITOR_INDENT_UNIT.length);
            editor.selectionStart = newPos;
            editor.selectionEnd = newPos;
        } else if (value[lineStart] === '\t') {
            editor.value = value.slice(0, lineStart) + value.slice(lineStart + 1);
            const newPos = Math.max(lineStart, selectionStart - 1);
            editor.selectionStart = newPos;
            editor.selectionEnd = newPos;
        } else {
            const leadingSpaces = value.slice(lineStart, selectionStart).match(/^ +/);
            if (leadingSpaces && leadingSpaces[0].length > 0) {
                const removeCount = Math.min(leadingSpaces[0].length, JSON_EDITOR_INDENT_UNIT.length);
                editor.value = value.slice(0, lineStart) + value.slice(lineStart + removeCount);
                const newPos = Math.max(lineStart, selectionStart - removeCount);
                editor.selectionStart = newPos;
                editor.selectionEnd = newPos;
            }
        }
    } else {
        const insertion = JSON_EDITOR_INDENT_UNIT;
        editor.value = value.slice(0, selectionStart) + insertion + value.slice(selectionEnd);
        const newPos = selectionStart + insertion.length;
        editor.selectionStart = newPos;
        editor.selectionEnd = newPos;
    }
}

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
