import { describe, expect, it } from 'vitest';

import {
  applyJsonEditorAutoIndent,
  applyTabIndentation,
  handleJsonEditorKeydown,
  wrapSelectionWithPair,
} from '../../static/scripts/advanced/json-editor-utils.js';

function createEditor(value, selectionStart = value.length, selectionEnd = selectionStart) {
  const editor = document.createElement('textarea');
  editor.value = value;
  editor.selectionStart = selectionStart;
  editor.selectionEnd = selectionEnd;
  return editor;
}

describe('json-editor-utils', () => {
  it('wraps selected text with matching pairs', () => {
    const editor = createEditor('value', 0, 5);
    wrapSelectionWithPair(editor, '{', '}');
    expect(editor.value).toBe('{value}');
    expect(editor.selectionStart).toBe(1);
    expect(editor.selectionEnd).toBe(6);
  });

  it('auto-indents new lines inside nested objects', () => {
    const editor = createEditor('{\n  "a": {\n    \n  }\n}', 15, 15);
    applyJsonEditorAutoIndent(editor);
    expect(editor.value).toContain('\n  \n');
    expect(editor.selectionStart).toBe(editor.selectionEnd);
  });

  it('indents and dedents selections with tab behavior', () => {
    const editor = createEditor('line1\nline2', 0, 11);
    applyTabIndentation(editor, false);
    expect(editor.value).toBe('  line1\n  line2');

    applyTabIndentation(editor, true);
    expect(editor.value).toBe('line1\nline2');
  });

  it('handles keyboard shortcuts for tab, enter, and brace wrapping', () => {
    const editor = createEditor('{}', 1, 1);
    document.body.appendChild(editor);

    const tabEvent = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true });
    Object.defineProperty(tabEvent, 'target', { value: editor });
    Object.defineProperty(tabEvent, 'preventDefault', { value: () => {} });
    handleJsonEditorKeydown(tabEvent);
    expect(editor.value).toBe('{  }');

    editor.value = '{';
    editor.selectionStart = 1;
    editor.selectionEnd = 1;
    const enterEvent = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true });
    Object.defineProperty(enterEvent, 'target', { value: editor });
    Object.defineProperty(enterEvent, 'preventDefault', { value: () => {} });
    handleJsonEditorKeydown(enterEvent);
    expect(editor.value).toContain('\n  ');

    const braceEditor = createEditor('', 0, 0);
    const braceEvent = new KeyboardEvent('keydown', { key: '{', bubbles: true });
    Object.defineProperty(braceEvent, 'target', { value: braceEditor });
    Object.defineProperty(braceEvent, 'preventDefault', { value: () => {} });
    handleJsonEditorKeydown(braceEvent);
    expect(braceEditor.value).toBe('{}');
  });

  it('handles collapsed wrap, dedent auto-indent branch, and modifier key bypass', () => {
    const collapsed = createEditor('', 0, 0);
    wrapSelectionWithPair(collapsed, '[', ']');
    expect(collapsed.value).toBe('[]');
    expect(collapsed.selectionStart).toBe(1);

    const dedentEditor = createEditor('{\n  \n}', 4, 4);
    applyJsonEditorAutoIndent(dedentEditor);
    expect(dedentEditor.value).toContain('\n');

    const nonTextareaEvent = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true });
    Object.defineProperty(nonTextareaEvent, 'target', { value: document.createElement('div') });
    expect(() => handleJsonEditorKeydown(nonTextareaEvent)).not.toThrow();

    const bypassEditor = createEditor('value', 5, 5);
    const bypassEvent = new KeyboardEvent('keydown', { key: '{', bubbles: true, ctrlKey: true });
    Object.defineProperty(bypassEvent, 'target', { value: bypassEditor });
    Object.defineProperty(bypassEvent, 'preventDefault', { value: () => {} });
    handleJsonEditorKeydown(bypassEvent);
    expect(bypassEditor.value).toBe('value');
  });
});
