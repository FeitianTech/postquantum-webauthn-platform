import { describe, expect, it } from 'vitest';

import {
  applyJsonEditorAutoIndent,
  applyTabIndentation,
  wrapSelectionWithPair,
} from '../../../../frontend/static/scripts/advanced/editor/json-editing.js';

// The JSON editor's own edits, on a value and a selection with no textarea
// (advanced/editor/json-editing.js): what both UIs' editors do on a key.

/** A textarea's state: the text, and the selection given by a `|` for the caret or `«…»` around a selection. */
function edit(marked) {
  const start = marked.includes('«') ? marked.indexOf('«') : marked.indexOf('|');
  const value = marked.replace(/[«»|]/g, '');
  const end = marked.includes('»') ? marked.indexOf('»') - 1 : start;
  return { value, selectionStart: start, selectionEnd: end };
}

/** The state written back the same way. */
function marked({ value, selectionStart, selectionEnd }) {
  if (selectionStart === selectionEnd) return `${value.slice(0, selectionStart)}|${value.slice(selectionStart)}`;
  return `${value.slice(0, selectionStart)}«${value.slice(selectionStart, selectionEnd)}»${value.slice(selectionEnd)}`;
}

function after(action, text, ...args) {
  const state = edit(text);
  action(state, ...args);
  return marked(state);
}

describe('{ and [', () => {
  it('wrap the selection, which stays selected inside the pair', () => {
    expect(after(wrapSelectionWithPair, '"a": «[1]»', '{', '}')).toBe('"a": {«[1]»}');
  });

  it('insert the pair with the caret between', () => {
    expect(after(wrapSelectionWithPair, '"a": |', '[', ']')).toBe('"a": [|]');
  });
});

describe('Enter', () => {
  it('keeps the line\'s indent', () => {
    expect(after(applyJsonEditorAutoIndent, '  "a": 1,|')).toBe('  "a": 1,\n  |');
  });

  it('indents once more after an opener', () => {
    expect(after(applyJsonEditorAutoIndent, '  "a": [|\n  1')).toBe('  "a": [\n    |\n  1');
  });

  it('puts the closer right after the caret on its own line, the caret indented between', () => {
    expect(after(applyJsonEditorAutoIndent, '  "a": {|}')).toBe('  "a": {\n    |\n  }');
  });

  it('dedents a blank line that a closer follows', () => {
    expect(after(applyJsonEditorAutoIndent, '    |]')).toBe('    \n  |]');
    expect(after(applyJsonEditorAutoIndent, ' |}')).toBe(' \n|}');
  });

  it('replaces the selection', () => {
    expect(after(applyJsonEditorAutoIndent, '"a"«, "b"»')).toBe('"a"\n|');
  });
});

describe('Tab and Shift+Tab', () => {
  it('indent and dedent each line of a selection over several lines', () => {
    expect(after(applyTabIndentation, '«a\nb»', false)).toBe('«  a\n  b»');
    expect(after(applyTabIndentation, '«  a\n\tb\n c\nd»', true)).toBe('«a\nb\nc\nd»');
  });

  it('insert two spaces in place of the selection on one line', () => {
    expect(after(applyTabIndentation, 'a«bc»d', false)).toBe('a  |d');
  });

  it('dedent the caret\'s line by two spaces, a tab, or the spaces before the caret', () => {
    expect(after(applyTabIndentation, '{\n    a|', true)).toBe('{\n  a|');
    expect(after(applyTabIndentation, '\ta|', true)).toBe('a|');
    expect(after(applyTabIndentation, ' |a', true)).toBe('|a');
  });

  it('leave a line with nothing to dedent as it is', () => {
    expect(after(applyTabIndentation, 'a|b', true)).toBe('a|b');
  });
});
