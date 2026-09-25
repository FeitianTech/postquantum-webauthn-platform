import { describe, expect, it } from 'vitest';

import {
  badgesFor,
  classifyCodecValue,
  codecEdnText,
  codecExpandedJson,
} from '../../../frontend/static/scripts/decoder/codec/values.js';

describe('codec values', () => {
  it('shows null, undefined and empty containers as muted text', () => {
    expect(classifyCodecValue(null)).toEqual({ kind: 'empty', text: 'null' });
    expect(classifyCodecValue(undefined)).toEqual({ kind: 'empty', text: 'undefined' });
    expect(classifyCodecValue([])).toEqual({ kind: 'empty', text: '[]' });
    expect(classifyCodecValue({})).toEqual({ kind: 'empty', text: '{}' });
  });

  it('keeps a string of up to 80 characters on one line, and a longer or multi-line one as a block', () => {
    expect(classifyCodecValue('a'.repeat(80))).toEqual({ kind: 'inline', text: 'a'.repeat(80) });
    expect(classifyCodecValue('a'.repeat(81))).toEqual({ kind: 'block', text: 'a'.repeat(81) });
    expect(classifyCodecValue('one\ntwo')).toEqual({ kind: 'block', text: 'one\ntwo' });
  });

  it('shows numbers, booleans and anything else as their text', () => {
    expect(classifyCodecValue(-7)).toEqual({ kind: 'primitive', text: '-7' });
    expect(classifyCodecValue(false)).toEqual({ kind: 'primitive', text: 'false' });
    expect(classifyCodecValue(10n)).toEqual({ kind: 'primitive', text: '10' });
  });

  it('lists an array\'s items for the same rules', () => {
    expect(classifyCodecValue([1, 'a'])).toEqual({ kind: 'list', items: [1, 'a'] });
  });

  it('labels a map\'s keys, and puts the interpretation badges before them', () => {
    const view = classifyCodecValue({ fmt: 'packed', '-1': 1, known: false, verification: 'Not verified: shown only' });
    expect(view.kind).toBe('map');
    expect(view.entries.map((entry) => entry.label)).toEqual(['Format', '-1', 'Known', 'Verification']);
    expect(view.entries[0]).toEqual({ key: 'fmt', label: 'Format', value: 'packed' });
    expect(view.badges).toEqual([['unknown', 'Unknown'], ['not-verified', 'Not verified']]);
  });

  it('badges a deprecated value, whether the server says true or why', () => {
    expect(badgesFor({ deprecated: true })).toEqual([['deprecated', 'Deprecated']]);
    expect(badgesFor({ deprecated: 'replaced by packed' })).toEqual([['deprecated', 'Deprecated']]);
    expect(badgesFor({ deprecated: false, known: true, verification: 'verified' })).toEqual([]);
  });

  it('writes a top-level expandedJson under "decoded json", or says it cannot', () => {
    expect(codecExpandedJson({ a: 1 })).toBe('{\n  "decoded json": {\n    "a": 1\n  }\n}');
    expect(codecExpandedJson(undefined)).toBe('{\n  "decoded json": null\n}');
    const loop = {};
    loop.self = loop;
    expect(codecExpandedJson(loop)).toBe('Unable to render expanded JSON');
  });

  it('shows EDN as the decoder wrote it', () => {
    expect(codecEdnText('{1: "a"}')).toBe('{1: "a"}');
    expect(codecEdnText({ not: 'text' })).toBe('{"not":"text"}');
  });
});
