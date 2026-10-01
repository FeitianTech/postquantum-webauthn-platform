import { describe, expect, it } from 'vitest';

import { stringifyAuthenticatorRawData } from './raw-stringify.js';

// The raw view's text (mds/raw-stringify.js).

describe('the raw view\'s text', () => {
  it('is JSON indented by four spaces', () => {
    expect(stringifyAuthenticatorRawData({ a: [1, { b: 'c' }] })).toBe('{\n    "a": [\n        1,\n        {\n            "b": "c"\n        }\n    ]\n}');
  });

  it('writes out what JSON cannot: big integers, maps, sets, bytes and cycles', () => {
    const cycle = { name: 'loop' };
    cycle.self = cycle;
    const bytes = new Uint8Array([9, 1, 2, 3]).subarray(1);
    const value = {
      big: 12345678901234567890n,
      map: new Map([['k', 1]]),
      set: new Set(['a', 'b']),
      buffer: new Uint8Array([4, 5]).buffer,
      view: bytes,
      data: new DataView(new ArrayBuffer(1)),
      cycle,
    };
    expect(JSON.parse(stringifyAuthenticatorRawData(value))).toEqual({
      big: '12345678901234567890',
      map: { k: 1 },
      set: ['a', 'b'],
      buffer: [4, 5],
      view: [1, 2, 3],
      data: [0],
      cycle: { name: 'loop', self: '[Circular]' },
    });
  });

  it('writes a line per key when JSON cannot write the value at all', () => {
    const refuses = () => {
      throw new Error('no JSON');
    };
    const noString = Object.assign(() => 1, { toJSON: refuses, [Symbol.toPrimitive]: refuses });
    const noJson = Object.assign(() => 2, { toJSON: refuses });
    const value = {
      toJSON: refuses,
      text: 'a "quoted" word',
      nothing: undefined,
      empty: null,
      count: 3,
      big: 4n,
      yes: true,
      no: false,
      symbol: Symbol('s'),
      noJson,
      noString,
      emptyList: [],
      emptyMap: {},
      list: [1, [2, [], {}], { inner: 'x' }],
      nested: { deeper: { leaf: 'y' } },
    };
    expect(stringifyAuthenticatorRawData(value).split('\n')).toEqual([
      'toJSON: undefined',
      'text: "a \\"quoted\\" word"',
      'nothing: undefined',
      'empty: null',
      'count: 3',
      'big: 4',
      'yes: true',
      'no: false',
      'symbol: undefined',
      `noJson: ${String(noJson)}`,
      'noString: ',
      'emptyList:',
      '    []',
      'emptyMap:',
      '    {}',
      'list:',
      '    1',
      '        2',
      '        []',
      '        {}',
      // A map inside a list is written at the list's own depth, as it always was.
      '    inner: "x"',
      'nested:',
      '    deeper:',
      '        leaf: "y"',
    ]);
    expect(stringifyAuthenticatorRawData([noJson, [], {}]).split('\n')).toEqual([`    ${String(noJson)}`, '    []', '    {}']);
    expect(stringifyAuthenticatorRawData(noJson)).toBe(String(noJson));
  });
});
