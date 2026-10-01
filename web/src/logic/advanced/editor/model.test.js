import { describe, expect, it } from 'vitest';

import {
  EDITOR_TEXT,
  editorTitle,
  locateJsonSyntaxError,
  readEditedRequest,
  requestText,
  topLevelExtras,
  validationFailedText,
  sortObjectKeys,
} from './model.js';
import { buildCreationOptions, registrationDefaults } from '../registration/request.js';

// The JSON editor with no page (advanced/editor/model.js).

const REQUEST = buildCreationOptions(
  { ...registrationDefaults(), userId: 'abcd', userName: 'alice', displayName: 'alice', challenge: '00112233445566778899aabbccddeeff' },
  { rpName: 'FIDO2/WebAuthn PQC Developer Tools', hostname: 'localhost' },
);

describe('the editor\'s words', () => {
  it('title it by the request it holds', () => {
    expect(editorTitle('registration')).toBe('JSON Editor (CredentialCreationOptions)');
    expect(editorTitle('authentication')).toBe('JSON Editor (CredentialRequestOptions)');
    expect(editorTitle(undefined)).toBe(EDITOR_TEXT.title);
  });

  it('say why an edit failed', () => {
    expect(validationFailedText('publicKey.timeout must be zero or greater.')).toBe(
      'JSON validation failed: publicKey.timeout must be zero or greater.',
    );
    expect([EDITOR_TEXT.saved, EDITOR_TEXT.reset]).toEqual(['JSON changes saved successfully!', 'JSON editor reset to current settings.']);
  });
});

describe('a request as the editor writes it', () => {
  it('sorts every object\'s keys and indents by two spaces', () => {
    expect(requestText({ publicKey: { timeout: 5, challenge: { $hex: '00' } }, extra: [2, 1] })).toBe(
      '{\n  "extra": [\n    2,\n    1\n  ],\n  "publicKey": {\n    "challenge": {\n      "$hex": "00"\n    },\n    "timeout": 5\n  }\n}',
    );
  });
});

describe('the keys an edit holds beside publicKey', () => {
  it('are kept apart from it', () => {
    expect(topLevelExtras({ publicKey: {}, note: 'mine', extra: { a: 1 } })).toEqual({ note: 'mine', extra: { a: 1 } });
  });

  it('are none for an edit that is not an object', () => {
    expect([topLevelExtras(null), topLevelExtras([1])]).toEqual([{}, {}]);
  });
});

describe('where text stops being JSON', () => {
  it('is nowhere in JSON', () => {
    const texts = [
      requestText(REQUEST),
      ' { } ',
      '[]',
      '[1, -2.5e+3, 0, true, false, null, "a\\"b\\\\c\\/d\\b\\f\\n\\r\\t\\u00e9"]',
      '{"a": {"b": [{}, []]}}',
      '"text"',
      '\t\n\r 7 \n',
    ];
    for (const text of texts) {
      expect(locateJsonSyntaxError(text)).toBeNull();
    }
  });

  it('is the character that cannot follow, with its line and column', () => {
    expect(locateJsonSyntaxError('{\n  "a": 1\n  "b": 2\n}')).toEqual({ offset: 13, line: 3, column: 3 });
    expect(locateJsonSyntaxError('{"a": [1, 2,]}')).toEqual({ offset: 12, line: 1, column: 13 });
    expect(locateJsonSyntaxError('{"a" 1}')).toEqual({ offset: 5, line: 1, column: 6 });
    expect(locateJsonSyntaxError('{a: 1}')).toEqual({ offset: 1, line: 1, column: 2 });
    expect(locateJsonSyntaxError('[1 2]')).toEqual({ offset: 3, line: 1, column: 4 });
  });

  it('is a value that is none of JSON\'s', () => {
    expect(locateJsonSyntaxError('[tru]')).toEqual({ offset: 1, line: 1, column: 2 });
    expect(locateJsonSyntaxError('[01]')).toEqual({ offset: 2, line: 1, column: 3 });
    expect(locateJsonSyntaxError("{'a': 1}")).toEqual({ offset: 1, line: 1, column: 2 });
  });

  it('is in a string, at a bad escape or a control character', () => {
    expect(locateJsonSyntaxError('"a\\x"')).toEqual({ offset: 2, line: 1, column: 3 });
    expect(locateJsonSyntaxError('"\\u12g4"')).toEqual({ offset: 1, line: 1, column: 2 });
    expect(locateJsonSyntaxError('"a\tb"')).toEqual({ offset: 2, line: 1, column: 3 });
  });

  it('is the end when the text ends too soon, or empty', () => {
    expect(locateJsonSyntaxError('{"a": [1')).toEqual({ offset: 8, line: 1, column: 9 });
    expect(locateJsonSyntaxError('"open')).toEqual({ offset: 5, line: 1, column: 6 });
    expect(locateJsonSyntaxError('')).toEqual({ offset: 0, line: 1, column: 1 });
  });

  it('is found exactly when the browser\'s parser refuses the text', () => {
    const json = '{"a": [1, "b\\n\\u00e9", true, null], "c": {"d": -1.5e3, "e": ""}}';
    const parses = (text) => {
      try {
        JSON.parse(text);
        return true;
      } catch {
        return false;
      }
    };
    for (let index = 0; index <= json.length; index += 1) {
      for (const text of [json.slice(0, index) + json.slice(index + 1), json.slice(0, index), `${json.slice(0, index)}x${json.slice(index)}`]) {
        expect(locateJsonSyntaxError(text) === null, text).toBe(parses(text));
      }
    }
  });

  it('is what follows a whole value', () => {
    expect(locateJsonSyntaxError('{}\n}')).toEqual({ offset: 3, line: 2, column: 1 });
  });
});

describe('an edit of the editor', () => {
  it('that does not parse says why and where', () => {
    const edit = readEditedRequest('{\n  "publicKey": {\n    "timeout": 1,\n  }\n}', 'registration');
    expect(edit.status).toBe('unparsed');
    expect(edit.message).toMatch(/^JSON validation failed: /);
    expect(edit.location).toEqual({ offset: 39, line: 4, column: 3 });
  });

  it('that the form cannot follow says the structure\'s sentence, or the first check it fails, and keeps what parsed', () => {
    expect(readEditedRequest('', 'registration')).toEqual({
      status: 'refused',
      root: {},
      message: 'JSON validation failed: Invalid JSON structure: Missing "publicKey" object.',
    });
    const refused = readEditedRequest(requestText({ ...REQUEST, publicKey: { ...REQUEST.publicKey, timeout: -1 } }), 'registration');
    expect(refused).toMatchObject({ status: 'refused', message: 'JSON validation failed: publicKey.timeout must be zero or greater.' });
    expect(refused.root.publicKey.timeout).toBe(-1);
  });

  it('that is not an object, or holds no publicKey object, is refused with the structure\'s sentence', () => {
    ['[]', '1', 'null', '"text"'].forEach((text) => {
      expect(readEditedRequest(text, 'registration').message).toBe('JSON validation failed: Invalid JSON structure.');
    });
    ['{"publicKey": 1}', '{"publicKey": null}', '{"extra": 1}'].forEach((text) => {
      expect(readEditedRequest(text, 'registration').message).toBe(
        'JSON validation failed: Invalid JSON structure: Missing "publicKey" object.',
      );
    });
  });

  it('that the form can follow is the request as parsed', () => {
    const text = requestText({ ...REQUEST, note: 'mine' });
    expect(readEditedRequest(text, 'registration')).toEqual({ status: 'accepted', root: JSON.parse(text) });
  });

  it('is checked as the scope\'s request', () => {
    const edit = readEditedRequest('{"publicKey": {"challenge": {"$hex": "00"}, "userVerification": "always"}}', 'authentication');
    expect(edit).toMatchObject({ status: 'refused', message: 'JSON validation failed: publicKey.userVerification must be required, preferred, or discouraged.' });
    expect(readEditedRequest('{"publicKey": {"challenge": {"$hex": "00"}}}', 'authentication').status).toBe('accepted');
  });
});

describe('sortObjectKeys', () => {
  it('orders every object\'s keys, in nested objects and lists too', () => {
    expect(sortObjectKeys({ z: 1, a: { c: 3, b: 2 } })).toEqual({ a: { b: 2, c: 3 }, z: 1 });
    expect(sortObjectKeys([{ z: 1, a: 2 }, { b: { d: 4, c: 3 } }])).toEqual([{ a: 2, z: 1 }, { b: { c: 3, d: 4 } }]);
  });

  it('leaves a value that is not a plain object as it is', () => {
    expect(sortObjectKeys('text')).toBe('text');
  });
});
