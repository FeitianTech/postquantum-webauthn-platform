import { describe, expect, it } from 'vitest';

import {
  CODEC_LENIENT_NOTE,
  CODEC_NO_DECODED_DATA,
  CODEC_NO_STRUCTURED_DATA,
  codecFindingParts,
  codecFindingsHeading,
  codecSections,
  describeCodecResult,
} from '../../../frontend/static/scripts/decoder/codec/result.js';

const keys = (sections) => sections.map((section) => section.key);

describe('codec result: sections', () => {
  it('has none without data, and one headed by the type for data that is not a map', () => {
    expect(codecSections('JSON', undefined)).toEqual([]);
    expect(codecSections('Number', 5)).toEqual([{ key: 'Number', label: 'Number', kind: 'value', value: 5 }]);
    expect(codecSections(undefined, null)).toEqual([{ key: 'Data', label: 'Data', kind: 'value', value: null }]);
    expect(codecSections('', [1])).toEqual([{ key: 'Data', label: 'Data', kind: 'value', value: [1] }]);
  });

  it('puts a CBOR answer\'s sections in the panel\'s order, then the rest in the answer\'s', () => {
    const data = { edn: '{}', extra: 1, ctap: {}, decodedValue: {}, getInfoDecoded: {}, ctapDecoded: {}, expandedJson: {} };
    const sections = codecSections('CBOR (SUCCESS status; GetInfo response)', data);
    expect(keys(sections)).toEqual(['ctapDecoded', 'getInfoDecoded', 'expandedJson', 'decodedValue', 'ctap', 'edn', 'extra']);
    expect(sections.find((section) => section.key === 'edn')).toMatchObject({ kind: 'edn', label: 'EDN (exact bytes)' });
    expect(sections.find((section) => section.key === 'expandedJson')).toMatchObject({ kind: 'expandedJson', label: 'Expanded JSON' });
    expect(sections.find((section) => section.key === 'ctap')).toMatchObject({ kind: 'value', label: 'CTAP metadata' });
  });

  it('orders every other known type', () => {
    expect(keys(codecSections('PublicKeyCredential', {
      responseDetails: 1, extensionsDecoded: 1, clientExtensionResults: 1, clientDataJSON: 1,
      authenticatorData: 1, attestationStatementDecoded: 1, attestationObject: 1, credential: 1,
    }))).toEqual([
      'credential', 'attestationObject', 'attestationStatementDecoded', 'authenticatorData',
      'clientDataJSON', 'clientExtensionResults', 'extensionsDecoded', 'responseDetails',
    ]);
    expect(keys(codecSections('Attestation object', {
      edn: 1, extensions: 1, extensionsDecoded: 1, authenticatorData: 1, attestationStatementDecoded: 1, attestationObject: 1,
    }))).toEqual(['attestationObject', 'attestationStatementDecoded', 'authenticatorData', 'extensionsDecoded', 'extensions', 'edn']);
    expect(keys(codecSections('Authenticator data', { flags: 1, authenticatorData: 1 }))).toEqual(['authenticatorData', 'flags']);
    expect(keys(codecSections('WebAuthn client data', { type: 1, clientDataJSON: 1 }))).toEqual(['clientDataJSON', 'type']);
    expect(keys(codecSections('X.509 certificate', { certificates: 1, parsedX5c: 1, pem: 1, raw: 1 })))
      .toEqual(['raw', 'pem', 'parsedX5c', 'certificates']);
  });

  it('keeps the answer\'s order for a type it has no order for, even one named like an object property', () => {
    expect(keys(codecSections('JSON', { json: 1, b: 2 }))).toEqual(['json', 'b']);
    expect(keys(codecSections('constructor (x)', { b: 1, a: 2 }))).toEqual(['b', 'a']);
    expect(keys(codecSections(42, { b: 1, a: 2 }))).toEqual(['b', 'a']);
  });
});

describe('codec result: findings', () => {
  it('counts them', () => {
    expect(codecFindingsHeading(1)).toBe('1 finding');
    expect(codecFindingsHeading(3)).toBe('3 findings');
  });

  it('gives a finding\'s parts and the panel\'s one line for it', () => {
    expect(codecFindingParts({
      source: 'response.clientDataJSON', offset: 8, path: '${1}', message: 'map key 1 appears twice', category: 'canonical',
    })).toEqual({
      source: 'response.clientDataJSON',
      offset: 'offset 8',
      path: '${1}',
      message: 'map key 1 appears twice',
      category: 'canonical',
      line: 'response.clientDataJSON: offset 8 · ${1} — map key 1 appears twice',
    });
  });

  it('shows a finding in JSON by its path alone, and tolerates missing fields', () => {
    expect(codecFindingParts({ offset: null, path: '${"a"}', message: 'repeats' }).line).toBe('${"a"} — repeats');
    expect(codecFindingParts({ offset: 1.5 })).toEqual({
      source: null, offset: null, path: '', message: '', category: null, line: ' — ',
    });
    expect(codecFindingParts(null).line).toBe(' — ');
  });
});

describe('codec result: the whole output', () => {
  it('says there is nothing to show for an answer that is not an object', () => {
    expect(describeCodecResult(null)).toEqual({ empty: CODEC_NO_DECODED_DATA });
    expect(describeCodecResult('text', 'encode')).toEqual({ empty: 'No decoded data available.' });
  });

  it('describes a decoded answer: pill, type, lenient note, findings and sections', () => {
    const view = describeCodecResult({
      success: true,
      type: 'CBOR',
      decodeMode: 'lenient',
      data: { decodedValue: { 1: 'c' }, edn: '{1: "a", 1: "c"}' },
      findings: [
        { category: 'rendering', offset: 0, path: '$', message: 'keys collide' },
        { category: 'canonical', offset: 8, path: '${1}', message: 'map key 1 appears twice' },
      ],
      malformed: ['map key 1 appears twice'],
    });
    expect(view).toMatchObject({
      empty: null,
      success: true,
      pill: 'Success',
      type: 'CBOR',
      lenientNote: CODEC_LENIENT_NOTE,
      findingsHeading: '2 findings',
      malformed: null,
      encoded: null,
      noSections: null,
    });
    expect(view.findings.map((finding) => [finding.category, finding.malformed])).toEqual([['rendering', false], ['canonical', true]]);
    expect(keys(view.sections)).toEqual(['decodedValue', 'edn']);
  });

  it('falls back to "Decoded data" and "Error", and lists malformed segments only when there are no findings', () => {
    const view = describeCodecResult({ success: false, malformed: ['a', 'b'], findings: 'not a list' });
    expect(view).toMatchObject({
      pill: 'Error', success: false, type: 'Decoded data', lenientNote: null, findingsHeading: null,
      findings: [], malformed: 'Malformed segments: a, b', noSections: CODEC_NO_STRUCTURED_DATA,
    });
    expect(describeCodecResult({ success: true, malformed: 'x' }).malformed).toBeNull();
  });

  it('shows the encoded bytes of an encoder answer in place of its sections', () => {
    const view = describeCodecResult({
      success: true,
      type: 'EDN (encoded)',
      data: { binary: { length: 2, hex: 'a0ff', base64: 'oP8=', encoding: 'hex' } },
      malformed: [],
    }, 'encode');
    expect(view.encoded).toEqual({
      label: 'Encoded output',
      formats: [{ key: 'hex', label: 'Hex', value: 'a0ff' }, { key: 'base64', label: 'Base64', value: 'oP8=' }],
      byteLength: 2,
    });
    expect(view.sections).toEqual([]);
    expect(view.noSections).toBeNull();
  });

  it('shows an encoder answer without bytes as sections', () => {
    const view = describeCodecResult({ success: true, type: 'JSON (encoded)', data: { json: { a: 1 } } }, 'encode');
    expect(view.encoded).toBeNull();
    expect(keys(view.sections)).toEqual(['json']);
  });
});
