import { beforeEach, describe, expect, it } from 'vitest';

import { renderDecodedResult } from '../../../frontend/static/scripts/decoder/codec/render-sections.js';

function render(payload) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  renderDecodedResult(container, payload);
  return container;
}

function headings(container) {
  return Array.from(container.querySelectorAll('.decoder-section > h4, .decoder-section > summary > h4'))
    .map((heading) => heading.textContent);
}

function badges(element) {
  return Array.from(element.querySelectorAll('.decoder-badge')).map((badge) => badge.textContent);
}

describe('decoder sections for getInfo, extensions and attestation formats', () => {
  beforeEach(() => {
    document.body.textContent = '';
  });

  it('shows a getInfo response as sent, with its options explained beside it', () => {
    const container = render({
      success: true,
      type: 'CBOR (SUCCESS status; GetInfo response)',
      data: {
        ctap: { code: 0 },
        getInfoDecoded: {
          '1 (versions)': ['FIDO_2_0'],
          '4 (options)': {
            rk: { value: true, meaning: 'can create discoverable credentials', defaultWhenAbsent: 'false' },
            vendorThing: { value: true, known: false, meaning: 'not an option ID CTAP 2.2 section 6.4 defines' },
          },
        },
        ctapDecoded: {
          getInfoResponse: { '1 (versions)': ['FIDO_2_0'], '4 (options)': { rk: true, vendorThing: true } },
        },
      },
    });

    expect(headings(container)).toEqual(['CTAP decoded', 'GetInfo (interpreted)', 'CTAP metadata']);
    const terms = Array.from(container.querySelectorAll('dt')).map((term) => term.textContent);
    expect(terms).toEqual(expect.arrayContaining(['GetInfo response', 'Default when absent']));
    expect(container.textContent).toContain('can create discoverable credentials');
    expect(badges(container)).toEqual(['Unknown']);
  });

  it('puts the interpreted sections right after the decoded CTAP message', () => {
    const container = render({
      success: true,
      type: 'CBOR (SUCCESS status; MakeCredential response)',
      data: {
        ctap: { code: 0 },
        expandedJson: { fmt: 'packed' },
        extensionsDecoded: [],
        attestationStatementDecoded: { fmt: 'packed' },
        ctapDecoded: { makeCredentialResponse: { '1 (fmt)': 'packed' } },
      },
    });

    expect(headings(container)).toEqual([
      'CTAP decoded',
      'Attestation statement (interpreted)',
      'Extensions (interpreted)',
      'Expanded JSON',
      'CTAP metadata',
    ]);
  });

  it('marks an unknown extension, and keeps it', () => {
    const container = render({
      success: true,
      type: 'Attestation object',
      data: {
        attestationObject: { fmt: 'none' },
        extensionsDecoded: [
          {
            role: 'makeCredential output',
            entries: {
              credProtect: { value: 2, known: true, meaning: 'userVerificationOptionalWithCredentialIDList (0x02)' },
              vendorExt: { value: '0102', known: false, meaning: 'not defined in CTAP 2.2 section 12' },
            },
          },
        ],
      },
    });

    expect(headings(container)).toEqual(['Attestation object', 'Extensions (interpreted)']);
    const terms = Array.from(container.querySelectorAll('dt')).map((term) => term.textContent);
    expect(terms).toEqual(expect.arrayContaining(['Cred Protect', 'Vendor Ext']));
    expect(badges(container)).toEqual(['Unknown']);
  });

  it('says an attestation statement is not verified, and SafetyNet is deprecated', () => {
    const container = render({
      success: true,
      type: 'Attestation object',
      data: {
        attestationStatementDecoded: {
          fmt: 'android-safetynet',
          known: true,
          verification: 'not verified: the decoder shows this statement',
          notChecked: ['the JWS signature'],
          fields: {
            response: {
              verification: 'NOT VERIFIED: the JWS signature is not checked',
              deprecated: 'WebAuthn L3 section 8.5: this format is deprecated',
            },
          },
        },
      },
    });

    const section = container.querySelector('.decoder-section');
    expect(section.querySelector('h4').textContent).toBe('Attestation statement (interpreted)');
    expect(badges(section)).toEqual(['Not verified', 'Not verified', 'Deprecated']);
    expect(container.textContent).toContain('Not checked');
  });

  it('names the PublicKeyCredential field a finding is in', () => {
    const container = render({
      success: true,
      type: 'PublicKeyCredential',
      findings: [
        {
          code: 'parse-error',
          offset: 40,
          path: '$',
          message: 'response.attestationObject does not decode',
          source: 'response.attestationObject',
        },
        { code: 'trailing-bytes', offset: 5, path: '$', message: 'Trailing 1 byte(s)' },
      ],
      data: { attestationObject: { parseError: { offset: 40, path: '$', reason: 'truncated' } } },
    });

    const items = Array.from(container.querySelectorAll('.decoder-findings li')).map((item) => item.textContent);
    expect(items).toEqual([
      'response.attestationObject: offset 40 · $ — response.attestationObject does not decode',
      'offset 5 · $ — Trailing 1 byte(s)',
    ]);
    expect(Array.from(container.querySelectorAll('dt')).map((term) => term.textContent)).toContain('Parse error');
  });

  it('renders interpreted text as text, never as markup', () => {
    const container = render({
      success: true,
      type: 'CBOR',
      findings: [{ offset: 0, path: '$', message: 'x', source: '<img src=x onerror="alert(1)">' }],
      data: {
        extensionsDecoded: [
          {
            entries: {
              '<script>alert(1)</script>': { value: '<b>x</b>', known: false, meaning: '<img src=x onerror="alert(2)">' },
            },
          },
        ],
      },
    });

    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('b')).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(2)">');
  });
});

describe('the EDN view', () => {
  beforeEach(() => {
    document.body.textContent = '';
  });

  it('shows the item as EDN in a closed section after the decoded value', () => {
    const container = render({
      success: true,
      type: 'CBOR',
      data: { edn: '{1: "a", 1: "b"}', decodedValue: { 1: 'b' } },
      findings: [],
      malformed: [],
    });

    expect(headings(container)).toEqual(['Decoded value', 'EDN (exact bytes)']);
    const section = container.querySelector('details.decoder-edn');
    expect(section.open).toBe(false);
    expect(section.querySelector('pre.decoder-edn-text').textContent).toBe('{1: "a", 1: "b"}');
  });

  it('comes after an attestation object\'s interpreted sections', () => {
    const container = render({
      success: true,
      type: 'Attestation object',
      data: { edn: '{"fmt": "none"}', attestationObject: { fmt: 'none' } },
    });

    expect(headings(container)).toEqual(['Attestation object', 'EDN (exact bytes)']);
  });

  it('writes the notation as text, never as markup', () => {
    const container = render({
      success: true,
      type: 'CBOR',
      data: { edn: '"<img src=x onerror=alert(1)>"' },
    });

    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('pre.decoder-edn-text').textContent).toBe('"<img src=x onerror=alert(1)>"');
  });
});

describe('findings without an offset', () => {
  it('shows a JSON finding by its path alone', () => {
    const container = render({
      success: true,
      type: 'JSON',
      data: { json: { a: 2 } },
      findings: [{ code: 'duplicate-json-key', offset: null, path: '${"a"}', message: 'object key "a" appears twice' }],
      malformed: [],
    });

    expect(Array.from(container.querySelectorAll('.decoder-findings li')).map((item) => item.textContent)).toEqual([
      '${"a"} — object key "a" appears twice',
    ]);
  });
});

