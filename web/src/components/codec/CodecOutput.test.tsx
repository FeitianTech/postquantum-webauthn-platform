import { codecSections } from '@legacy/decoder/codec/result.js';
import { formatKey } from '@legacy/decoder/codec/labels.js';
import { render, screen, within } from '@testing-library/react';

import attestationGoldens from '../../../../tests/app/characterization/golden/routes/decoder-attestation-objects.json';
import answers from '@/test/codec-answers.json';

import { CodecOutput } from './CodecOutput';
import type { CodecAnswer, CodecMode } from './model';

type Recorded = { answer: CodecAnswer };
const RECORDED = answers as Record<string, Recorded>;
// The eight attestation objects the characterization tests record (tpm,
// fido-u2f, packed, apple, android-safetynet, android-key, packed, none).
const ATTESTATIONS = (attestationGoldens as { requests: { body: CodecAnswer }[] }).requests.map((request) => request.body);

function show(answer: unknown, mode: CodecMode = 'decode') {
  render(<CodecOutput mode={mode} answer={answer as CodecAnswer} rawOpen={false} onRaw={() => {}} />);
  return screen.getByRole('region', { name: 'Codec Output' });
}

function sectionHeadings(output: HTMLElement) {
  return Array.from(output.querySelectorAll('[data-codec-section] > h4')).map((heading) => heading.textContent);
}

describe('the Codec output over real answers', () => {
  it.each(ATTESTATIONS.map((answer, index) => [index, answer] as const))(
    'shows attestation object %i with every section in the current order and its EDN (CX-X1, CX-X2, CX-N1, CX-P1, CX-P6)',
    (_index, answer) => {
      const output = show(answer);
      const data = answer.data as Record<string, unknown>;
      const expected = codecSections(answer.type, data).map((section: { label: string }) => section.label);
      expect(sectionHeadings(output)).toEqual(expected);
      expect(expected.slice(0, 2)).toEqual(['Attestation object', 'Attestation statement (interpreted)']);
      expect(output.querySelector('[data-role="type"]')).toHaveTextContent('Attestation object');
      expect(output.querySelector('[data-codec-section="edn"] pre')!.textContent).toBe(data.edn);
      // Shown, not verified: the badge says so.
      expect(within(output.querySelector('[data-codec-section="attestationStatementDecoded"]') as HTMLElement).getAllByText('Not verified').length).toBeGreaterThan(0);
    },
  );

  it('shows a duplicate key and two keys that collide as JSON: both findings, with category, offset and path (CX-F1, CX-F2)', () => {
    const output = show(RECORDED['decode-duplicate-and-colliding-keys'].answer);
    const findings = within(output).getByRole('region', { name: '2 findings' });
    const rows = within(findings).getAllByRole('listitem');
    const parts = rows.map((row) => ({
      category: row.querySelector('[data-role="category"]')?.textContent,
      offset: row.querySelector('[data-role="offset"]')?.textContent,
      path: row.querySelector('[data-role="path"]')?.textContent,
    }));
    expect(parts).toEqual([
      { category: 'rendering', offset: 'offset 0', path: '$' },
      { category: 'canonical', offset: 'offset 8', path: '${1}' },
    ]);
    // The one the server also counts as malformed is amber.
    expect(rows[1].querySelector('[data-role="category"]')!.className).toContain('bg-warning-tint');
    expect(rows[0].querySelector('[data-role="category"]')!.className).toContain('bg-surface');
    expect(rows[1].querySelector('[data-role="message"]')).toHaveTextContent('map key 1 appears twice (first at offset 1)');
    expect(output.querySelector('[data-codec-section="edn"] pre')).toHaveTextContent('{1: "a", "1": "b", 1: "c"}');
    expect(sectionHeadings(output)).toEqual(['Decoded value', 'EDN (exact bytes)']);
    // Keys spelled with their type are shown as written.
    expect(within(output.querySelector('[data-codec-section="decodedValue"]') as HTMLElement).getByText('"1" (text)')).toBeInTheDocument();
  });

  it('shows a lenient answer\'s note and its finding by offset and path (CX-O6)', () => {
    const output = show(RECORDED['decode-nan-lenient'].answer);
    expect(output.querySelector('[data-role="lenient-note"]')).toHaveTextContent(
      'Decoded in lenient mode (best effort); skipped items are listed below.',
    );
    const row = within(within(output).getByRole('region', { name: '1 finding' })).getByRole('listitem');
    expect(row.querySelector('[data-role="category"]')).toHaveTextContent('malformed');
    expect(row.querySelector('[data-role="offset"]')).toHaveTextContent('offset 6');
    expect(row.querySelector('[data-role="path"]')).toHaveTextContent('${"a"}');
    expect(sectionHeadings(output)).toEqual(['Json']);
  });

  it('shows a framed getInfo: the CTAP view, its interpretation, the metadata and EDN (CX-P3, CX-P4)', () => {
    const output = show(RECORDED['decode-get-info-framed'].answer);
    expect(output.querySelector('[data-role="type"]')).toHaveTextContent('CBOR (SUCCESS status; GetInfo response)');
    expect(sectionHeadings(output)).toEqual(['CTAP decoded', 'GetInfo (interpreted)', 'CTAP metadata', 'EDN (exact bytes)']);
    const interpreted = output.querySelector('[data-codec-section="getInfoDecoded"]') as HTMLElement;
    expect(within(interpreted).getAllByText('Default when absent').length).toBeGreaterThan(0);
    expect(within(interpreted).getAllByText('Meaning').length).toBeGreaterThan(0);
    const metadata = output.querySelector('[data-codec-section="ctap"]') as HTMLElement;
    expect(within(metadata).getByText('Code (hex)')).toBeInTheDocument();
    expect(within(metadata).getByText('0x00')).toBeInTheDocument();
  });

  it('shows the padding and trailing bytes after a CTAP response (CX-P4)', () => {
    const output = show(RECORDED['decode-make-credential-padded'].answer);
    const metadata = output.querySelector('[data-codec-section="ctap"]') as HTMLElement;
    expect(within(metadata).getByText('Trailing bytes (hex)')).toBeInTheDocument();
    expect(within(metadata).getByText('0000000000')).toBeInTheDocument();
    expect(within(metadata).getByText('Padding bytes (all 00 or ff)')).toBeInTheDocument();
    const trailing = output.querySelector('[data-finding="trailing"]');
    expect(trailing).toHaveTextContent('Trailing 5 byte(s) after CBOR payload');
  });

  it('shows a certificate: Raw, PEM and its details (CX-P6)', () => {
    const answer = RECORDED['decode-certificate'].answer;
    const output = show(answer);
    expect(sectionHeadings(output)).toEqual(['Raw', 'PEM', 'Certificate details']);
    const pem = String((answer.data as Record<string, unknown>).pem);
    expect(output.querySelector('[data-codec-section="pem"] pre')!.textContent).toBe(pem);
    const details = output.querySelector('[data-codec-section="parsedX5c"]') as HTMLElement;
    expect(within(details).getAllByText(formatKey('issuer')).length).toBeGreaterThan(0);
    expect(within(details).getAllByText(formatKey('subject')).length).toBeGreaterThan(0);
  });
});

describe('the Codec output in its other states', () => {
  it('says there is nothing to show for an answer that is not an object (CX-O5)', () => {
    const output = show('not an object');
    expect(output).toHaveTextContent('No decoded data available.');
    expect(output.querySelector('[data-role="outcome"]')).toBeNull();
  });

  it('says Error and "Decoded data" when the answer does, and that there is no section (CX-O3, CX-O4, CX-O7)', () => {
    const output = show({ success: false });
    expect(output.querySelector('[data-role="outcome"]')).toHaveTextContent('Error');
    expect(output.querySelector('[data-role="outcome"]')!.className).toContain('bg-danger-tint');
    expect(output.querySelector('[data-role="type"]')).toHaveTextContent('Decoded data');
    expect(output).toHaveTextContent('No structured data available.');
  });

  it('lists malformed segments when there are no findings, in encode mode too (CX-F4)', () => {
    const output = show({ success: true, type: 'JSON (encoded)', data: { json: { a: 1 } }, malformed: ['one', 'two'] }, 'encode');
    expect(output.querySelector('[data-role="malformed"]')).toHaveTextContent('Malformed segments: one, two');
    expect(sectionHeadings(output)).toEqual(['Json']);
  });

  it('names the field a finding was found in (CX-F2)', () => {
    const output = show({
      success: true,
      type: 'PublicKeyCredential',
      data: {},
      findings: [{ source: 'response.clientDataJSON', offset: null, path: '${"type"}', message: 'object key "type" appears twice' }],
    });
    const row = within(output).getByRole('listitem');
    expect(row.querySelector('[data-role="source"]')).toHaveTextContent('response.clientDataJSON');
    expect(row.querySelector('[data-role="offset"]')).toBeNull();
    expect(row.querySelector('[data-role="category"]')).toBeNull();
    expect(row.querySelector('[data-role="path"]')).toHaveTextContent('${"type"}');
  });

  it('shows a top-level Expanded JSON as a block of JSON (CX-N2)', () => {
    const output = show({ success: true, type: 'CBOR', data: { expandedJson: { a: 1 } } });
    expect(output.querySelector('[data-codec-section="expandedJson"] pre')!.textContent).toBe('{\n  "decoded json": {\n    "a": 1\n  }\n}');
  });

  it('shows the encoded bytes without a byte length when the answer gives none (CX-C3)', () => {
    const output = show({ success: true, type: 'X', data: { binary: { hex: '00' } } }, 'encode');
    expect(output.querySelector('[data-encoded="hex"]')).toHaveTextContent('00');
    expect(output.querySelector('[data-role="byte-length"]')).toBeNull();
  });
});
