import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type Difference, type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './parity';
import { recorded } from './recorded';

// The text the current Codec showed and the text /beta shows, for the same inputs
// from tests/app/codec_corpus.py, compared word for word per section once
// layout and separators are set aside (parity.ts). Every difference must be one
// listed below, with its reason. The current Codec's side is its recording, which
// keeps the input it was given (recorded.ts).

// Items of the corpus, and how each is sent: some with a CTAP status byte in
// front, one with five bytes of HID padding after it.
const INPUTS = [
  { name: 'literal:a30161616131616218016163', note: 'a repeated key, colliding keys, a non-shortest integer' },
  { name: 'literal:a241010162303102', note: 'a byte-string key and a text key that read alike' },
  { name: 'real_vectors:GET_INFO', note: 'getInfo without its status byte' },
  { name: 'real_vectors:GET_INFO', before: '00', note: 'getInfo as CTAP sends it' },
  { name: 'real_vectors:MAKE_CREDENTIAL_RESPONSE', before: '00', after: '0000000000', note: 'makeCredential with padding' },
  { name: 'captured-attestation-object:tpm', note: 'TPM attestation with its certificates' },
  { name: 'captured-attestation-object:packed', note: 'packed attestation' },
  { name: 'registration:ML-DSA-44:none', note: 'an ML-DSA-44 credential' },
  { name: 'fido2-client:_MC_RESP (not canonical)', note: 'a response that is not canonical' },
  { name: 'literal:5f4101580102ff', note: 'an indefinite-length byte string' },
  { name: 'literal:d80100', note: 'a tag' },
] as const;

// The corpus holds only strictly well-formed items; this one is read leniently.
const LENIENT = { hex: 'a2010203', note: 'CBOR that is not well-formed, read leniently' };

// What /beta shows that the current UI does not, and why.
const EXPECTED: ExpectedDifference[] = [
  {
    only: 'beta',
    token: /^(rendering|canonical|malformed|skipped|trailing|json|limit|input|ambiguous|ctap)$/,
    reason: "the finding's category, shown as a chip (new: the current UI leaves it out)",
  },
];

async function betaText(page: Page, input: string, lenient: boolean) {
  await page.goto('/beta#codec');
  const decoding = page.locator('#codec-mode-panel-decode');
  await decoding.getByRole('textbox', { name: 'Input to decode' }).fill(input);
  if (lenient) await decoding.getByRole('switch', { name: 'Best effort (lenient)' }).click();
  await decoding.getByRole('button', { name: 'Decode', exact: true }).click();
  const output = decoding.locator('[data-codec-output="decode"]');
  await expect(output).toBeVisible();
  return readShownText(output, '[data-codec-section] > h4');
}

test.describe('the Codec reads the same in both UIs', () => {
  const found: Record<string, Difference[]> = {};

  test.afterAll(async ({}, testInfo) => {
    const report = Object.entries(found).flatMap(([label, differences]) => [`${label}:`, ...describeDifferences(differences).map((line) => `  ${line}`)]);
    await testInfo.attach('codec-parity.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  const cases = [
    ...INPUTS.map((input) => `${input.name}${'before' in input ? ` (${input.note})` : ''}`),
    `lenient ${LENIENT.hex}`,
  ];

  for (const label of cases) {
    test(label, async ({ page }) => {
      const current = recorded<{ input: string; lenient: boolean; sections: ShownSection[] }>('codec-parity', label);
      const beta = await betaText(page, current.input, current.lenient);
      expect(current.sections.length, 'the current UI showed sections').toBeGreaterThan(1);

      const differences = compareShownText(current.sections, beta, EXPECTED);
      found[label] = differences;
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    });
  }
});
