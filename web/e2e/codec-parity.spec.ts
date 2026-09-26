import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type Difference, type ExpectedDifference, compareShownText, describeDifferences, readShownText } from './parity';

// The text the current Codec shows and the text /beta shows, for the same inputs
// from tests/app/codec_corpus.py, compared word for word per section once
// layout and separators are set aside (parity.ts). Every difference must be one
// listed below, with its reason.

const repo = resolve(import.meta.dirname, '..', '..');
const python = process.env.E2E_PYTHON ?? join(repo, '.venv', 'bin', 'python');

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

function corpusHex(names: readonly string[]): Record<string, string> {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: '1' };
  delete env.CHARACTERIZATION_WRITE;
  const script = [
    'import json, sys',
    'from tests.app.codec_corpus import corpus',
    'items = corpus()',
    'missing = [name for name in sys.argv[1:] if name not in items]',
    "if missing: sys.exit('not in tests/app/codec_corpus.py: ' + ', '.join(missing))",
    'print(json.dumps({name: items[name].hex() for name in sys.argv[1:]}))',
  ].join('\n');
  return JSON.parse(execFileSync(python, ['-B', '-c', script, ...new Set(names)], { cwd: repo, env, encoding: 'utf8' }));
}

async function legacyText(page: Page, input: string, lenient: boolean) {
  await page.goto('/');
  await expect(page.locator('body')).toHaveClass(/app-loaded/);
  await page.locator('.nav-tab[data-tab="codec"]').first().click();
  await page.locator('#decoder-input').fill(input);
  if (lenient) await page.locator('#decoder-lenient').check();
  await page.locator('#decoder-submit').click();
  const output = page.locator('#decoder-output.is-visible');
  await expect(output).toBeVisible();
  return readShownText(output, '.decoder-section h4');
}

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
  let hex: Record<string, string> = {};
  const found: Record<string, Difference[]> = {};

  test.beforeAll(() => {
    hex = corpusHex(INPUTS.map((input) => input.name));
  });

  test.afterAll(async ({}, testInfo) => {
    const report = Object.entries(found).flatMap(([label, differences]) => [`${label}:`, ...describeDifferences(differences).map((line) => `  ${line}`)]);
    await testInfo.attach('codec-parity.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  const cases = [
    ...INPUTS.map((input) => ({ label: `${input.name}${'before' in input ? ` (${input.note})` : ''}`, input, lenient: false })),
    { label: `lenient ${LENIENT.hex}`, input: null, lenient: true },
  ];

  for (const { label, input, lenient } of cases) {
    test(label, async ({ page, watch }) => {
      // Without the MDS snapshot (CI has none) the current UI's explorer gets a 404, the documented fallback.
      watch.allow(/^console error: Failed to load resource: .* 404 .*\/fido-mds3\.explorer(\.full)?\.json\)$/);
      const text = input ? `${'before' in input ? input.before : ''}${hex[input.name]}${'after' in input ? input.after : ''}` : LENIENT.hex;

      const legacy = await legacyText(page, text, lenient);
      const beta = await betaText(page, text, lenient);
      expect(legacy.length, 'the current UI showed sections').toBeGreaterThan(1);

      const differences = compareShownText(legacy, beta, EXPECTED);
      found[label] = differences;
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    });
  }
});
