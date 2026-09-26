import { readFileSync } from 'node:fs';

import type { Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';

// The Codec at /beta against the real server, under the strict CSP.

type Recorded = { request: { payload: string; format?: string }; answer: { data: { binary: { hex: string } } } };
// The server's answers the unit tests render (tests/app/tooling/test_web_codec_answers.py keeps them current).
const RECORDED: Record<string, Recorded> = JSON.parse(readFileSync(new URL('../src/test/codec-answers.json', import.meta.url), 'utf8'));

// {1: "a", "1": "b", 1: "c"}: key 1 twice, and keys 1 and "1" that read alike as JSON.
const DUPLICATE_AND_COLLIDING = 'a301616161316162016163';
const FAILED_422 = /^console error: Failed to load resource: the server responded with a status of 422 /;

const panel = (page: Page, mode: 'decode' | 'encode') => page.locator(`#codec-mode-panel-${mode}`);

async function openCodec(page: Page) {
  await page.goto('/beta#codec');
  await expect(page.getByRole('tabpanel', { name: 'Codec' })).toBeVisible();
}

async function decode(page: Page, input: string) {
  const decoding = panel(page, 'decode');
  await decoding.getByRole('textbox', { name: 'Input to decode' }).fill(input);
  await decoding.getByRole('button', { name: 'Decode', exact: true }).click();
  return decoding;
}

async function encode(page: Page, format: string, input: string) {
  await page.getByRole('tab', { name: 'Encode' }).click();
  const encoding = panel(page, 'encode');
  await encoding.getByRole('combobox', { name: 'Encoding format' }).selectOption(format);
  await encoding.getByRole('textbox', { name: 'Input to encode' }).fill(input);
  await encoding.getByRole('button', { name: 'Encode', exact: true }).click();
  return encoding;
}

test.describe('the Codec at /beta', () => {
  test('decodes a map with a repeated key and two keys that collide: both findings, and the EDN', async ({ page }) => {
    await openCodec(page);
    await expect(panel(page, 'decode').getByRole('region', { name: 'Supported Inputs' })).toBeVisible();
    const decoding = await decode(page, DUPLICATE_AND_COLLIDING);

    const output = decoding.getByRole('region', { name: 'Codec Output' });
    await expect(output.locator('[data-role="outcome"]')).toHaveText('Success✓');
    await expect(output.locator('[data-role="type"]')).toHaveText('CBOR');
    const findings = output.getByRole('region', { name: '2 findings' });
    await expect(findings.locator('[data-role="category"]')).toHaveText(['rendering', 'canonical']);
    await expect(findings.locator('[data-role="offset"]')).toHaveText(['offset 0', 'offset 8']);
    await expect(findings.locator('[data-role="path"]')).toHaveText(['$', '${1}']);
    await expect(findings.locator('[data-role="message"]').nth(1)).toContainText('map key 1 appears twice (first at offset 1)');
    await expect(output.locator('[data-codec-section="edn"] pre')).toHaveText('{1: "a", "1": "b", 1: "c"}');
    await expect(output.getByRole('button', { name: 'Copy EDN (exact bytes)' })).toBeVisible();
    await expect(panel(page, 'decode').getByRole('region', { name: 'Supported Inputs' })).toHaveCount(0);
    await expect(page.getByText('Response decoded successfully!')).toBeVisible();
  });

  test('refuses {"a": NaN} strictly with its offset and path, and reads it leniently with a finding', async ({ page, watch }) => {
    watch.allow(FAILED_422);
    await openCodec(page);
    const decoding = await decode(page, '{"a": NaN}');

    const alert = decoding.getByRole('alert');
    await expect(alert.locator('[data-role="failure-text"]')).toHaveText(/^Decoding failed: Not JSON at offset 6 \(\$\{"a"\}\): NaN is not JSON/);
    await expect(alert.locator('[data-role="offset"]')).toHaveText('6');
    await expect(alert.locator('[data-role="path"]')).toHaveText('${"a"}');
    await expect(decoding.getByRole('region', { name: 'Codec Output' })).toHaveCount(0);

    await decoding.getByRole('switch', { name: 'Best effort (lenient)' }).click();
    await decoding.getByRole('button', { name: 'Decode', exact: true }).click();
    const output = decoding.getByRole('region', { name: 'Codec Output' });
    await expect(output.locator('[data-role="lenient-note"]')).toHaveText(
      'Decoded in lenient mode (best effort); skipped items are listed below.',
    );
    const finding = output.getByRole('region', { name: '1 finding' }).getByRole('listitem');
    await expect(finding.locator('[data-role="category"]')).toHaveText('malformed');
    await expect(finding.locator('[data-role="offset"]')).toHaveText('offset 6');
    await expect(finding.locator('[data-role="path"]')).toHaveText('${"a"}');
    await expect(decoding.getByRole('alert')).toHaveCount(0);
  });

  test('encodes the EDN it decoded back to exactly the bytes it came from', async ({ page }) => {
    await openCodec(page);
    const decoding = await decode(page, DUPLICATE_AND_COLLIDING);
    const edn = await decoding.locator('[data-codec-section="edn"] pre').textContent();

    const encoding = await encode(page, 'EDN', edn ?? '');
    await expect(encoding.locator('[data-role="type"]')).toHaveText('EDN (encoded)');
    await expect(encoding.locator('[data-encoded="hex"] pre')).toHaveText(DUPLICATE_AND_COLLIDING);
    await expect(encoding.locator('[data-role="byte-length"]')).toHaveText('Byte length: 11');
  });

  for (const [name, format] of [
    ['encode-cbor', 'CBOR (canonical)'],
    ['encode-edn', 'EDN'],
    ['encode-ctap', 'CBOR (CTAP/WebAuthn Data)'],
    ['encode-json', 'JSON (binary)'],
    ['encode-der', 'DER'],
    ['encode-pem', 'PEM'],
    ['encode-cose', 'COSE'],
  ] as const) {
    test(`encodes in ${format}: every view of the bytes and their length`, async ({ page }) => {
      const { request, answer } = RECORDED[name];
      await openCodec(page);
      const encoding = await encode(page, format, request.payload);
      const encoded = encoding.getByRole('region', { name: 'Encoded output' });
      await expect(encoded.locator('[data-encoded="hex"] pre')).toHaveText(answer.data.binary.hex);
      const views = await encoded.locator('[data-encoded]').evaluateAll((blocks) => blocks.map((block) => block.getAttribute('data-encoded')));
      expect(views.slice(0, 4)).toEqual(['hex', 'base64', 'base64url', 'colonHex']);
      await expect(encoded.locator('[data-role="byte-length"]')).toHaveText(`Byte length: ${answer.data.binary.hex.length / 2}`);
    });
  }

  test('opens and closes the raw views: the close button, Escape, and focus back on Raw', async ({ page }) => {
    await openCodec(page);
    const decoding = await decode(page, DUPLICATE_AND_COLLIDING);
    const raw = decoding.getByRole('button', { name: 'Raw' });
    await raw.click();
    const dialog = page.getByRole('dialog', { name: 'Raw Codec Output' });
    await expect(dialog).toBeVisible();
    const text = JSON.parse((await dialog.locator('pre').textContent()) ?? '');
    expect(text.data.edn).toBe('{1: "a", "1": "b", 1: "c"}');
    expect(text.findings).toHaveLength(2);
    await dialog.getByRole('button', { name: 'Close raw codec output' }).click();
    await expect(dialog).toBeHidden();
    await expect(raw).toBeFocused();

    const encoding = await encode(page, 'CBOR (canonical)', '{"a": 1}');
    await encoding.getByRole('button', { name: 'Raw' }).click();
    const encoderDialog = page.getByRole('dialog', { name: 'Raw Encoder Output' });
    await expect(encoderDialog).toContainText('"hex": "a1616101"');
    await page.keyboard.press('Escape');
    await expect(encoderDialog).toBeHidden();
    await expect(encoding.getByRole('button', { name: 'Raw' })).toBeFocused();
  });

  test('puts the input beside the output at 1440 px, one above the other at 375 px, and never scrolls sideways', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openCodec(page);
    await decode(page, DUPLICATE_AND_COLLIDING);
    const input = panel(page, 'decode').locator('[data-codec-column="input"]');
    const output = panel(page, 'decode').locator('[data-codec-column="output"]');
    await expect(output.getByRole('region', { name: 'Codec Output' })).toBeVisible();
    let [left, right] = await Promise.all([input.boundingBox(), output.boundingBox()]);
    expect(right!.x).toBeGreaterThan(left!.x + left!.width);
    expect(Math.abs(right!.y - left!.y)).toBeLessThan(2);
    expect(await greyFills(page, '#nav-panel-codec')).toEqual([]);

    await page.setViewportSize({ width: 375, height: 812 });
    [left, right] = await Promise.all([input.boundingBox(), output.boundingBox()]);
    expect(right!.y).toBeGreaterThan(left!.y + left!.height);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  });
});
