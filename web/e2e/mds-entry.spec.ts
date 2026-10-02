import type { Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';

// An MDS entry's page, its certificates and its raw view at /#mds/<entryId>
// in Chromium, against Flask serving the fixture snapshot (tests/fixtures/mds,
// through serve-flask.mjs) and decoding its certificates, under the strict CSP.

const L1 = 'aaguid:f1d0f1d0-0000-4000-8000-000000000001';
const UV = 'aaguid:f1d0f1d0-0000-4000-8000-000000000007';
const SECTIONS = [
  'Overview',
  'Metadata Statement',
  'User Verification Details',
  'Attestation Root Certificates',
  'Authenticator Get Info',
  'Status Reports',
];
const ROOT_SUBJECT = /CN=Fixture FIDO2 Attestation Root/;

const section = (page: Page) => page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
const entryPage = (page: Page) => section(page).locator('[data-mds-entry]');
const certificatePage = (page: Page) => section(page).locator('[data-mds-certificate]');
const part = (page: Page, key: string) => entryPage(page).locator(`[data-section="${key}"]`);
const pageWidth = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth);

async function openEntry(page: Page, entryId = L1) {
  await page.goto(`/#mds/${entryId}`);
  await expect(entryPage(page).getByRole('heading', { level: 3 })).toBeVisible();
}

test.describe('/#mds/<entryId>', () => {
  test('opens an entry from its row, with every section the current page shows', async ({ page }) => {
    await page.goto('/#mds');
    await section(page).locator(`tbody tr[data-entry-id="${L1}"]`).getByRole('link').click();
    await expect(page).toHaveURL(new RegExp(`#mds/${L1}$`));
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeFocused();
    await expect(entryPage(page).getByRole('heading', { level: 4 })).toHaveText(SECTIONS);

    await expect(part(page, 'overview')).toContainText('FIDO Certified L1');
    await expect(part(page, 'metadataStatement').locator('[data-chips="Authentication Algorithms"] li')).toHaveText([
      'secp256r1_ecdsa_sha256_raw',
      'ed25519_eddsa_sha512_raw',
    ]);
    await expect(part(page, 'authenticatorGetInfo')).toContainText('Remaining Discoverable Credentials');
    await expect(part(page, 'authenticatorGetInfo').locator('[data-chips="Options"] li')).toContainText(['uv: false']);
    await expect(part(page, 'statusReports').locator('[data-report]')).toHaveCount(3);
    await expect(part(page, 'statusReports').locator('[data-report]').last()).toContainText(
      'https://fixture.example/certificates/FIDO20020260901001',
    );

    await entryPage(page).getByRole('button', { name: 'Back' }).first().click();
    await expect(page).toHaveURL(/#mds$/);
  });

  test('opens an entry by its URL and again after a reload, with the combinations and their descriptors', async ({ page }) => {
    await openEntry(page, UV);
    await page.reload();
    const combinations = part(page, 'userVerification').locator('[data-combination]');
    await expect(combinations).toHaveCount(10);
    await expect(combinations.first()).toContainText('Base: 10 • Min length: 6 • Max retries: 8 • Block slowdown: 30');
    await expect(combinations.first()).toContainText('Self-attested FAR: 0.00002');
    await expect(combinations.nth(1)).toContainText('Min complexity: 9');
  });

  test('decodes a certificate with its button busy, shows it under the entry, and both Backs return to the button', async ({
    page,
    context,
  }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route('**/api/mds/decode-certificate', async (route) => {
      await held;
      await route.continue();
    });
    await openEntry(page);
    const button = part(page, 'certificates').getByRole('button', { name: 'Certificate 1' });
    await button.click();
    await expect(button).toHaveAttribute('aria-busy', 'true');
    release();

    await expect(certificatePage(page).getByRole('heading', { level: 3, name: ROOT_SUBJECT })).toBeFocused();
    await expect(page).toHaveURL(new RegExp(`#mds/${L1}/certificate/1$`));
    await expect(entryPage(page)).toBeHidden();
    for (const label of ['Subject', 'Issuer', 'Not Before', 'Not After', 'Serial Number', 'Serial Number (Hex)']) {
      await expect(certificatePage(page).locator(`[data-item="${label}"]`)).toBeVisible();
    }
    await expect(certificatePage(page).getByRole('heading', { level: 4 })).toHaveText(['Public Key', 'Signature', 'Raw', 'Decoded Output']);
    await expect(certificatePage(page).locator('pre').last()).toContainText('Version: 3');

    await certificatePage(page).getByRole('button', { name: 'Copy raw certificate' }).click();
    const raw = await page.evaluate(() => navigator.clipboard.readText());
    expect(raw).toMatch(/^MII[A-Za-z0-9+/=]+$/);

    await certificatePage(page).getByRole('button', { name: 'Back' }).first().click();
    await expect(page).toHaveURL(new RegExp(`#mds/${L1}$`));
    await expect(button).toBeFocused();

    await button.click();
    await expect(certificatePage(page).getByRole('heading', { level: 3, name: ROOT_SUBJECT })).toBeVisible();
    await page.goBack();
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
    await expect(button).toBeFocused();
  });

  test('decodes a certificate a link or a reload opens', async ({ page }) => {
    await page.goto(`/#mds/${L1}/certificate/1`);
    await expect(certificatePage(page).getByRole('heading', { level: 3, name: ROOT_SUBJECT })).toBeVisible();
    await page.reload();
    await expect(certificatePage(page).getByRole('heading', { level: 3, name: ROOT_SUBJECT })).toBeVisible();
    await certificatePage(page).getByRole('button', { name: 'Back' }).first().click();
    await expect(page).toHaveURL(new RegExp(`#mds/${L1}$`));
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
  });

  test('shows the raw view: the JSON copied and saved as a file, Escape and focus back on Raw', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await openEntry(page);
    const rawButton = entryPage(page).getByRole('button', { name: 'Raw' }).last();
    await rawButton.click();
    const dialog = page.getByRole('dialog', { name: 'Fixture Security Key L1 – Authenticator Raw Data' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(`AAGUID: ${L1.slice('aaguid:'.length)} • FIDO2`);

    await dialog.getByRole('button', { name: 'Copy Raw authenticator metadata' }).click();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    const raw = JSON.parse(copied);
    expect(raw.aaguid).toBe(L1.slice('aaguid:'.length));
    expect(raw.metadataStatement.attestationRootCertificates).toHaveLength(1);
    expect(copied).toContain('\n    "metadataStatement": {\n        ');

    const [download] = await Promise.all([page.waitForEvent('download'), dialog.getByRole('button', { name: 'Download JSON' }).click()]);
    expect(download.suggestedFilename()).toBe('aaguid-f1d0f1d0-0000-4000-8000-000000000001.json');
    const chunks: Buffer[] = [];
    for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
    expect(Buffer.concat(chunks).toString('utf8')).toBe(copied);

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(rawButton).toBeFocused();
  });

  test('keeps a condensed header in view while the entry scrolls, with Back and Raw', async ({ page }) => {
    await openEntry(page);
    const bar = page.locator('[data-condensed-header]').first();
    await expect(bar).toBeHidden();
    await page.mouse.wheel(0, 900);
    await expect(bar).toBeVisible();
    const shellBottom = (await page.locator('[data-shell-header]').boundingBox())!;
    const barBox = (await bar.boundingBox())!;
    expect(Math.abs(barBox.y - (shellBottom.y + shellBottom.height))).toBeLessThanOrEqual(1);
    await expect(bar).toContainText('Fixture Security Key L1');
    await bar.getByRole('button', { name: 'Back' }).click();
    await expect(page).toHaveURL(/#mds$/);
  });

  test('fits a phone: no sideways scroll on the entry, the certificate or the raw view, and no grey fill', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await openEntry(page);
    expect(await pageWidth(page)).toBeLessThanOrEqual(375);
    for (const cell of await part(page, 'statusReports').getByRole('cell').all()) {
      const box = (await cell.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(375);
    }
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);

    await entryPage(page).getByRole('button', { name: 'Raw' }).last().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    expect(await pageWidth(page)).toBeLessThanOrEqual(375);
    await page.keyboard.press('Escape');

    await part(page, 'certificates').getByRole('button', { name: 'Certificate 1' }).click();
    await expect(certificatePage(page).getByRole('heading', { level: 3 })).toBeVisible();
    expect(await pageWidth(page)).toBeLessThanOrEqual(375);
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);
  });
});

test.describe('the link to an AAGUID\'s MDS entry', () => {
  test('opens a listed entry by its URL', async ({ page }) => {
    await page.goto('/#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000002');
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Fixture Security Key L2' })).toBeVisible();
  });

  test('asks the server for an entry the list does not hold', async ({ page }) => {
    // The list this session loads leaves out Fixture Security Key L1.
    for (const pattern of ['**/fido-mds3.explorer.full.json*', '**/api/mds/metadata/explorer/full']) {
      await page.route(pattern, async (route) => {
        const response = await route.fetch();
        const snapshot = await response.json();
        snapshot.entries = snapshot.entries.filter((entry: { entryId: string }) => entry.entryId !== L1);
        await route.fulfill({ response, json: snapshot });
      });
    }
    const resolved = page.waitForRequest((request) => request.url().includes('/api/mds/metadata/resolve?entryId='));
    await page.goto(`/#mds/${L1}`);
    expect((await resolved).url()).toContain(`entryId=${encodeURIComponent(L1)}`);
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();
    await expect(entryPage(page).getByRole('heading', { level: 4 })).toHaveText(SECTIONS);
  });

  test('says when the metadata has no entry for the AAGUID', async ({ page, watch }) => {
    watch.allow(/status of 404/);
    await page.goto('/#mds/aaguid:00000000-0000-4000-8000-00000000abcd');
    await expect(entryPage(page).getByRole('heading', { level: 3, name: 'Authenticator metadata not found.' })).toBeVisible();
    await expect(entryPage(page).getByRole('alert')).toHaveText('Metadata entry not found.');
  });
});

test.describe('an MDS entry\'s identifiers', () => {
  for (const width of [700, 1024, 1100, 1279, 1280, 1440]) {
    test(`are whole at ${width} px, with no Show all`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await openEntry(page);
      // Geist Mono is fetched when mono text first shows: measure in it, not in its fallback.
      await page.evaluate(() => document.fonts.ready);
      for (const [key, label] of [
        ['overview', 'Identifier'],
        ['overview', 'AAGUID'],
        ['authenticatorGetInfo', 'AAGUID'],
      ]) {
        const code = part(page, key).locator(`[data-item="${label}"] code`);
        await expect(code).toHaveText(/^[0-9a-f-]{36}$/);
        const fits = await code.evaluate((node) => node.scrollWidth <= node.clientWidth);
        expect(fits, `${key} ${label} at ${width} px`).toBe(true);
        await expect(part(page, key).locator(`[data-item="${label}"]`).getByRole('button', { name: 'Show all' })).toHaveCount(0);
      }
    });
  }
});
