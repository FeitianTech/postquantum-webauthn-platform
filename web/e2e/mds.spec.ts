import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Locator, Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';

// The MDS list at /#mds in Chromium, against Flask serving the fixture
// snapshot (tests/fixtures/mds, through serve-flask.mjs) under the strict CSP.

const repo = resolve(import.meta.dirname, '..', '..');
const UPLOAD = join(repo, 'tests', 'fixtures', 'mds', 'custom-metadata.json');
const L1 = 'aaguid:f1d0f1d0-0000-4000-8000-000000000001';
const MANY_ROOTS = 'aaguid:f1d0f1d0-0000-4000-8000-000000000006';

const section = (page: Page) => page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
const rows = (page: Page) => section(page).locator('tbody tr[data-entry-id]:not([hidden])');
const row = (page: Page, entryId: string) => section(page).locator(`tbody tr[data-entry-id="${entryId}"]`);
const filter = (page: Page, name: string) => {
  const bar = section(page).getByRole('region', { name: 'Filters' });
  return bar.getByRole('combobox', { name, exact: true }).or(bar.getByRole('searchbox', { name, exact: true }));
};
const header = (page: Page, name: string) => section(page).getByRole('columnheader', { name: new RegExp(`^${name}`) });
const frame = (page: Page) => section(page).locator('[data-mds-frame]');

async function openList(page: Page, path = '/#mds') {
  await page.goto(path);
  await expect(rows(page)).toHaveCount(32);
}

async function names(list: Locator) {
  return list.locator('a[data-entry-link]').allTextContents();
}

test.describe('/#mds', () => {
  test('loads the fixture: the count, the status line, the 14 columns', async ({ page }) => {
    await openList(page);
    await expect(section(page).getByText(/^Entries:/)).toHaveText('Entries: 32 of 32 total');
    const status = section(page).locator('[role="status"][data-variant]');
    await expect(status).toHaveAttribute('data-variant', 'success');
    await expect(status).toHaveText(/^Loaded 32 authenticators\. Last updated .+\.$/);
    await expect(section(page).getByRole('columnheader')).toHaveCount(14);
    await expect(header(page, 'Date Updated')).toHaveAttribute('aria-sort', 'descending');
  });

  test('filters, clears, and sorts', async ({ page }) => {
    await openList(page);
    await filter(page, 'Search').fill('u2f');
    await expect(rows(page)).toHaveCount(1);
    await expect(header(page, 'Name')).toContainText('(filtered)');
    await expect(section(page).getByText('1 active')).toBeVisible();

    await filter(page, 'Certification').click();
    await filter(page, 'Search').fill('');
    await filter(page, 'Certification').fill('FIDO Certified L');
    await section(page).getByRole('option', { name: 'FIDO Certified L2' }).click();
    await expect(rows(page)).toHaveCount(2);

    await section(page).getByRole('button', { name: 'Clear filters' }).first().click();
    await expect(rows(page)).toHaveCount(32);
    await expect(filter(page, 'Certification')).toHaveValue('');

    await header(page, 'Name').getByRole('button').click();
    await expect(header(page, 'Name')).toHaveAttribute('aria-sort', 'ascending');
    expect((await names(rows(page)))[0]).toMatch(/^Fixture Authenticator With A Deliberately Long Description/);
  });

  test('sorts by a column picked by name, and turns the order round', async ({ page }) => {
    await openList(page);
    const sort = section(page).getByRole('combobox', { name: 'Sort', exact: true });
    await sort.selectOption('Name');
    await expect(header(page, 'Name')).toHaveAttribute('aria-sort', 'ascending');
    const first = (await names(rows(page)))[0];
    await section(page).getByRole('button', { name: 'Sort descending' }).click();
    await expect(header(page, 'Name')).toHaveAttribute('aria-sort', 'descending');
    expect((await names(rows(page))).at(-1)).toBe(first);
  });

  test('shows the level a revoked key reached beside its revocation', async ({ page }) => {
    await openList(page);
    const revoked = row(page, 'aaguid:f1d0f1d0-0000-4000-8000-000000000005');
    await expect(revoked.locator('td').nth(3)).toHaveText(/^FIDO Certified L1/);
    await filter(page, 'Certification').fill('FIDO Certified');
    await section(page).getByRole('option', { name: 'FIDO Certified', exact: true }).click();
    await expect(rows(page)).toHaveCount(29);
    await expect(revoked).toBeVisible();
  });

  test('filters by the latest status, which a column of its own shows', async ({ page }) => {
    await openList(page);
    await expect(row(page, 'aaguid:f1d0f1d0-0000-4000-8000-000000000005').locator('td').nth(4)).toHaveText('Revoked');
    await filter(page, 'Status').fill('Revoked');
    await section(page).getByRole('option', { name: 'Revoked' }).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(header(page, 'Status')).toContainText('(filtered)');
  });

  test('keeps a long CN within reach: one line with the whole value as a tooltip, every word when expanded', async ({ page }) => {
    await openList(page);
    const cn = row(page, MANY_ROOTS).locator('td').nth(12);
    const title = await cn.getAttribute('title');
    expect(title!.length).toBeGreaterThanOrEqual(954);
    const collapsed = (await row(page, MANY_ROOTS).boundingBox())!.height;

    await row(page, MANY_ROOTS).getByRole('button', { name: /^Show all of/ }).click();
    await expect(row(page, MANY_ROOTS)).toHaveAttribute('aria-expanded', 'true');
    expect((await row(page, MANY_ROOTS).boundingBox())!.height).toBeGreaterThan(collapsed * 4);
    const pills = cn.locator('span > span');
    await expect(pills).toHaveCount(15);
    // Nothing clipped: every value sits inside its cell.
    const cell = (await cn.boundingBox())!;
    for (const box of await pills.evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().right))) {
      expect(box).toBeLessThanOrEqual(cell.x + cell.width);
    }
  });

  test('copies an AAGUID whole', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await openList(page);
    await row(page, L1).getByRole('button', { name: 'Copy AAGUID' }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('f1d0f1d0-0000-4000-8000-000000000001');
  });

  test('uploads metadata, shows its entry, then deletes it', async ({ page }) => {
    await openList(page);
    const manage = section(page).getByRole('button', { name: 'Manage Metadata' });
    await manage.click();
    const dialog = page.getByRole('dialog', { name: 'Manage Trusted Metadata' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('No custom metadata has been added yet.')).toBeVisible();

    const uploaded = page.waitForResponse('**/api/mds/metadata/upload');
    await dialog.locator('input[type="file"]').setInputFiles(UPLOAD);
    await expect(dialog.getByText('Metadata uploaded successfully.')).toBeVisible();
    // The answer carries the session's own entries alone, which the page merges with its list.
    const answer = await (await uploaded).json();
    expect(Object.keys(answer).sort()).toEqual(['custom', 'items']);
    expect(answer.custom.entries.map((entry: { name: string }) => entry.name)).toEqual(['Fixture Uploaded Authenticator']);
    expect(answer.custom.meta).toMatchObject({ customEntryCount: 1, hasCustomEntries: true });
    await expect(rows(page)).toHaveCount(33);
    await expect(section(page).getByRole('link', { name: 'Fixture Uploaded Authenticator' })).toBeAttached();
    // Its row names its icon by a URL of its own, as a packaged row does, and the image loads from it.
    const uploadedRow = row(page, 'aaguid:f1d0f1d0-0000-4000-8000-000000000099');
    const icon = uploadedRow.locator('img');
    await expect(icon).toHaveAttribute('src', /^\/api\/mds\/metadata\/custom\/[0-9a-f]{32}\.json\/icon$/);
    await uploadedRow.scrollIntoViewIfNeeded();
    await expect.poll(() => icon.evaluate((image: HTMLImageElement) => (image.complete ? image.naturalWidth : 0))).toBeGreaterThan(0);
    await expect(section(page).locator('[role="status"][data-variant]')).toHaveText(/Including 1 session metadata entry\. Custom metadata updated\.$/);
    await expect(dialog.getByText('custom-metadata.json')).toBeVisible();
    expect(await greyFills(page, '[data-overlay="dialog"]')).toEqual([]);

    await dialog.getByRole('button', { name: 'Delete custom-metadata.json' }).click();
    await expect(dialog.getByText('custom-metadata.json removed.')).toBeVisible();
    await expect(rows(page)).toHaveCount(32);
    await expect(dialog.getByText('No custom metadata has been added yet.')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(manage).toBeFocused();
  });

  test('shows an upload in place of the packaged entry with its AAGUID', async ({ page }) => {
    await openList(page);
    await section(page).getByRole('button', { name: 'Manage Metadata' }).click();
    const dialog = page.getByRole('dialog', { name: 'Manage Trusted Metadata' });
    // The uploaded statement, given Fixture Security Key L1's AAGUID.
    const buffer = Buffer.from(readFileSync(UPLOAD, 'utf8').replaceAll('000000000099', '000000000001'));
    await dialog.locator('input[type="file"]').setInputFiles({ name: 'replacing-l1.json', mimeType: 'application/json', buffer });
    await expect(dialog.getByText('Metadata uploaded successfully.')).toBeVisible();

    await expect(row(page, L1).locator('a[data-entry-link]')).toHaveText('Fixture Uploaded Authenticator');
    await expect(rows(page)).toHaveCount(32);
    expect(await names(rows(page))).not.toContain('Fixture Security Key L1');
  });

  test('opens an entry from its row and goes back, by the page and by the browser, to the list as it was', async ({ page }) => {
    await openList(page);
    await filter(page, 'Search').fill('Fixture');
    await header(page, 'Name').getByRole('button').click();
    await frame(page).evaluate((element) => {
      element.scrollTop = 400;
    });
    const target = rows(page).nth(15);
    const entryId = (await target.getAttribute('data-entry-id'))!;
    const name = (await target.locator('a').textContent())!;

    // A click anywhere in the row but its controls.
    await target.locator('td').nth(2).click();
    await expect(page).toHaveURL(new RegExp(`#mds/${entryId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`));
    await expect(section(page).getByRole('heading', { level: 3, name })).toBeFocused();
    await expect(section(page).locator('[data-mds-list]')).toBeHidden();

    await section(page).getByRole('button', { name: 'Back' }).click();
    await expect(section(page).locator('[data-mds-list]')).toBeVisible();
    await expect(page).toHaveURL(/#mds$/);
    await expect(section(page).locator(`[data-entry-link="${entryId}"]`)).toBeFocused();
    expect(await frame(page).evaluate((element) => element.scrollTop)).toBe(400);
    await expect(filter(page, 'Search')).toHaveValue('Fixture');
    await expect(header(page, 'Name')).toHaveAttribute('aria-sort', 'ascending');

    await section(page).locator(`[data-entry-link="${entryId}"]`).press('Enter');
    await expect(section(page).getByRole('heading', { level: 3, name })).toBeVisible();
    await page.goBack();
    await expect(section(page).locator('[data-mds-list]')).toBeVisible();
    await expect(section(page).locator(`[data-entry-link="${entryId}"]`)).toBeFocused();
    await page.goForward();
    await expect(section(page).getByRole('heading', { level: 3, name })).toBeVisible();
  });

  test('opens an entry a link names, an AAID with its # encoded', async ({ page }) => {
    await page.goto('/#mds/aaid:F1D0%230012');
    await expect(section(page).getByRole('heading', { level: 3, name: 'Fixture UAF Authenticator' })).toBeVisible();
    const entry = section(page).locator('[data-mds-entry]');
    await expect(entry.locator('[data-entry-subtitle]').getByText('F1D0#0012', { exact: true })).toBeVisible();
    await expect(entry.locator('[data-section="overview"]').getByText('F1D0#0012', { exact: true })).toBeVisible();
    await section(page).getByRole('button', { name: 'Back' }).click();
    await expect(rows(page)).toHaveCount(32);
  });

  test('never scrolls the page sideways on a phone, and has no grey fill', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await openList(page);
    const pageWidth = () => page.evaluate(() => document.documentElement.scrollWidth);
    expect(await pageWidth()).toBeLessThanOrEqual(375);
    await row(page, MANY_ROOTS).getByRole('button', { name: /^Show all of/ }).click();
    expect(await pageWidth()).toBeLessThanOrEqual(375);

    await section(page).getByRole('button', { name: 'Show filters' }).click();
    await expect(filter(page, 'User Verification')).toBeVisible();
    await filter(page, 'User Verification').click();
    expect(await pageWidth()).toBeLessThanOrEqual(375);
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);
  });

  test('gives the icon a narrow column on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await openList(page);
    const icon = (await header(page, 'Icon').boundingBox())!;
    const width = await frame(page).evaluate((element) => element.clientWidth);
    expect(icon.width / width).toBeLessThan(0.15);
    await expect(header(page, 'Icon')).toHaveAccessibleName(/^Icon/);
  });

  test('narrows the icon column when the window narrows to a phone after loading', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 800 });
    await openList(page);
    await page.setViewportSize({ width: 375, height: 812 });
    await expect
      .poll(async () => (await header(page, 'Icon').boundingBox())!.width / (await frame(page).evaluate((element) => element.clientWidth)))
      .toBeLessThan(0.15);
    await page.setViewportSize({ width: 1024, height: 800 });
    await expect.poll(async () => (await header(page, 'Icon').boundingBox())!.width).toBeCloseTo(72, 0);
  });

  test('fades the table\'s right edge while it can scroll further that way', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 800 });
    await openList(page);
    const fade = section(page).locator('[data-mds-fade]');
    await expect(fade).toBeVisible();
    const [frameBox, fadeBox] = [(await frame(page).boundingBox())!, (await fade.boundingBox())!];
    expect(Math.abs(frameBox.x + frameBox.width - (fadeBox.x + fadeBox.width))).toBeLessThanOrEqual(20);
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);
    await frame(page).evaluate((element) => {
      element.scrollLeft = element.scrollWidth;
    });
    await expect(fade).toBeHidden();
    await frame(page).evaluate((element) => {
      element.scrollLeft = 0;
    });
    await expect(fade).toBeVisible();
  });

  test('fits the table\'s frame under the header when the header takes two rows', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 800 });
    await openList(page);
    const shellHeight = (await page.locator('[data-shell-header]').boundingBox())!.height;
    expect(shellHeight).toBeGreaterThan(90);
    const variable = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--header-height'));
    expect(Number.parseFloat(variable)).toBeCloseTo(shellHeight, 0);
    const frameHeight = (await frame(page).boundingBox())!.height;
    expect(frameHeight).toBeLessThanOrEqual(800 - shellHeight - 32 + 1);
  });

  test('keeps the header row in view while the list scrolls', async ({ page }) => {
    await openList(page);
    await frame(page).evaluate((element) => {
      element.scrollTop = 600;
    });
    const top = (await frame(page).boundingBox())!.y;
    const head = (await section(page).locator('thead').boundingBox())!.y;
    expect(Math.abs(head - top)).toBeLessThanOrEqual(2);
  });
});
