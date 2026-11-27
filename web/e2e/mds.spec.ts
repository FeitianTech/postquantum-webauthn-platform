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
const bar = (page: Page) => section(page).getByRole('region', { name: 'Filters' });
// Eight of the filters wait behind this button.
const moreFilters = (page: Page) => bar(page).getByRole('button', { name: /^More filters/ }).click();
const header = (page: Page, name: string) => section(page).getByRole('columnheader', { name: new RegExp(`^${name}`) });

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
    await expect(header(page, 'ID')).toContainText('(filtered)');

    await expect(filter(page, 'Certification')).toBeHidden();
    await moreFilters(page);
    await filter(page, 'Certification').click();
    await filter(page, 'Search').fill('');
    await filter(page, 'Certification').fill('FIDO Certified L');
    await section(page).getByRole('option', { name: 'FIDO Certified L2' }).click();
    await expect(rows(page)).toHaveCount(2);
    await expect(bar(page).getByRole('button', { name: 'Fewer filters (1)' })).toBeVisible();

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
    await moreFilters(page);
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

  test('keeps a long CN out of the two lines, and shows every word of it on a line of its own when expanded', async ({ page }) => {
    await openList(page);
    const cn = row(page, MANY_ROOTS).locator('td').nth(12);
    expect((await cn.getAttribute('title'))!.length).toBeGreaterThanOrEqual(954);
    const collapsed = (await row(page, MANY_ROOTS).boundingBox())!.height;

    await row(page, MANY_ROOTS).getByRole('button', { name: /^Show all of/ }).click();
    await expect(row(page, MANY_ROOTS)).toHaveAttribute('aria-expanded', 'true');
    expect((await row(page, MANY_ROOTS).boundingBox())!.height).toBeGreaterThan(collapsed * 4);
    await expect(cn.getByText('CN', { exact: true })).toBeVisible();
    const pills = cn.locator('span > span');
    await expect(pills).toHaveCount(15);
    // Nothing clipped: every value sits inside its cell.
    const cell = (await cn.boundingBox())!;
    for (const box of await pills.evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().right))) {
      expect(box).toBeLessThanOrEqual(cell.x + cell.width);
    }
  });

  for (const width of [1440, 1152, 1024, 768, 375]) {
    test(`fits every row in a ${width} px window: nothing scrolls sideways, no identifier is cut`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      await openList(page);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      const cut = await rows(page)
        .locator('code')
        .evaluateAll((codes) => codes.filter((code) => code.scrollWidth > code.clientWidth).map((code) => code.textContent));
      expect(cut).toEqual([]);
    });
  }

  test('gives a column its place from the width at which it fits, and keeps a hidden one\'s header for a screen reader', async ({ page }) => {
    await openList(page);
    const sortButton = (name: string) => header(page, name).locator('button');
    await expect(section(page).getByRole('columnheader')).toHaveCount(14);
    // Never a column: out of sight and out of the tab order, its row's cell too.
    await expect(sortButton('CN')).toBeHidden();
    expect((await header(page, 'CN').boundingBox())!.width).toBeLessThanOrEqual(1);
    expect((await row(page, L1).locator('td').nth(12).boundingBox())!.width).toBeLessThanOrEqual(1);
    // At 1280 px the user verification has no room yet; at 1440 it has.
    await expect(sortButton('Algorithms')).toBeVisible();
    await expect(sortButton('User Verification')).toBeHidden();
    await page.setViewportSize({ width: 1440, height: 800 });
    await expect(sortButton('User Verification')).toBeVisible();
    await page.setViewportSize({ width: 1024, height: 800 });
    await expect(sortButton('Algorithms')).toBeHidden();
    await expect(sortButton('Transports')).toBeVisible();
    await page.setViewportSize({ width: 800, height: 800 });
    await expect(sortButton('Transports')).toBeHidden();
    await expect(sortButton('Status')).toBeVisible();
    // The name sits over the ID.
    const [name, id] = [(await header(page, 'Name').boundingBox())!, (await header(page, 'ID').boundingBox())!];
    expect(id.y).toBeGreaterThan(name.y);
    expect(id.x).toBe(name.x);
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
    await page.evaluate(() => window.scrollTo(0, 700));
    const target = rows(page).nth(15);
    const entryId = (await target.getAttribute('data-entry-id'))!;
    const name = (await target.locator('a').textContent())!;

    // A click anywhere in the row but its controls expands it; its link opens the entry.
    await target.locator('td').nth(2).click();
    await expect(target).toHaveAttribute('aria-expanded', 'true');
    const top = (await target.boundingBox())!.y;
    expect(top).toBeGreaterThan(100);
    await target.getByRole('link', { name: /^Open entry/ }).click();
    await expect(page).toHaveURL(new RegExp(`#mds/${entryId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`));
    await expect(section(page).getByRole('heading', { level: 3, name })).toBeFocused();
    await expect(section(page).locator('[data-mds-list]')).toBeHidden();

    await section(page).getByRole('button', { name: 'Back' }).click();
    await expect(section(page).locator('[data-mds-list]')).toBeVisible();
    await expect(page).toHaveURL(/#mds$/);
    await expect(section(page).locator(`[data-entry-link="${entryId}"]`)).toBeFocused();
    // The row is where it was in the window, still expanded.
    expect(Math.abs((await target.boundingBox())!.y - top)).toBeLessThanOrEqual(1);
    await expect(target).toHaveAttribute('aria-expanded', 'true');
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

    // A phone keeps only the search out.
    await expect(filter(page, 'Search')).toBeVisible();
    await expect(filter(page, 'Protocol')).toBeHidden();
    await moreFilters(page);
    await expect(filter(page, 'Protocol')).toBeVisible();
    await expect(filter(page, 'User Verification')).toBeVisible();
    await filter(page, 'User Verification').click();
    expect(await pageWidth()).toBeLessThanOrEqual(375);
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);
  });

  test('scrolls the list with the page, the filters and the header row staying under the site\'s header, two rows of it too', async ({ page }) => {
    await page.setViewportSize({ width: 1100, height: 800 });
    await openList(page);
    const shellHeight = (await page.locator('[data-shell-header]').boundingBox())!.height;
    expect(shellHeight).toBeGreaterThan(90);
    const variable = (name: string) => page.evaluate((property) => Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue(property)), name);
    expect(await variable('--header-height')).toBeCloseTo(shellHeight, 0);

    // Nothing in the section scrolls by itself: the wheel always moves the page.
    const scrollers = await section(page).evaluate((panel) =>
      [...panel.querySelectorAll('*')].filter((element) => element.scrollHeight > element.clientHeight + 1 && /auto|scroll/.test(getComputedStyle(element).overflowY)).length,
    );
    expect(scrollers).toBe(0);
    await page.evaluate(() => window.scrollTo(0, 1200));
    const pinned = async () => {
      const [filters, head] = [(await bar(page).boundingBox())!, (await section(page).locator('thead').boundingBox())!];
      expect(Math.abs(filters.y - shellHeight)).toBeLessThanOrEqual(1);
      expect(await variable('--mds-toolbar-height')).toBeCloseTo(filters.height, 0);
      // The header row tucks a pixel under the bar: no row shows between them.
      expect(Math.abs(head.y - (filters.y + filters.height - 1))).toBeLessThanOrEqual(1);
    };
    await pinned();
    // The bar grows with its other filters, and the header row moves down with it.
    await moreFilters(page);
    await expect(filter(page, 'CN')).toBeVisible();
    await pinned();
    // A list a filter offers ends above the window's bottom.
    await filter(page, 'User Verification').click();
    const list = (await page.getByRole('listbox').boundingBox())!;
    expect(list.y + list.height).toBeLessThanOrEqual(800);
    expect(await greyFills(page, '#nav-panel-mds')).toEqual([]);
  });

  test('leaves the filters in the page in a short window, the header row alone under the site\'s header', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 600 });
    await openList(page);
    await page.evaluate(() => window.scrollTo(0, 1200));
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--mds-toolbar-height'))).toBe('0px');
    await expect(bar(page)).not.toBeInViewport();
    const shellHeight = (await page.locator('[data-shell-header]').boundingBox())!.height;
    expect(Math.abs((await section(page).locator('thead').boundingBox())!.y - (shellHeight - 1))).toBeLessThanOrEqual(1);
  });

  test('offers the way back to the top once the page is well into the list', async ({ page }) => {
    await openList(page);
    const toTop = section(page).getByRole('button', { name: 'Back to top of the authenticator list' });
    await expect(toTop).toBeHidden();
    await page.evaluate(() => window.scrollTo(0, 1500));
    await expect(toTop).toBeVisible();
    const box = (await toTop.boundingBox())!;
    expect(box.y + box.height).toBeLessThanOrEqual(720 - 16 + 1);
    await toTop.click();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    await expect(toTop).toBeHidden();
  });
});
