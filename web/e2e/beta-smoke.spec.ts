import type { Locator, Page } from '@playwright/test';

import { expect, test } from './fixtures';

// The new UI at /beta, served by Flask from the built export under the strict
// CSP: the shell, the sections, the Analyze Browser panel, the phone menu, and
// the design system's rules checked on the design page in a real browser.

const SECTIONS = ['Simple Authentication', 'Advanced Authentication', 'Codec', 'FIDO MDS Authenticators'];

async function highlightSitsOn(page: Page, tab: Locator) {
  const highlight = page.locator('[data-segment-highlight]').first();
  await expect
    .poll(async () => {
      const [h, t] = await Promise.all([highlight.boundingBox(), tab.boundingBox()]);
      return h && t ? Math.round(Math.abs(h.x - t.x) + Math.abs(h.width - t.width)) : -1;
    })
    .toBeLessThanOrEqual(1);
}

test.describe('/beta', () => {
  test('switches sections on the page and by the hash, and each unported section leads to the current UI', async ({ page }) => {
    await page.goto('/beta');
    const tabs = page.getByRole('tablist', { name: 'Sections' });
    await expect(tabs.getByRole('tab')).toHaveText(SECTIONS.map((name) => `${name}${name}`));
    await expect(page.getByRole('tabpanel', { name: 'Simple Authentication' })).toBeVisible();
    await highlightSitsOn(page, tabs.getByRole('tab', { name: 'Simple Authentication' }));

    for (const [name, hash] of [
      ['Codec', 'codec'],
      ['FIDO MDS Authenticators', 'mds'],
      ['Advanced Authentication', 'advanced'],
    ] as const) {
      const tab = tabs.getByRole('tab', { name });
      await tab.click();
      const panel = page.getByRole('tabpanel', { name });
      await expect(panel).toBeVisible();
      await expect(panel.getByRole('link', { name: 'Open the current interface' })).toHaveAttribute('href', '/');
      await expect(page).toHaveURL(new RegExp(`/beta#${hash}$`));
      await highlightSitsOn(page, tab);
    }

    await page.goto('/beta#codec');
    await expect(page.getByRole('tabpanel', { name: 'Codec' })).toBeVisible();
    await expect(tabs.getByRole('tab', { name: 'Codec' })).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Tab');
  });

  for (const motion of ['no-preference', 'reduce'] as const) {
    test(`moves the one highlight to the chosen section: ${motion === 'reduce' ? 'jumping under reduced motion' : 'sliding'}`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: motion });
      await page.goto('/beta');
      // Transitions at a tenth of their speed, so the middle of a slide can be seen.
      const devtools = await page.context().newCDPSession(page);
      await devtools.send('Animation.enable');
      await devtools.send('Animation.setPlaybackRate', { playbackRate: 0.1 });
      const highlight = page.locator('[data-segment-highlight]');
      const x = () => highlight.evaluate((element) => new DOMMatrixReadOnly(getComputedStyle(element).transform).m41);
      const target = page.getByRole('tab', { name: 'FIDO MDS Authenticators' });
      const from = await x();
      const to = await target.evaluate((element) => (element as HTMLElement).offsetLeft);

      await target.click();
      await page.waitForTimeout(700);
      const during = await x();
      if (motion === 'reduce') {
        expect(during).toBeCloseTo(to, 0);
      } else {
        expect(during).toBeGreaterThan(from + 10);
        expect(during).toBeLessThan(to - 10);
        await expect.poll(x, { timeout: 6000 }).toBeCloseTo(to, 0);
      }
    });
  }

  test('opens the Analyze Browser panel, and Escape closes it and gives focus back', async ({ page }) => {
    await page.goto('/beta');
    const trigger = page.getByRole('button', { name: 'Analyze Browser' });
    await trigger.click();

    const dialog = page.getByRole('dialog', { name: 'Browser Analysis' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toBeFocused();
    for (const label of ['Browser', 'Version', 'Engine', 'System']) {
      await expect(dialog.locator('dt', { hasText: new RegExp(`^${label}$`) })).toBeVisible();
    }
    await expect(dialog.locator('[data-item="engine"] [data-role="value"]')).toHaveText('Blink');
    await expect(dialog.getByRole('region', { name: 'WebAuthn' }).locator('[data-fact]')).toHaveCount(6);
    await expect(dialog.getByRole('region', { name: 'Authenticators' }).locator('[data-fact]')).toHaveCount(2);
    await expect(dialog.locator('[data-fact="secureContext"] [data-state]')).toHaveAttribute('data-state', 'yes');
    await expect(dialog.getByRole('region', { name: 'Post-quantum' })).toContainText('-48 ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87');

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
  });

  test('on a phone, the sections, Analyze Browser and GitHub are in the menu sheet', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/beta');
    await expect(page.getByRole('tablist', { name: 'Sections' })).toBeHidden();

    await page.getByRole('button', { name: 'Menu' }).click();
    const sheet = page.getByRole('dialog', { name: 'Menu' });
    await expect(sheet).toBeVisible();
    await expect(sheet.getByRole('link', { name: 'View project on GitHub' })).toBeVisible();
    await sheet.getByRole('button', { name: 'FIDO MDS Authenticators' }).click();
    await expect(sheet).toBeHidden();
    await expect(page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' })).toBeVisible();

    await page.getByRole('button', { name: 'Menu' }).click();
    await page.getByRole('dialog', { name: 'Menu' }).getByRole('button', { name: 'Analyze Browser' }).click();
    await expect(page.getByRole('dialog', { name: 'Browser Analysis' })).toBeVisible();
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(width).toBeLessThanOrEqual(375);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', { name: 'Menu' })).toBeFocused();
    await expect(page.getByRole('button', { name: 'Analyze Browser' })).toBeHidden();

    // Neither page scrolls sideways on a phone.
    for (const path of ['/beta', '/beta/design']) {
      await page.goto(path);
      expect(await page.evaluate(() => document.documentElement.scrollWidth), path).toBeLessThanOrEqual(375);
    }
  });

  test('keeps the design rules: no focus effect on text fields, a focus ring on controls, no grey fill', async ({ page }) => {
    await page.goto('/beta/design');

    // Text fields: focus changes nothing around them.
    const field = page.getByLabel('Filled');
    const look = (locator: Locator) =>
      locator.evaluate((element) => {
        const style = getComputedStyle(element);
        return { outline: style.outlineStyle, shadow: style.boxShadow, border: style.borderColor };
      });
    const before = await look(field);
    await field.focus();
    await expect(field).toBeFocused();
    expect(await look(field)).toEqual(before);
    expect(before.outline).toBe('none');
    expect(before.shadow).toBe('none');

    // Controls: keyboard focus draws a ring.
    await page.locator('body').click({ position: { x: 5, y: 5 } });
    await page.keyboard.press('Tab');
    const focused = page.locator(':focus');
    await expect(focused).toHaveText('Default');
    expect(await focused.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe('solid');
    for (const control of [
      page.getByRole('tab', { name: 'Simple Authentication' }).nth(0),
      page.getByRole('switch', { name: 'Off', exact: true }),
      page.getByRole('button', { name: 'ML-DSA-44', exact: true }),
    ]) {
      await control.focus();
      expect(await control.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe('solid');
    }

    // No neutral grey background anywhere (white, colours and tints only). The
    // scrim that dims the page under a dialog is not a component.
    const greys = await page.evaluate(() => {
      const found: string[] = [];
      for (const element of document.querySelectorAll<HTMLElement>('body *')) {
        if (element.getClientRects().length === 0 || element.matches('[data-overlay-backdrop]')) continue;
        const colour = getComputedStyle(element).backgroundColor;
        const parts = colour.match(/[\d.]+/g)?.map(Number) ?? [];
        const [r, g, b, a = 1] = parts;
        if (parts.length < 3 || a === 0) continue;
        const neutral = Math.max(r, g, b) - Math.min(r, g, b) < 6;
        if (neutral && Math.min(r, g, b) < 250) found.push(`${element.tagName.toLowerCase()}.${element.className}: ${colour}`);
      }
      return found;
    });
    expect(greys).toEqual([]);
  });
});
