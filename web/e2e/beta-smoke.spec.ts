import type { Locator, Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';

// The new UI at /beta, served by Flask from the built export under the strict
// CSP: the shell, the sections, the Analyze Browser panel, the phone menu, and
// the design system's rules checked on the design page in a real browser.

const SECTIONS = ['Simple Authentication', 'Advanced Authentication', 'Codec', 'FIDO MDS Authenticators'];

// The top bar's highlight (the Codec's Decode / Encode switch has its own).
const sectionHighlight = (page: Page) => page.getByRole('tablist', { name: 'Sections' }).locator('[data-segment-highlight]');

async function highlightSitsOn(page: Page, tab: Locator) {
  const highlight = sectionHighlight(page);
  await expect
    .poll(async () => {
      const [h, t] = await Promise.all([highlight.boundingBox(), tab.boundingBox()]);
      return h && t ? Math.round(Math.abs(h.x - t.x) + Math.abs(h.width - t.width)) : -1;
    })
    .toBeLessThanOrEqual(1);
}

test.describe('/beta', () => {
  test('switches sections on the page and by the hash, and no section leads to the current UI', async ({ page }) => {
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
      await expect(page.getByRole('tabpanel', { name })).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`/beta#${hash}$`));
      await highlightSitsOn(page, tab);
    }

    // Every section is ported (Phase 29B), and none links to the current UI.
    const advanced = page.getByRole('tabpanel', { name: 'Advanced Authentication' });
    await advanced.getByRole('tab', { name: 'Authentication' }).click();
    await expect(advanced.getByRole('button', { name: 'Assert Credential' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Open the current interface' })).toHaveCount(0);

    await page.goto('/beta#codec');
    await expect(page.getByRole('tabpanel', { name: 'Codec' })).toBeVisible();
    await expect(tabs.getByRole('tab', { name: 'Codec' })).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Tab');
  });

  // The exported page is the same for every hash; until the scripts arrive it
  // chooses no section, and the hydrated page's first frame shows the hash's.
  // Each frame from the first is recorded while the scripts are held back.
  for (const [hash, section] of [
    ['', 'simple'],
    ['#advanced', 'advanced'],
    ['#codec', 'codec'],
    ['#mds', 'mds'],
    ['#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000002', 'mds'],
  ] as const) {
    test(`loads /beta${hash} on its section from the first frame, with no fade or entrance`, async ({ page }) => {
      await page.route('**/beta/_next/static/**', async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 600));
        await route.continue();
      });
      await page.addInitScript(() => {
        const frames: Array<{ selected: string[]; shown: string[]; moving: string[] }> = [];
        (globalThis as unknown as { pqcFrames: typeof frames }).pqcFrames = frames;
        const record = () => {
          const tabs = document.querySelector('[role="tablist"][aria-label="Sections"]');
          if (tabs) {
            frames.push({
              selected: [...tabs.querySelectorAll('[role="tab"][aria-selected="true"]')].map((tab) => tab.id),
              shown: [...document.querySelectorAll('[role="tabpanel"][id^="nav-panel-"]:not([hidden])')].map((panel) => panel.id),
              moving: document
                .getAnimations()
                .filter((animation) =>
                  animation instanceof CSSTransition
                    ? tabs.contains((animation.effect as KeyframeEffect).target)
                    : animation instanceof CSSAnimation && animation.animationName === 'section-in',
                )
                .map((animation) => (animation instanceof CSSTransition ? `transition ${animation.transitionProperty}` : 'section-in')),
            });
          }
          requestAnimationFrame(record);
        };
        requestAnimationFrame(record);
      });

      await page.goto(`/beta${hash}`);
      const tab = page.getByRole('tablist', { name: 'Sections' }).getByRole('tab', { name: SECTIONS[['simple', 'advanced', 'codec', 'mds'].indexOf(section)] });
      await expect(tab).toHaveAttribute('aria-selected', 'true');
      await highlightSitsOn(page, tab);
      await page.waitForTimeout(700);
      const frames = await page.evaluate(() => (globalThis as unknown as { pqcFrames: Array<{ selected: string[]; shown: string[]; moving: string[] }> }).pqcFrames);

      // Frames before the scripts, then the section's: never another section, never a fade.
      expect(frames.length).toBeGreaterThan(10);
      expect(frames[0]).toEqual({ selected: [], shown: [], moving: [] });
      for (const frame of frames) {
        expect(frame.selected.filter((id) => id !== `nav-tab-${section}`)).toEqual([]);
        expect(frame.shown.filter((id) => id !== `nav-panel-${section}`)).toEqual([]);
        expect(frame.moving).toEqual([]);
      }
      expect(frames.at(-1)).toEqual({ selected: [`nav-tab-${section}`], shown: [`nav-panel-${section}`], moving: [] });
    });
  }

  for (const motion of ['no-preference', 'reduce'] as const) {
    test(`moves the one highlight to the chosen section: ${motion === 'reduce' ? 'jumping under reduced motion' : 'sliding'}`, async ({ page }) => {
      await page.emulateMedia({ reducedMotion: motion });
      await page.goto('/beta');
      // Transitions at a tenth of their speed, so the middle of a slide can be seen.
      const devtools = await page.context().newCDPSession(page);
      await devtools.send('Animation.enable');
      await devtools.send('Animation.setPlaybackRate', { playbackRate: 0.1 });
      const highlight = sectionHighlight(page);
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

    // Copy report, with the page allowed to use the clipboard: the raw findings
    // as JSON, and the words of the current panel.
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await dialog.getByRole('button', { name: 'Copy report' }).click();
    await expect(dialog.getByRole('status')).toHaveText('Report copied to the clipboard.');
    const report = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
    expect(Object.keys(report)).toEqual(['report', 'generatedAt', 'page', 'identity', 'webauthn']);
    expect(report.page).toMatch(/^http:\/\/localhost:\d+$/);
    expect(Object.keys(report.webauthn.facts)).toHaveLength(8);
    await expect(dialog.getByRole('textbox', { name: 'Browser analysis report, as JSON' })).toBeHidden();

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
    const github = sheet.getByRole('link', { name: 'View project on GitHub' });
    await expect(github).toBeVisible();
    await expect(github).toHaveAttribute('href', 'https://github.com/FeitianTech/postquantum-webauthn-platform');
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

  test('leads from the 404 page to the new interface by a plain link, so Back shows the 404 page again', async ({ page, watch }) => {
    // The missing page's own status; a Trusted Types report would still fail the test.
    watch.allow(/status of 404/);
    const missing = await page.goto('/beta/no-such-page');
    expect(missing?.status()).toBe(404);
    await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();

    await page.getByRole('link', { name: 'Go to the new interface' }).click();
    await expect(page.getByRole('tablist', { name: 'Sections' })).toBeVisible();
    expect(new URL(page.url()).pathname).toMatch(/^\/beta\/?$/);

    await page.goBack();
    await expect(page).toHaveURL(/\/beta\/no-such-page$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Sections' })).toHaveCount(0);
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

    // No neutral grey background anywhere (white, colours and tints only).
    const greys = await greyFills(page);
    expect(greys).toEqual([]);
  });
});
