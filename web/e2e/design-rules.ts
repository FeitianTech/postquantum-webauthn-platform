import type { Page } from '@playwright/test';

// Every element with a neutral grey background (white, colours and tints are
// fine), inside `scope` or the whole page. The scrim that dims the page under a
// dialog is not a component.
export function greyFills(page: Page, scope = 'body') {
  return page.evaluate((selector) => {
    const found: string[] = [];
    for (const element of document.querySelectorAll<HTMLElement>(`${selector} *`)) {
      if (element.getClientRects().length === 0 || element.matches('[data-overlay-backdrop]')) continue;
      const colour = getComputedStyle(element).backgroundColor;
      const parts = colour.match(/[\d.]+/g)?.map(Number) ?? [];
      const [r, g, b, a = 1] = parts;
      if (parts.length < 3 || a === 0) continue;
      const neutral = Math.max(r, g, b) - Math.min(r, g, b) < 6;
      if (neutral && Math.min(r, g, b) < 250) found.push(`${element.tagName.toLowerCase()}.${element.className}: ${colour}`);
    }
    return found;
  }, scope);
}
