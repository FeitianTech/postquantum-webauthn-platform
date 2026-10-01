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
      const parts = colour.match(/-?[\d.]+(?:e-?\d+)?/g)?.map(Number) ?? [];
      if (parts.length < 3 || (parts[3] ?? 1) === 0) continue;
      // Tailwind's colours with an opacity come back as oklab(L a b / alpha):
      // grey is no hue (a and b near 0) and not white (L under 0.98).
      const grey = colour.startsWith('oklab(')
        ? Math.abs(parts[1]) < 0.005 && Math.abs(parts[2]) < 0.005 && parts[0] < 0.98
        : Math.max(parts[0], parts[1], parts[2]) - Math.min(parts[0], parts[1], parts[2]) < 6 && Math.min(parts[0], parts[1], parts[2]) < 250;
      if (grey) found.push(`${element.tagName.toLowerCase()}.${element.className}: ${colour}`);
    }
    return found;
  }, scope);
}
