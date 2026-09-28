import type { Page } from '@playwright/test';

import { expect } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './parity';

// A saved credential's details and registration in the new UI's dialog levels, for the
// parity specs, which compare them with what the current modal at / showed (its
// registration view, the second modal for a certificate or the authenticator
// data), as recorded.

export const STORAGE_KEY = 'postquantum-webauthn.credentials';

const escape = (word: string) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function expectedFor(name: string): ExpectedDifference[] {
  return [
    { only: 'beta', token: new RegExp(`^${escape(name)}$`), section: '', reason: 'the credential\'s name, the details\' title (new)' },
    {
      only: 'beta',
      token: /^(Registration|Details)$/,
      section: 'Registration Details',
      reason: 'the way to the registration\'s own level: its heading (the button\'s label is set aside)',
    },
    {
      only: 'legacy',
      token: /^[()]$/,
      section: 'Properties',
      reason: 'the roots Root Valid tried (FIDO MDS, Chain) are chips, each in its verdict\'s tone, not a list in parentheses',
    },
  ];
}

export async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

export async function betaLevel(page: Page, level: string, headings: string) {
  const root = page.getByRole('dialog').locator(`[data-level="${level}"]`);
  await expect(root).toBeVisible();
  return readShownText(root, headings);
}

// The dialog's certificate and authenticator-data levels' text, by their buttons.
export async function betaSubViews(page: Page) {
  const texts: Record<string, string> = {};
  const dialog = page.getByRole('dialog');
  const buttons = dialog.locator('[data-level="registration"] [data-level-open]');
  const labels = await buttons.allTextContents();
  for (const label of labels) {
    await dialog.locator('[data-level="registration"]').getByRole('button', { name: label.trim(), exact: true }).click();
    const shown = dialog.locator('[data-level]:not([hidden])');
    await expect(shown).not.toHaveAttribute('data-level', 'registration');
    const text = shown.locator('[data-section="Decoded Output"] pre, :scope > div > pre, pre').last();
    texts[label.trim()] = (await text.textContent()) ?? '';
    await dialog.getByRole('button', { name: 'Back' }).click();
    await expect(dialog.locator('[data-level="registration"]')).toBeVisible();
  }
  return texts;
}

export function report(legacy: ShownSection[], beta: ShownSection[], expected: ExpectedDifference[]) {
  const differences = compareShownText(legacy, beta, expected);
  return describeDifferences(differences.filter((difference) => !difference.reason));
}
