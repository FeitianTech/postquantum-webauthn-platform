import type { Page } from '@playwright/test';

import { expect } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './recorded-words';

// A saved credential's details and registration in the dialog's levels, for the
// *-recorded specs, which compare them with their recordings.

export const STORAGE_KEY = 'postquantum-webauthn.credentials';

const escape = (word: string) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function expectedFor(name: string): ExpectedDifference[] {
  return [
    { only: 'shown', token: new RegExp(`^${escape(name)}$`), section: '', reason: 'the credential\'s name, the details\' title (new)' },
    {
      only: 'shown',
      token: /^(Registration|Details)$/,
      section: 'Registration Details',
      reason: 'the way to the registration\'s own level: its heading (the button\'s label is set aside)',
    },
    {
      only: 'recorded',
      token: /^[()]$/,
      section: 'Properties',
      reason: 'the roots Root Valid tried (FIDO MDS, Chain) are chips, each in its verdict\'s tone, not a list in parentheses',
    },
    {
      only: 'recorded',
      token: /^("pqc_signature_valid"|null)$/,
      section: 'Server-retrieved Data',
      reason: 'no separate ML-DSA signature result (pqc_signature_valid): ML-DSA attestations are verified like any other',
    },
    ...(name === 'mldsa65@example.com' ? MLDSA_NONE_ATTESTATION : []),
  ];
}

// The ML-DSA-65 registration's attestation is "none": the ML-DSA-only root
// evaluation that gave it root checks and a metadata warning is gone, as for any
// other "none" attestation.
const MLDSA_NONE_REASON = 'a "none" ML-DSA attestation has no root evaluation, as any other "none" attestation';
const MLDSA_NONE_ATTESTATION: ExpectedDifference[] = [
  {
    only: 'recorded',
    token: /^("root_checks"|"chain"|"fido_mds"|"trusted_ca"|"warnings"|"metadata_not_available"|[[\]{}])$/,
    section: 'Server-retrieved Data',
    reason: MLDSA_NONE_REASON,
  },
  { only: 'shown', token: /^\[\]$/, section: 'Server-retrieved Data', reason: MLDSA_NONE_REASON },
  { only: 'recorded', token: /^(FIDO|MDS|Chain)$/, section: 'Properties', reason: MLDSA_NONE_REASON },
];

export async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

export async function shownLevel(page: Page, level: string, headings: string) {
  const root = page.getByRole('dialog').locator(`[data-level="${level}"]`);
  await expect(root).toBeVisible();
  return readShownText(root, headings);
}

// The dialog's certificate and authenticator-data levels' text, by their buttons.
export async function shownSubViews(page: Page) {
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

export function report(legacy: ShownSection[], shown: ShownSection[], expected: ExpectedDifference[]) {
  const differences = compareShownText(legacy, shown, expected);
  return describeDifferences(differences.filter((difference) => !difference.reason));
}
