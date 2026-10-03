import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { shownLevel, shownSubViews, expectedFor, keep, report } from './credential-views';
import { expect, test } from './fixtures';
import type { ShownSection } from './recorded-words';
import { recorded } from './recorded';

// What a saved credential's details and its registration show (the dialog's
// levels), against their recording (recorded.ts), for the same stored records and
// for an advanced credential whose records the recording keeps: word for word per
// section (layout, separators and controls' own labels set aside:
// recorded-words.ts), and each certificate's and the authenticator data's text
// equal. Every difference must be one listed below, with its reason.

type DetailRecording = { sections: ShownSection[]; subViews: Record<string, string> };

const repo = resolve(import.meta.dirname, '..', '..');

// registration-detail-decodes: ES256, EdDSA, ML-DSA-65 and a packed one with a
// certificate, as the server registered them.
const REGISTERED = JSON.parse(
  readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', 'registration-detail-decodes.json'), 'utf8'),
)
  .requests.filter((entry: { request: string }) => entry.request.includes('/register/complete'))
  .map((entry: { body: { storedCredential: Record<string, unknown> } }) => entry.body.storedCredential);

const RECORDS = ['es256', 'eddsa', 'mldsa65', 'x5c'].map((name, index) => ({
  ...REGISTERED[index],
  type: 'simple',
  userName: `${name}@example.com`,
  email: `${name}@example.com`,
})) as Record<string, unknown>[];

test.describe('a saved credential\'s details, as recorded', () => {
  for (const record of RECORDS) {
    const name = record.userName as string;
    test(`show the same words, section by section, and the same certificates and authenticator data: ${name}`, async ({ page }) => {
      const current = recorded<DetailRecording>('credential-detail', name);
      const { sections: legacy, subViews: legacySubs } = current;

      await page.goto('/#simple');
      await keep(page, RECORDS);
      await page.reload();
      await page.goto(`/#simple/credential/id:${record.credentialIdBase64Url}`);
      const detail = await shownLevel(page, 'detail', 'h4');
      await page.getByRole('dialog').getByRole('button', { name: 'Show registration details' }).click();
      const registration = await shownLevel(page, 'registration', 'h4, [data-recorded-heading]');
      const shownSubs = await shownSubViews(page);

      expect(report(legacy, [...detail, ...registration], expectedFor(name))).toEqual([]);
      expect(legacy.map((section) => section.heading)).toEqual(
        [...detail, ...registration].map((section) => section.heading).filter((heading) => heading && heading !== 'Registration Details'),
      );
      expect(shownSubs).toEqual(legacySubs);
    });
  }

  test('an advanced registration\'s level shows the recorded words', async ({ page }) => {
    const current = recorded<DetailRecording & { records: object[] }>('credential-detail', 'the result of an advanced registration');
    const { sections: legacy, subViews: legacySubs } = current;

    await page.goto('/#simple');
    await keep(page, current.records);
    await page.reload();
    const key = await page.locator('li[data-credential-key]').first().getAttribute('data-credential-key');
    await page.goto(`/#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration`);
    const shown = await shownLevel(page, 'registration', 'h4, [data-recorded-heading]');
    const shownSubs = await shownSubViews(page);

    expect(report(legacy, shown, [])).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(shown.map((section) => section.heading));
    expect(shownSubs).toEqual(legacySubs);
  });
});
