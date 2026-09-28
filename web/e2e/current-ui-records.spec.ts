import { STORAGE_KEY, openCurrent } from './credential-views';
import { expect, test } from './fixtures';
import { RECORDING, recorded } from './recorded';
import { addVirtualAuthenticator } from './virtual-authenticator';

// Records a Simple and an Advanced credential the current UI at / registered: the
// stored records it wrote, as a visitor's browser holds them, and the virtual
// authenticator's credentials (private keys and counters), so the new UI can be
// shown to read and use them once the current UI is gone. Runs only while
// recording (recorded.ts).

type StoredRecord = { type?: string; registrationDetailSnapshot?: unknown };

test('the current UI registers a Simple and an Advanced credential', async ({ page }) => {
  test.skip(!RECORDING, 'records only, with PARITY_RECORD=1');
  await recorded('current-ui-records', 'records', async () => {
    const authenticator = await addVirtualAuthenticator(page);
    await openCurrent(page);
    await page.locator('#simple-email').fill('current-ui-simple@example.com');
    await page.getByRole('button', { name: 'Register Passkey', exact: true }).click();
    await expect(page.locator('#simple-status')).toContainText('Registration successful!');

    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('#user-name').fill('current-ui-advanced');
    await page.locator('[data-action="advanced-register"]').click();
    await expect(page.locator('#registrationResultModal')).toBeVisible();

    const read = () => page.evaluate((key) => JSON.parse(window.localStorage.getItem(key) ?? '[]') as StoredRecord[], STORAGE_KEY);
    await expect
      .poll(async () => {
        const records = await read();
        return records.length === 2 && records.some((record) => record.type === 'advanced' && record.registrationDetailSnapshot);
      })
      .toBe(true);
    return { records: await read(), credentials: await authenticator.credentials() };
  });
});
