import { expect, test } from './fixtures';
import { addVirtualAuthenticator } from './virtual-authenticator';

// The current UI at /, end to end: a real registration and authentication in
// the Simple tab, answered by Chromium's virtual authenticator and verified by
// the server. Later phases run the same ceremonies against /beta.
test('registers a passkey and authenticates with it in the Simple tab', async ({ page, watch }) => {
  // Without the MDS snapshot (CI has none: docs/MDS_SNAPSHOT.md) the current
  // UI's explorer loads it in the background and gets a 404, the documented
  // fallback. Nothing else may reach the console.
  watch.allow(/^console error: Failed to load resource: .* 404 .*\/fido-mds3\.explorer(\.full)?\.json\)$/);
  const authenticator = await addVirtualAuthenticator(page);
  await page.goto('/');
  await expect(page.locator('body')).toHaveClass(/app-loaded/);

  await page.locator('#simple-email').fill(`e2e-${Date.now()}`);
  await page.getByRole('button', { name: 'Register Passkey', exact: true }).click();
  await expect(page.locator('#simple-status')).toContainText('Registration successful! Algorithm:');
  await expect(page.locator('#simple-credentials-list .credential-item')).toHaveCount(1);

  const [registered] = await authenticator.credentials();
  expect(registered.rpId).toBe('localhost');

  await page.getByRole('button', { name: 'Authenticate', exact: true }).click();
  await expect(page.locator('#simple-status')).toContainText('Authentication successful! You have been verified.');
  await expect(page.locator('#simple-ceremony-result')).toBeVisible();

  const [used] = await authenticator.credentials();
  expect(used.credentialId).toBe(registered.credentialId);
  expect(used.signCount).toBeGreaterThan(registered.signCount);
});
