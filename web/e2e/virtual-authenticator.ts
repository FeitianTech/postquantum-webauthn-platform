import type { Page } from '@playwright/test';

export type VirtualCredential = {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  userHandle?: string;
  signCount: number;
};

type AuthenticatorOptions = {
  protocol?: 'ctap2' | 'u2f';
  transport?: 'usb' | 'nfc' | 'ble' | 'cable' | 'internal';
  hasResidentKey?: boolean;
  hasUserVerification?: boolean;
  isUserVerified?: boolean;
  automaticPresenceSimulation?: boolean;
};

// A virtual authenticator in Chromium through the DevTools WebAuthn domain: the
// page's navigator.credentials.create() and get() are answered by it, with real
// signatures the server verifies, and no prompt. By default a CTAP2 security
// key on USB (the simple flow asks for a cross-platform authenticator) with a
// resident key and user verification, that consents on its own.
export async function addVirtualAuthenticator(page: Page, options: AuthenticatorOptions = {}) {
  const session = await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      ...options,
    },
  });
  return {
    authenticatorId,
    async credentials(): Promise<VirtualCredential[]> {
      const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials as VirtualCredential[];
    },
    async remove() {
      await session.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    },
  };
}
