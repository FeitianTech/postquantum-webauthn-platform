import { beforeEach, describe, expect, it, vi } from 'vitest';

import { state } from '../../static/scripts/shared/state.js';
import {
  applyAuthenticatorAttachmentPreference,
  applyHintsToCheckboxes,
  collectSelectedHints,
  deriveAllowedAttachmentsFromHints,
  ensureAuthenticationHintsAllowed,
  normalizeHintValue,
  registerHintsChangeCallback,
} from '../../static/scripts/advanced/hints.js';

describe('hints', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <input id="hint-client-device" type="checkbox" />
      <input id="hint-hybrid" type="checkbox" />
      <input id="hint-security-key" type="checkbox" />
      <input id="hint-client-device-auth" type="checkbox" />
      <input id="hint-hybrid-auth" type="checkbox" />
      <input id="hint-security-key-auth" type="checkbox" />
    `;
    state.storedCredentials = [];
  });

  it('collects and applies hint selections', () => {
    const callback = vi.fn();
    registerHintsChangeCallback(callback);

    document.getElementById('hint-client-device').checked = true;
    document.getElementById('hint-security-key').checked = true;
    expect(collectSelectedHints('registration')).toEqual(['client-device', 'security-key']);
    expect(deriveAllowedAttachmentsFromHints(['client-device', 'hybrid'])).toEqual(['platform', 'cross-platform']);
    expect(normalizeHintValue(' Hybrid ')).toBe('hybrid');

    applyHintsToCheckboxes(['hybrid'], 'registration');
    expect(document.getElementById('hint-hybrid').checked).toBe(true);
    expect(callback).toHaveBeenCalled();
  });

  it('applies attachment preferences and validates allowed credentials', () => {
    const target = { publicKey: { authenticatorSelection: {} } };
    applyAuthenticatorAttachmentPreference(target, ['platform']);
    expect(target.publicKey.authenticatorSelection.authenticatorAttachment).toBe('platform');

    state.storedCredentials = [
      { credentialIdHex: '414243', authenticatorAttachment: 'platform' },
    ];

    const publicKey = {
      hints: ['client-device'],
      allowCredentials: [{ id: { $hex: '414243' } }],
      authenticatorSelection: {},
    };
    expect(ensureAuthenticationHintsAllowed(publicKey, { requireSelection: true })).toEqual(['platform']);
  });

  it('throws when required selections are invalid', () => {
    expect(() => ensureAuthenticationHintsAllowed({}, { requireSelection: true }))
      .toThrow('Please select at least one authenticator hint before continuing.');

    expect(() => ensureAuthenticationHintsAllowed({ hints: ['unknown'] }, { requireSelection: true }))
      .toThrow('Selected hints do not map to any authenticator attachments.');
  });
});
