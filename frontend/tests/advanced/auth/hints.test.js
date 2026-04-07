import { beforeEach, describe, expect, it, vi } from 'vitest';

import { state } from '../../../static/scripts/shared/state.js';
import {
  applyAuthenticatorAttachmentPreference,
  applyHintsToCheckboxes,
  collectSelectedHints,
  deriveAllowedAttachmentsFromHints,
  ensureAuthenticationHintsAllowed,
  normalizeHintValue,
  registerHintsChangeCallback,
} from '../../../static/scripts/advanced/hints.js';

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

  it('handles authentication-scope checkbox application without firing registration callbacks', () => {
    const callback = vi.fn();
    registerHintsChangeCallback(callback);

    applyHintsToCheckboxes(['security-key'], 'authentication');

    expect(document.getElementById('hint-security-key-auth').checked).toBe(true);
    expect(document.getElementById('hint-client-device-auth').checked).toBe(false);
    expect(callback).not.toHaveBeenCalled();

    document.getElementById('hint-client-device-auth').checked = true;
    expect(collectSelectedHints('authentication')).toEqual(['client-device', 'security-key']);
  });

  it('filters incompatible allowCredentials and synthesizes fallback descriptors by hint attachment', () => {
    state.storedCredentials = [
      { credentialIdHex: '414243', authenticatorAttachment: 'platform' },
      { credentialIdHex: '444546', authenticatorAttachment: 'cross-platform' },
    ];

    const constrained = {
      hints: ['client-device'],
      allowCredentials: [
        { id: { $hex: '444546' }, type: 'public-key' },
      ],
      authenticatorSelection: {},
    };

    const resolved = ensureAuthenticationHintsAllowed(constrained, { requireSelection: true });
    expect(resolved).toEqual(['platform']);
    expect(constrained.allowCredentials).toBeUndefined();

    const fallbackSingle = {
      hints: ['security-key'],
      allowCredentials: [],
      authenticatorSelection: {},
    };

    ensureAuthenticationHintsAllowed(fallbackSingle, { requireSelection: true });
    expect(fallbackSingle.allowCredentials).toEqual([
      {
        type: 'public-key',
        id: { $hex: '444546' },
      },
    ]);

    const fallbackMultiple = {
      hints: ['security-key', 'client-device'],
      allowCredentials: [],
      authenticatorSelection: {},
    };

    ensureAuthenticationHintsAllowed(fallbackMultiple, { requireSelection: true });
    expect(fallbackMultiple.allowCredentials).toHaveLength(2);
  });

  it('derives attachment preferences from fallback sources and removes stale attachment fields', () => {
    const withFallbackSelection = { publicKey: { authenticatorSelection: {} } };
    applyAuthenticatorAttachmentPreference(
      withFallbackSelection,
      ['platform', 'cross-platform'],
      { authenticatorSelection: { authenticatorAttachment: 'cross-platform' } },
    );
    expect(withFallbackSelection.publicKey.authenticatorSelection.authenticatorAttachment).toBe('cross-platform');

    const withHintSource = { publicKey: { authenticatorSelection: {} } };
    applyAuthenticatorAttachmentPreference(
      withHintSource,
      [],
      { hints: ['client-device'] },
    );
    expect(withHintSource.publicKey.authenticatorSelection.authenticatorAttachment).toBe('platform');

    const withStaleValue = { publicKey: { authenticatorSelection: { authenticatorAttachment: '   ' } } };
    applyAuthenticatorAttachmentPreference(withStaleValue, [], {});
    expect(Object.prototype.hasOwnProperty.call(withStaleValue.publicKey.authenticatorSelection, 'authenticatorAttachment')).toBe(false);
  });

  it('continues applying registration hint callbacks when one callback throws', () => {
    const callback = vi.fn();
    registerHintsChangeCallback(callback);
    registerHintsChangeCallback(() => {
      throw new Error('callback failure');
    });
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    applyHintsToCheckboxes(['client-device'], 'registration');

    expect(callback).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to run registration hints change callback.',
      expect.any(Error),
    );
  });
});
