import { describe, expect, it } from 'vitest';

import {
  HINT_VALUES,
  applyAuthenticatorAttachmentPreference,
  deriveAllowedAttachmentsFromHints,
  enforceAuthenticatorAttachmentWithHints,
  ensureAuthenticationHintsAllowed,
  normalizeHintValue,
} from './hints.js';

// What the hints and the authenticator attachment mean for a request, with no
// form (advanced/hints.js).

const PLATFORM = { credentialIdHex: 'aa01', authenticatorAttachment: 'platform' };
const SECURITY_KEY = { credentialIdHex: 'bb02', properties: { authenticatorAttachment: ' Cross-Platform ' } };
const NO_ATTACHMENT = { credentialIdHex: 'cc03' };

describe('the hints', () => {
  it('are offered in the form\'s order', () => {
    expect(HINT_VALUES).toEqual(['client-device', 'hybrid', 'security-key']);
  });

  it('are compared trimmed and in lower case, and a value that is not text is none', () => {
    expect(normalizeHintValue(' Security-Key ')).toBe('security-key');
    expect(normalizeHintValue(3)).toBe('');
  });

  it('imply their attachments, each once, in the order first implied', () => {
    expect(deriveAllowedAttachmentsFromHints(['security-key', 'client-device', 'hybrid', 'unknown', ''])).toEqual([
      'cross-platform',
      'platform',
    ]);
    expect(deriveAllowedAttachmentsFromHints('hybrid')).toEqual([]);
  });
});

describe('the attachment given to the browser', () => {
  it('is the one attachment the hints resolved to', () => {
    const options = { publicKey: { authenticatorSelection: { authenticatorAttachment: 'cross-platform' } } };
    applyAuthenticatorAttachmentPreference(options, [' Platform ']);
    expect(options.publicKey.authenticatorSelection.authenticatorAttachment).toBe('platform');
  });

  it('is otherwise the first attachment a source names, the options themselves first', () => {
    const options = { authenticatorSelection: { authenticatorAttachment: '' } };
    applyAuthenticatorAttachmentPreference(options, ['platform', 'cross-platform'], null, { authenticatorSelection: {} }, {
      authenticatorSelection: { authenticatorAttachment: 'cross-platform' },
    });
    expect(options.authenticatorSelection.authenticatorAttachment).toBe('cross-platform');
  });

  it('is otherwise the one attachment a source\'s hints imply', () => {
    const options = { publicKey: { hints: ['client-device', 'security-key'] } };
    applyAuthenticatorAttachmentPreference(options, 'none', 'text', { hints: 'hybrid' }, { hints: ['hybrid'] });
    expect(options.publicKey.authenticatorSelection).toEqual({ authenticatorAttachment: 'cross-platform' });
  });

  it('is left out when nothing names one', () => {
    const options = { publicKey: { authenticatorSelection: { authenticatorAttachment: 'nothing', residentKey: 'required' } } };
    applyAuthenticatorAttachmentPreference(options, []);
    expect(options.publicKey.authenticatorSelection).toEqual({ authenticatorAttachment: 'nothing', residentKey: 'required' });

    const none = { publicKey: { authenticatorSelection: { residentKey: 'required' } } };
    applyAuthenticatorAttachmentPreference(none, []);
    expect(none.publicKey.authenticatorSelection).toEqual({ residentKey: 'required' });
  });

  it('removes an attachment that is no attachment', () => {
    const options = { publicKey: { authenticatorSelection: { authenticatorAttachment: 5 } } };
    applyAuthenticatorAttachmentPreference(options, []);
    expect(options.publicKey.authenticatorSelection).toEqual({});
  });

  it('changes nothing that is not options', () => {
    expect(() => applyAuthenticatorAttachmentPreference(null, ['platform'])).not.toThrow();
  });
});

describe('the credentials a request allows', () => {
  it('are left as they are when nothing resolves an attachment, and nothing is asked of a missing request', () => {
    const publicKey = { allowCredentials: [{ id: { $hex: 'aa01' } }] };
    expect(ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [PLATFORM] })).toEqual([]);
    expect(publicKey.allowCredentials).toEqual([{ id: { $hex: 'aa01' } }]);
    expect(ensureAuthenticationHintsAllowed(null)).toEqual([]);
    expect(ensureAuthenticationHintsAllowed({ hints: 'hybrid' }, null)).toEqual([]);
  });

  it('take the attachment from the selection when no hint implies one', () => {
    const publicKey = { hints: ['unknown'], authenticatorSelection: { authenticatorAttachment: ' Platform ' } };
    expect(ensureAuthenticationHintsAllowed(publicKey)).toEqual(['platform']);
    expect(ensureAuthenticationHintsAllowed({ authenticatorSelection: { authenticatorAttachment: '' } })).toEqual([]);
    expect(ensureAuthenticationHintsAllowed({ authenticatorSelection: 'platform' })).toEqual([]);
  });

  it('keep only the saved credentials whose attachment the hints allow, when one of them is not', () => {
    const publicKey = {
      hints: ['client-device', 'client-device'],
      allowCredentials: [
        null,
        { id: {} },
        { id: { $hex: 'AA01' } },
        { id: { $hex: 'dd04' } },
        { id: { $hex: 'bb02' } },
        { id: { $hex: 'cc03' } },
      ],
    };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [PLATFORM, SECURITY_KEY, NO_ATTACHMENT, {}] });
    expect(publicKey.allowCredentials).toEqual([{ id: { $hex: 'AA01' } }]);
  });

  it('keep the list as it is with no saved credential to judge it by', () => {
    const publicKey = { hints: ['client-device'], allowCredentials: [{ id: { $hex: 'bb02' } }] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: null });
    expect(publicKey.allowCredentials).toEqual([{ id: { $hex: 'bb02' } }]);
  });

  it('leave out the list when none of them is allowed', () => {
    const publicKey = { hints: ['client-device'], allowCredentials: [{ id: { $hex: 'bb02' } }] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [SECURITY_KEY] });
    expect(publicKey).not.toHaveProperty('allowCredentials');
  });

  it('keep a list whose every saved credential is allowed, and ids they do not know', () => {
    const publicKey = { hints: ['hybrid'], allowCredentials: [{ id: { $hex: 'bb02' } }, { id: { $hex: 'ee05' } }, 'text'] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [SECURITY_KEY, { credentialIdHex: '' }] });
    expect(publicKey.allowCredentials).toEqual([{ id: { $hex: 'bb02' } }, { id: { $hex: 'ee05' } }, 'text']);
  });

  it('fill an empty list with the first saved credential of the one attachment allowed', () => {
    const publicKey = { hints: ['hybrid'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [PLATFORM, SECURITY_KEY] });
    expect(publicKey.allowCredentials).toEqual([{ type: 'public-key', id: { $hex: 'bb02' } }]);
  });

  it('leave an empty list empty when no saved credential has the attachment, or it has no id', () => {
    const none = { hints: ['hybrid'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(none, { storedCredentials: [PLATFORM] });
    expect(none.allowCredentials).toEqual([]);

    const noId = { hints: ['hybrid'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(noId, { storedCredentials: [{ authenticatorAttachment: 'cross-platform' }] });
    expect(noId.allowCredentials).toEqual([]);
  });

  it('fill an empty list with every saved credential either of two attachments allows', () => {
    const publicKey = { hints: ['client-device', 'security-key'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(publicKey, {
      storedCredentials: [PLATFORM, NO_ATTACHMENT, SECURITY_KEY, { authenticatorAttachment: 'platform' }],
    });
    expect(publicKey.allowCredentials).toEqual([
      { type: 'public-key', id: { $hex: 'aa01' } },
      { type: 'public-key', id: { $hex: 'bb02' } },
    ]);
  });

  it('leave out an empty list that no saved credential can fill', () => {
    const publicKey = { hints: ['client-device', 'hybrid'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: [NO_ATTACHMENT] });
    expect(publicKey).not.toHaveProperty('allowCredentials');
  });

  it('leave an empty list empty with no saved credential', () => {
    const publicKey = { hints: ['hybrid'], allowCredentials: [] };
    ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: 'none' });
    expect(publicKey.allowCredentials).toEqual([]);
  });

  it('offer no saved credential to a registration\'s request', () => {
    const publicKey = { hints: ['client-device'], allowCredentials: [] };
    expect(enforceAuthenticatorAttachmentWithHints(publicKey)).toEqual(['platform']);
    expect(publicKey.allowCredentials).toEqual([]);
    expect(enforceAuthenticatorAttachmentWithHints({ hints: ['hybrid'] })).toEqual(['cross-platform']);
  });

  it('require no hint: a missing request, no hints or hints that imply no attachment give none', () => {
    expect(ensureAuthenticationHintsAllowed(null)).toEqual([]);
    expect(enforceAuthenticatorAttachmentWithHints({})).toEqual([]);
    expect(ensureAuthenticationHintsAllowed({ hints: ['unknown'] })).toEqual([]);
    expect(ensureAuthenticationHintsAllowed({ hints: ['hybrid'] })).toEqual(['cross-platform']);
  });
});
