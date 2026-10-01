// What the JSON editor accepts as an authentication request's publicKey (advanced/authentication/validation.js).
import { describe, expect, it } from 'vitest';

import { validateAuthenticationPublicKey } from './validation.js';

function authentication() {
  return {
    challenge: { $hex: '00112233445566778899aabbccddeeff' },
    timeout: 90000,
    rpId: 'localhost',
    allowCredentials: [{ type: 'public-key', id: { $hex: 'aa01' }, transports: ['usb', 'nfc'] }],
    userVerification: 'preferred',
    extensions: { largeBlob: { read: true }, prf: { eval: { first: { $hex: '01' } } } },
    hints: ['security-key'],
  };
}

/** The request with `change` applied to it. */
function withChange(change) {
  const publicKey = authentication();
  change(publicKey);
  return publicKey;
}

function check(change) {
  return () => validateAuthenticationPublicKey(withChange(change));
}

describe('an authentication request', () => {
  it('is accepted with every member the editor handles', () => {
    expect(() => validateAuthenticationPublicKey(authentication())).not.toThrow();
  });

  it('is accepted with only the challenge', () => {
    expect(() => validateAuthenticationPublicKey({ challenge: { $base64url: 'ABEiMw' } })).not.toThrow();
  });

  it('is refused when it is not an object', () => {
    expect(() => validateAuthenticationPublicKey('challenge')).toThrow('publicKey must be an object.');
  });

  it('is refused with a registration member', () => {
    expect(check(publicKey => { publicKey.rp = { name: 'Example' }; })).toThrow('publicKey contains unsupported properties: rp');
  });
});

describe('the challenge', () => {
  it('is required', () => {
    expect(check(publicKey => { delete publicKey.challenge; })).toThrow('publicKey.challenge is required.');
  });

  it('must hold bytes', () => {
    expect(check(publicKey => { publicKey.challenge = {}; })).toThrow(
      'publicKey.challenge must be a base64url, base64, or hexadecimal value.',
    );
  });
});

describe('the timeout', () => {
  it('is accepted as a whole number in text, as zero, or as blank text', () => {
    expect(check(publicKey => { publicKey.timeout = '60000'; })).not.toThrow();
    expect(check(publicKey => { publicKey.timeout = 0; })).not.toThrow();
    expect(check(publicKey => { publicKey.timeout = ' '; })).not.toThrow();
  });

  it('is refused below zero', () => {
    expect(check(publicKey => { publicKey.timeout = '-1'; })).toThrow('publicKey.timeout must be zero or greater.');
  });

  it('is refused when it is not a number', () => {
    expect(check(publicKey => { publicKey.timeout = 'soon'; })).toThrow('publicKey.timeout must be a whole number.');
  });
});

describe('the relying party id', () => {
  it('may be left out', () => {
    expect(check(publicKey => { delete publicKey.rpId; })).not.toThrow();
  });

  it('must be text that is not blank when given', () => {
    const message = 'publicKey.rpId must be a non-empty string when provided.';
    expect(check(publicKey => { publicKey.rpId = 443; })).toThrow(message);
    expect(check(publicKey => { publicKey.rpId = '  '; })).toThrow(message);
  });
});

describe('the allowed credentials', () => {
  it('are accepted empty, and with no type or transports', () => {
    expect(check(publicKey => { publicKey.allowCredentials = []; })).not.toThrow();
    expect(check(publicKey => { publicKey.allowCredentials = [{ id: 'qgE' }]; })).not.toThrow();
  });

  it('must be an array', () => {
    expect(check(publicKey => { publicKey.allowCredentials = { id: { $hex: 'aa01' } }; })).toThrow(
      'publicKey.allowCredentials must be an array.',
    );
  });

  it('must each be an object, named by index', () => {
    expect(check(publicKey => { publicKey.allowCredentials.push(null); })).toThrow(
      'publicKey.allowCredentials[1] must be an object.',
    );
  });

  it('must each be of type public-key', () => {
    expect(check(publicKey => { publicKey.allowCredentials[0].type = 'password'; })).toThrow(
      'publicKey.allowCredentials[0].type must be "public-key".',
    );
  });

  it('must each have an id', () => {
    expect(check(publicKey => { delete publicKey.allowCredentials[0].id; })).toThrow(
      'publicKey.allowCredentials[0].id is required.',
    );
  });

  it('must each give transports as an array of text', () => {
    const message = 'publicKey.allowCredentials[0].transports must be an array of strings.';
    expect(check(publicKey => { publicKey.allowCredentials[0].transports = 'usb'; })).toThrow(message);
    expect(check(publicKey => { publicKey.allowCredentials[0].transports = ['usb', null]; })).toThrow(message);
  });
});

describe('the user verification', () => {
  it('is accepted as required, preferred or discouraged, or left out', () => {
    ['required', 'preferred', 'discouraged'].forEach(userVerification => {
      expect(check(publicKey => { publicKey.userVerification = userVerification; })).not.toThrow();
    });
    expect(check(publicKey => { delete publicKey.userVerification; })).not.toThrow();
  });

  it('is refused as anything else', () => {
    const message = 'publicKey.userVerification must be required, preferred, or discouraged.';
    expect(check(publicKey => { publicKey.userVerification = 'always'; })).toThrow(message);
    expect(check(publicKey => { publicKey.userVerification = 3; })).toThrow(message);
  });
});

describe('the extensions', () => {
  it('are accepted empty or left out', () => {
    expect(check(publicKey => { publicKey.extensions = {}; })).not.toThrow();
    expect(check(publicKey => { delete publicKey.extensions; })).not.toThrow();
  });

  it('must be an object', () => {
    expect(check(publicKey => { publicKey.extensions = 'largeBlob'; })).toThrow('publicKey.extensions must be an object.');
  });

  it('are refused with a registration extension', () => {
    expect(check(publicKey => { publicKey.extensions.credProps = true; })).toThrow(
      'publicKey.extensions contains unsupported properties: credProps',
    );
  });

  it('check largeBlob by the authentication members', () => {
    expect(check(publicKey => { publicKey.extensions.largeBlob = { support: 'required' }; })).toThrow(
      'publicKey.extensions.largeBlob contains unsupported properties: support',
    );
    expect(check(publicKey => { publicKey.extensions.largeBlob = { read: 'yes' }; })).toThrow(
      'publicKey.extensions.largeBlob.read must be a boolean.',
    );
  });

  it('check prf', () => {
    expect(check(publicKey => { publicKey.extensions.prf = { eval: 'first' }; })).toThrow(
      'publicKey.extensions.prf.eval must be an object.',
    );
  });
});

describe('the hints', () => {
  it('are refused with a hint WebAuthn does not define', () => {
    expect(check(publicKey => { publicKey.hints = ['usb']; })).toThrow('publicKey.hints[0] is not a supported hint value.');
  });
});
