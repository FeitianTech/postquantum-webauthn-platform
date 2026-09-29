// What the JSON editor accepts as a registration request's publicKey (advanced/json-editor/validation-registration.js).
import { describe, expect, it } from 'vitest';

import { validateRegistrationPublicKey } from './validation-registration.js';

function registration() {
  return {
    rp: { name: 'FIDO2/WebAuthn PQC Developer Tools', id: 'localhost' },
    user: { id: { $hex: 'abcd' }, name: 'alice', displayName: 'alice' },
    challenge: { $hex: '00112233445566778899aabbccddeeff' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -48 },
      { type: 'public-key', alg: -7 },
    ],
    timeout: 90000,
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
    attestation: 'direct',
    excludeCredentials: [],
    extensions: { credProps: true },
  };
}

/** The request with `change` applied to it. */
function withChange(change) {
  const publicKey = registration();
  change(publicKey);
  return publicKey;
}

function check(change) {
  return () => validateRegistrationPublicKey(withChange(change));
}

describe('a registration request', () => {
  it('is accepted as the form writes it', () => {
    expect(() => validateRegistrationPublicKey(registration())).not.toThrow();
  });

  it('is accepted with only the relying party, the user and the challenge', () => {
    const { rp, user, challenge } = registration();
    expect(() => validateRegistrationPublicKey({ rp, user, challenge })).not.toThrow();
  });

  it('is refused when it is not an object', () => {
    expect(() => validateRegistrationPublicKey(null)).toThrow('publicKey must be an object.');
    expect(() => validateRegistrationPublicKey([registration()])).toThrow('publicKey must be an object.');
  });

  it('is refused with a member the editor does not handle', () => {
    expect(check(publicKey => { publicKey.attestationFormats = ['packed']; })).toThrow(
      'publicKey contains unsupported properties: attestationFormats',
    );
  });
});

describe('the relying party', () => {
  it('is required as an object', () => {
    expect(check(publicKey => { delete publicKey.rp; })).toThrow('publicKey.rp must be an object.');
    expect(check(publicKey => { publicKey.rp = 'localhost'; })).toThrow('publicKey.rp must be an object.');
  });

  it('is refused with a member other than name and id', () => {
    expect(check(publicKey => { publicKey.rp.icon = 'https://example.com/icon.png'; })).toThrow(
      'publicKey.rp contains unsupported properties: icon',
    );
  });

  it('needs a name that is not blank', () => {
    expect(check(publicKey => { delete publicKey.rp.name; })).toThrow('publicKey.rp.name must be a non-empty string.');
    expect(check(publicKey => { publicKey.rp.name = '   '; })).toThrow('publicKey.rp.name must be a non-empty string.');
  });

  it('may leave out its id', () => {
    expect(check(publicKey => { delete publicKey.rp.id; })).not.toThrow();
  });

  it('needs an id that is text when it gives one', () => {
    expect(check(publicKey => { publicKey.rp.id = 443; })).toThrow('publicKey.rp.id must be a string when provided.');
  });
});

describe('the user', () => {
  it('is required as an object', () => {
    expect(check(publicKey => { publicKey.user = null; })).toThrow('publicKey.user must be an object.');
  });

  it('is refused with a member other than id, name and displayName', () => {
    expect(check(publicKey => { publicKey.user.icon = 'avatar.png'; })).toThrow(
      'publicKey.user contains unsupported properties: icon',
    );
  });

  it('needs an id', () => {
    expect(check(publicKey => { delete publicKey.user.id; })).toThrow('publicKey.user.id is required.');
  });

  it('needs an id that holds bytes', () => {
    expect(check(publicKey => { publicKey.user.id = { $hex: '' }; })).toThrow(
      'publicKey.user.id must be a base64url, base64, or hexadecimal value.',
    );
  });

  it('needs a name that is text and not blank', () => {
    expect(check(publicKey => { publicKey.user.name = 42; })).toThrow('publicKey.user.name must be a non-empty string.');
    expect(check(publicKey => { publicKey.user.name = ' '; })).toThrow('publicKey.user.name must be a non-empty string.');
  });

  it('needs a display name that is text and not blank', () => {
    expect(check(publicKey => { delete publicKey.user.displayName; })).toThrow(
      'publicKey.user.displayName must be a non-empty string.',
    );
    expect(check(publicKey => { publicKey.user.displayName = ''; })).toThrow(
      'publicKey.user.displayName must be a non-empty string.',
    );
  });
});

describe('the challenge', () => {
  it('is required', () => {
    expect(check(publicKey => { delete publicKey.challenge; })).toThrow('publicKey.challenge is required.');
  });

  it('must hold bytes', () => {
    expect(check(publicKey => { publicKey.challenge = { $base64: 'q8-0' }; })).toThrow(
      'publicKey.challenge must be a base64url, base64, or hexadecimal value.',
    );
  });
});

describe('the timeout', () => {
  it('is accepted as a whole number in text, as zero, or as blank text', () => {
    expect(check(publicKey => { publicKey.timeout = '120000'; })).not.toThrow();
    expect(check(publicKey => { publicKey.timeout = 0; })).not.toThrow();
    expect(check(publicKey => { publicKey.timeout = ''; })).not.toThrow();
    expect(check(publicKey => { publicKey.timeout = null; })).not.toThrow();
  });

  it('is refused below zero', () => {
    expect(check(publicKey => { publicKey.timeout = -1; })).toThrow('publicKey.timeout must be zero or greater.');
  });

  it('is refused when it is not a number', () => {
    expect(check(publicKey => { publicKey.timeout = 'soon'; })).toThrow('publicKey.timeout must be a whole number.');
  });
});

describe('the credential parameters', () => {
  it('are accepted empty, with no type, and with the algorithm as text', () => {
    expect(check(publicKey => { publicKey.pubKeyCredParams = []; })).not.toThrow();
    expect(check(publicKey => { publicKey.pubKeyCredParams = [{ alg: -257 }, { type: '', alg: '-7' }]; })).not.toThrow();
  });

  it('must be an array', () => {
    expect(check(publicKey => { publicKey.pubKeyCredParams = { type: 'public-key', alg: -7 }; })).toThrow(
      'publicKey.pubKeyCredParams must be an array.',
    );
  });

  it('must each be an object, named by index', () => {
    expect(check(publicKey => { publicKey.pubKeyCredParams.push(-7); })).toThrow(
      'publicKey.pubKeyCredParams[2] must be an object.',
    );
  });

  it('must each be of type public-key', () => {
    expect(check(publicKey => { publicKey.pubKeyCredParams[0].type = 'password'; })).toThrow(
      'publicKey.pubKeyCredParams[0].type must be "public-key".',
    );
  });

  it('must each name an algorithm', () => {
    expect(check(publicKey => { delete publicKey.pubKeyCredParams[1].alg; })).toThrow(
      'publicKey.pubKeyCredParams[1].alg is required.',
    );
    expect(check(publicKey => { publicKey.pubKeyCredParams[1].alg = null; })).toThrow(
      'publicKey.pubKeyCredParams[1].alg is required.',
    );
  });

  it('must each name the algorithm by a finite number', () => {
    const message = 'publicKey.pubKeyCredParams[0].alg must be a valid COSE algorithm number.';
    expect(check(publicKey => { publicKey.pubKeyCredParams[0].alg = 'ES256'; })).toThrow(message);
    expect(check(publicKey => { publicKey.pubKeyCredParams[0].alg = Number.NEGATIVE_INFINITY; })).toThrow(message);
    expect(check(publicKey => { publicKey.pubKeyCredParams[0].alg = true; })).toThrow(message);
  });

  it('must each name an algorithm the tool supports', () => {
    expect(check(publicKey => { publicKey.pubKeyCredParams[0].alg = -999; })).toThrow(
      'publicKey.pubKeyCredParams[0].alg is not a supported algorithm.',
    );
  });
});

describe('the authenticator selection', () => {
  it('is accepted empty', () => {
    expect(check(publicKey => { publicKey.authenticatorSelection = {}; })).not.toThrow();
  });

  it('is accepted with each value WebAuthn defines', () => {
    expect(check(publicKey => {
      publicKey.authenticatorSelection = {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      };
    })).not.toThrow();
  });

  it('must be an object', () => {
    expect(check(publicKey => { publicKey.authenticatorSelection = 'platform'; })).toThrow(
      'publicKey.authenticatorSelection must be an object.',
    );
  });

  it('is refused with a member it does not define', () => {
    expect(check(publicKey => { publicKey.authenticatorSelection.hints = ['hybrid']; })).toThrow(
      'publicKey.authenticatorSelection contains unsupported properties: hints',
    );
  });

  it('needs an attachment of platform or cross-platform', () => {
    const message = 'publicKey.authenticatorSelection.authenticatorAttachment must be "platform" or "cross-platform".';
    expect(check(publicKey => { publicKey.authenticatorSelection.authenticatorAttachment = 'usb'; })).toThrow(message);
    expect(check(publicKey => { publicKey.authenticatorSelection.authenticatorAttachment = 1; })).toThrow(message);
  });

  it('needs a resident key of discouraged, preferred or required', () => {
    const message = 'publicKey.authenticatorSelection.residentKey must be discouraged, preferred, or required.';
    expect(check(publicKey => { publicKey.authenticatorSelection.residentKey = 'always'; })).toThrow(message);
    expect(check(publicKey => { publicKey.authenticatorSelection.residentKey = true; })).toThrow(message);
  });

  it('needs requireResidentKey to be a boolean', () => {
    expect(check(publicKey => { publicKey.authenticatorSelection.requireResidentKey = 'yes'; })).toThrow(
      'publicKey.authenticatorSelection.requireResidentKey must be a boolean.',
    );
  });

  it('needs a user verification of required, preferred or discouraged', () => {
    const message = 'publicKey.authenticatorSelection.userVerification must be required, preferred, or discouraged.';
    expect(check(publicKey => { publicKey.authenticatorSelection.userVerification = 'always'; })).toThrow(message);
    expect(check(publicKey => { publicKey.authenticatorSelection.userVerification = null; })).toThrow(message);
  });
});

describe('the attestation', () => {
  it('is accepted as none, indirect, direct or enterprise', () => {
    ['none', 'indirect', 'direct', 'enterprise'].forEach(attestation => {
      expect(check(publicKey => { publicKey.attestation = attestation; })).not.toThrow();
    });
  });

  it('is refused as anything else', () => {
    const message = 'publicKey.attestation must be none, indirect, direct, or enterprise.';
    expect(check(publicKey => { publicKey.attestation = 'full'; })).toThrow(message);
    expect(check(publicKey => { publicKey.attestation = 0; })).toThrow(message);
  });
});

describe('the excluded credentials', () => {
  it('are accepted with an id, and with or without a type and transports', () => {
    expect(check(publicKey => {
      publicKey.excludeCredentials = [
        { type: 'public-key', id: { $hex: 'aa01' }, transports: ['usb', 'nfc'] },
        { id: { $base64url: 'uwI' } },
      ];
    })).not.toThrow();
  });

  it('must be an array', () => {
    expect(check(publicKey => { publicKey.excludeCredentials = { id: { $hex: 'aa01' } }; })).toThrow(
      'publicKey.excludeCredentials must be an array.',
    );
  });

  it('must each be an object, named by index', () => {
    expect(check(publicKey => { publicKey.excludeCredentials = ['aa01']; })).toThrow(
      'publicKey.excludeCredentials[0] must be an object.',
    );
  });

  it('must each be of type public-key', () => {
    expect(check(publicKey => { publicKey.excludeCredentials = [{ type: 'password', id: { $hex: 'aa01' } }]; })).toThrow(
      'publicKey.excludeCredentials[0].type must be "public-key".',
    );
  });

  it('must each have an id', () => {
    expect(check(publicKey => { publicKey.excludeCredentials = [{ type: 'public-key' }]; })).toThrow(
      'publicKey.excludeCredentials[0].id is required.',
    );
  });

  it('must each give transports as an array of text', () => {
    const message = 'publicKey.excludeCredentials[0].transports must be an array of strings.';
    expect(check(publicKey => { publicKey.excludeCredentials = [{ id: { $hex: 'aa01' }, transports: 'usb' }]; })).toThrow(message);
    expect(check(publicKey => { publicKey.excludeCredentials = [{ id: { $hex: 'aa01' }, transports: ['usb', 2] }]; })).toThrow(message);
  });
});

describe('the extensions', () => {
  it('are accepted empty', () => {
    expect(check(publicKey => { publicKey.extensions = {}; })).not.toThrow();
  });

  it('are accepted with every registration extension the editor handles', () => {
    expect(check(publicKey => {
      publicKey.extensions = {
        credProps: true,
        minPinLength: true,
        credentialProtectionPolicy: 'userVerificationOptionalWithCredentialIDList',
        enforceCredentialProtectionPolicy: false,
        largeBlob: { support: 'required' },
        prf: { eval: { first: { $hex: '01' } } },
      };
    })).not.toThrow();
  });

  it('must be an object', () => {
    expect(check(publicKey => { publicKey.extensions = ['credProps']; })).toThrow('publicKey.extensions must be an object.');
  });

  it('are refused with an extension the editor does not handle', () => {
    expect(check(publicKey => { publicKey.extensions.appidExclude = 'https://example.com'; })).toThrow(
      'publicKey.extensions contains unsupported properties: appidExclude',
    );
  });

  it('need credProps to be a boolean', () => {
    expect(check(publicKey => { publicKey.extensions.credProps = 'true'; })).toThrow(
      'publicKey.extensions.credProps must be a boolean.',
    );
  });

  it('need minPinLength to be a boolean', () => {
    expect(check(publicKey => { publicKey.extensions.minPinLength = 4; })).toThrow(
      'publicKey.extensions.minPinLength must be a boolean.',
    );
  });

  it('accept each credential protection policy CTAP defines', () => {
    ['userVerificationOptional', 'userVerificationOptionalWithCredentialIDList', 'userVerificationRequired'].forEach(policy => {
      expect(check(publicKey => { publicKey.extensions.credentialProtectionPolicy = policy; })).not.toThrow();
    });
  });

  it('refuse any other credential protection policy', () => {
    const message = 'publicKey.extensions.credentialProtectionPolicy must be a recognised policy value.';
    expect(check(publicKey => { publicKey.extensions.credentialProtectionPolicy = 'userVerificationAlways'; })).toThrow(message);
    expect(check(publicKey => { publicKey.extensions.credentialProtectionPolicy = 2; })).toThrow(message);
  });

  it('need enforceCredentialProtectionPolicy to be a boolean', () => {
    expect(check(publicKey => { publicKey.extensions.enforceCredentialProtectionPolicy = 'yes'; })).toThrow(
      'publicKey.extensions.enforceCredentialProtectionPolicy must be a boolean.',
    );
  });

  it('check largeBlob by the registration members', () => {
    expect(check(publicKey => { publicKey.extensions.largeBlob = { read: true }; })).toThrow(
      'publicKey.extensions.largeBlob contains unsupported properties: read',
    );
  });

  it('check prf', () => {
    expect(check(publicKey => { publicKey.extensions.prf = { eval: { first: {} } }; })).toThrow(
      'publicKey.extensions.prf.eval.first must be a base64url, base64, or hexadecimal value.',
    );
  });
});

describe('the hints', () => {
  it('are accepted as an array of known hints', () => {
    expect(check(publicKey => { publicKey.hints = ['security-key', 'hybrid']; })).not.toThrow();
  });

  it('are refused as text', () => {
    expect(check(publicKey => { publicKey.hints = 'security-key'; })).toThrow('publicKey.hints must be an array of strings.');
  });
});
