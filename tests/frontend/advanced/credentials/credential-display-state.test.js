import { afterEach, describe, expect, it } from 'vitest';

import { resetRegistrationState } from '../../../../frontend/static/scripts/advanced/credential-display/registration-state.js';
import { registrationDetailState } from '../../../../frontend/static/scripts/advanced/credential-display/state.js';

// The one registration state the sanitisers and the snapshot's context default
// to (advanced/credential-display/state.js).

afterEach(() => {
  resetRegistrationState(registrationDetailState);
});

describe('the registration state', () => {
  it('starts with nothing decoded', () => {
    expect(registrationDetailState).toEqual({
      attestationObject: null,
      attestationCertificates: [],
      visibleAttestationCertificateIndices: [],
      authenticatorData: null,
      authenticatorDataHash: '',
      authenticatorDataHex: '',
    });
  });

  it('is emptied in place', () => {
    registrationDetailState.attestationObject = { fmt: 'none' };
    registrationDetailState.attestationCertificates.push({ parsedX5c: {} });
    registrationDetailState.authenticatorDataHex = '4996';
    const certificates = registrationDetailState.attestationCertificates;
    resetRegistrationState(registrationDetailState);
    expect(registrationDetailState.attestationObject).toBeNull();
    expect(registrationDetailState.attestationCertificates).toEqual([]);
    expect(registrationDetailState.attestationCertificates).not.toBe(certificates);
    expect(registrationDetailState.authenticatorDataHex).toBe('');
  });
});
