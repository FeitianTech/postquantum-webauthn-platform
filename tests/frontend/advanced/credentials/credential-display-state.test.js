import { afterEach, describe, expect, it } from 'vitest';

import {
  clearPendingCredentialFlash,
  getCredentialBackgroundWarmupPromise,
  getGlobalCursorApplyCount,
  getGlobalCursorPreviousValues,
  getPendingCredentialFlash,
  isCredentialDeletionInProgress,
  registrationDetailState,
  resetRegistrationDetailState,
  setCredentialBackgroundWarmupPromise,
  setCredentialDeletionInProgressFlag,
  setGlobalCursorApplyCount,
  setGlobalCursorPreviousValues,
  setPendingCredentialFlash,
} from '../../../../frontend/static/scripts/advanced/credential-display/state.js';

// The current UI's one registration state and the saved list's flags
// (advanced/credential-display/state.js).

afterEach(() => {
  resetRegistrationDetailState();
  setGlobalCursorApplyCount(0);
  setGlobalCursorPreviousValues([]);
  clearPendingCredentialFlash();
  setCredentialBackgroundWarmupPromise(null);
  setCredentialDeletionInProgressFlag(false);
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
    resetRegistrationDetailState();
    expect(registrationDetailState.attestationObject).toBeNull();
    expect(registrationDetailState.attestationCertificates).toEqual([]);
    expect(registrationDetailState.attestationCertificates).not.toBe(certificates);
    expect(registrationDetailState.authenticatorDataHex).toBe('');
  });
});

describe("the cursor's count and saved values", () => {
  it('keeps a count that is a finite number', () => {
    setGlobalCursorApplyCount(2);
    expect(getGlobalCursorApplyCount()).toBe(2);
  });

  it('counts zero for anything else', () => {
    setGlobalCursorApplyCount(2);
    setGlobalCursorApplyCount(Number.POSITIVE_INFINITY);
    expect(getGlobalCursorApplyCount()).toBe(0);
    setGlobalCursorApplyCount('2');
    expect(getGlobalCursorApplyCount()).toBe(0);
  });

  it('keeps a list of saved values', () => {
    const values = [{ element: 'body', cursor: 'wait' }];
    setGlobalCursorPreviousValues(values);
    expect(getGlobalCursorPreviousValues()).toBe(values);
  });

  it('keeps no saved values for anything but a list', () => {
    setGlobalCursorPreviousValues({ cursor: 'wait' });
    expect(getGlobalCursorPreviousValues()).toEqual([]);
  });
});

describe('the pending flash', () => {
  it('keeps the credential to flash until cleared', () => {
    const flash = { credentialKey: 'simple:AQID' };
    setPendingCredentialFlash(flash);
    expect(getPendingCredentialFlash()).toBe(flash);
    clearPendingCredentialFlash();
    expect(getPendingCredentialFlash()).toBeNull();
  });

  it('keeps nothing for an empty value', () => {
    setPendingCredentialFlash({ credentialKey: 'simple:AQID' });
    setPendingCredentialFlash('');
    expect(getPendingCredentialFlash()).toBeNull();
  });
});

describe('the warm-up and the deletion flag', () => {
  it('keeps the warm-up under way, or none', () => {
    const warmup = Promise.resolve();
    setCredentialBackgroundWarmupPromise(warmup);
    expect(getCredentialBackgroundWarmupPromise()).toBe(warmup);
    setCredentialBackgroundWarmupPromise(undefined);
    expect(getCredentialBackgroundWarmupPromise()).toBeNull();
  });

  it('keeps whether a deletion is under way as a boolean', () => {
    setCredentialDeletionInProgressFlag('yes');
    expect(isCredentialDeletionInProgress()).toBe(true);
    setCredentialDeletionInProgressFlag(0);
    expect(isCredentialDeletionInProgress()).toBe(false);
  });
});
