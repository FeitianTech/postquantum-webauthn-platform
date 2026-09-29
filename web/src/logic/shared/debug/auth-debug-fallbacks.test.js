import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  printAuthenticationDebug,
  printRegistrationDebug,
} from './auth.js';

let log;

// The value printed after a label, e.g. printed('hints:').
function printed(label) {
  const call = log.mock.calls.find((args) => args[0] === label);
  return call ? call[1] : undefined;
}

describe('the debug lines printed after a ceremony', () => {
  beforeEach(() => {
    log = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('fall back to their defaults for a registration with no extension results and no server answer', () => {
    printRegistrationDebug({}, {}, undefined);

    expect(printed('Resident key:')).toBe(false);
    expect(printed('Attestation (retrieve or not, plus the format):')).toBe('true, direct');
    expect(printed('challenge hex code:')).toBe('');
    expect(printed('pubkeycredparam used:')).toEqual([]);
    expect(printed('credprotect setting:')).toBe('none');
    expect(printed('largeblob:')).toBe('none');
    expect(printed('prf:')).toBe(false);
  });

  it('call a credProtect setting of 0 none', () => {
    printRegistrationDebug({ getClientExtensionResults: () => ({}) }, {}, { credProtectUsed: 0 });

    expect(printed('credprotect setting:')).toBe('none');
  });

  it('fall back to their defaults for an authentication with no extension results and no server answer', () => {
    printAuthenticationDebug({}, {}, undefined);

    expect(printed('Fake credential ID length:')).toBe(0);
    expect(printed('challenge hex code:')).toBe('');
    expect(printed('hints:')).toEqual([]);
    expect(printed('largeblob:')).toBe('none');
    expect(printed('prf eval first hex code:')).toBe('');
  });

  it('say a large blob was read from the JSON form of the extension results', () => {
    printAuthenticationDebug({ clientExtensionResults: { largeBlob: { blob: 'AQID' } } }, {}, {});

    expect(printed('largeblob:')).toBe('read');
    expect(printed('largeblob write hex code:')).toBe('010203');
  });
});
