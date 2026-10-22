import { describe, expect, it } from 'vitest';

import { reportedResidentKey } from './resident-key.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// Whether a saved credential is discoverable (credentials/resident-key.js).

function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

describe('reportedResidentKey', () => {
  it('is credProps.rk as the browser reported it', () => {
    expect(reportedResidentKey({ clientExtensionOutputs: { credProps: { rk: true } } })).toBe(true);
    expect(reportedResidentKey({ clientExtensionOutputs: { credProps: { rk: false } } })).toBe(false);
  });

  it('reads the record the server saved', () => {
    expect(reportedResidentKey(storedCredential('simple-register-packed-x5c-extensions'))).toBe(true);
  });

  it('is null when the browser did not say', () => {
    expect(reportedResidentKey({ clientExtensionOutputs: { credProps: {} } })).toBeNull();
    expect(reportedResidentKey({ clientExtensionOutputs: { credProps: true } })).toBeNull();
    expect(reportedResidentKey({ clientExtensionOutputs: { credProps: { rk: 'true' } } })).toBeNull();
    expect(reportedResidentKey({ clientExtensionOutputs: 'credProps' })).toBeNull();
    expect(reportedResidentKey({})).toBeNull();
    expect(reportedResidentKey(null)).toBeNull();
  });

  it('never reads the residentKey an earlier version derived from the BE flag or the request', () => {
    const record = { residentKey: true, properties: { residentKey: true }, clientExtensionOutputs: { credProps: {} } };

    expect(reportedResidentKey(record)).toBeNull();
  });
});
