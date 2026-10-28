import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { recordFindings } from './findings.js';
import { repoFile } from '@/test/logic/repo-file.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// A saved credential's attestation findings (credentials/detail/findings.js),
// over the records the server answered (characterization goldens) and one an
// earlier release saved (the stored-records recording).
const stored = (scenario) => goldenAnswers(scenario)
    .find(({ request, status }) => request.includes('/register/complete') && status === 200).body.storedCredential;

describe('a saved credential\'s findings', () => {
  it('are a Simple record\'s checks: its warnings', () => {
    expect(recordFindings(stored('simple-register-packed-self'))).toEqual({
      errors: [],
      warnings: ['metadata_not_available', 'trust_path_missing'],
    });
  });

  it('are an Advanced record\'s summary, which it keeps without its checks', () => {
    const record = stored('advanced-register-mldsa44-self');
    expect(record.properties.attestationChecks).toBeUndefined();
    expect(recordFindings(record)).toEqual({ errors: ['trust_path_missing'], warnings: ['metadata_not_available'] });
  });

  it('are what an earlier release saved, its sentence for a missing root too', () => {
    const { records } = JSON.parse(readFileSync(repoFile('web/e2e/recorded/stored-records/records.json'), 'utf8'));
    expect(recordFindings(records.find((record) => record.type === 'advanced'))).toEqual({
      errors: ['No root found for Authenticator', 'metadata_entry_missing'],
      warnings: [],
    });
    expect(recordFindings(records.find((record) => record.type === 'simple'))).toEqual({ errors: [], warnings: [] });
  });

  it('take the checks at the record\'s top before its summary, each list where it is first', () => {
    const record = {
      attestationChecks: { errors: ['origin_mismatch'] },
      properties: { attestationSummary: { errors: ['ignored'], warnings: ['metadata_not_available'] } },
    };
    expect(recordFindings(record)).toEqual({ errors: ['origin_mismatch'], warnings: ['metadata_not_available'] });
  });

  it('are none for a record that keeps none', () => {
    expect(recordFindings({ type: 'simple', credentialId: 'AQID' })).toEqual({ errors: [], warnings: [] });
  });
});
