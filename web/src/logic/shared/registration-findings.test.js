import { describe, expect, it } from 'vitest';

import { FINDINGS_TITLE, answerFindings, findingList, hasFindings } from './registration-findings.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// The register-complete answers the server gave (characterization goldens).
const complete = (scenario, status = 200) => goldenAnswers(scenario)
    .find(({ request, status: given }) => request.includes('/register/complete') && given === status).body;

describe('a registration answer\'s findings', () => {
  it('are an Advanced registration\'s errors and warnings, as the server listed them', () => {
    expect(answerFindings(complete('advanced-register-mldsa44-self'))).toEqual({
      errors: ['trust_path_missing'],
      warnings: ['metadata_not_available'],
    });
  });

  it('are a Simple registration\'s warnings: an error would have refused it', () => {
    expect(answerFindings(complete('simple-register-packed-self'))).toEqual({
      errors: [],
      warnings: ['metadata_not_available', 'trust_path_missing'],
    });
  });

  it('are the errors a refused Simple registration answered with', () => {
    expect(answerFindings(complete('simple-register-failures', 400))).toEqual({ errors: [], warnings: [] });
    const refused = goldenAnswers('simple-register-failures').find(({ body }) => 'attestationErrors' in body).body;
    expect(answerFindings(refused)).toEqual({ errors: ['cross_origin_not_allowed'], warnings: [] });
  });

  it('are none for an answer without any, or for no answer', () => {
    expect(answerFindings(complete('simple-register-es256'))).toEqual({ errors: [], warnings: [] });
    expect(answerFindings(null)).toEqual({ errors: [], warnings: [] });
    expect(answerFindings(undefined)).toEqual({ errors: [], warnings: [] });
  });
});

describe('a list of findings', () => {
  it('keeps the server\'s strings, trimmed, and leaves out blank ones and anything else', () => {
    expect(findingList([' metadata_entry_missing ', '', '  ', 7, null, { code: 'x' }, 'cose_key_error: 3'])).toEqual([
      'metadata_entry_missing',
      'cose_key_error: 3',
    ]);
  });

  it('is empty for a value that is not a list', () => {
    expect(findingList('metadata_entry_missing')).toEqual([]);
    expect(findingList(undefined)).toEqual([]);
  });
});

describe('whether there is a finding to show', () => {
  it('is so for an error or a warning, and not for none', () => {
    expect(hasFindings({ errors: ['origin_mismatch'], warnings: [] })).toBe(true);
    expect(hasFindings({ errors: [], warnings: ['metadata_not_available'] })).toBe(true);
    expect(hasFindings({ errors: [], warnings: [] })).toBe(false);
    expect(hasFindings(null)).toBe(false);
  });

  it('is titled as the page titles the list', () => {
    expect(FINDINGS_TITLE).toBe('Verification findings');
  });
});
