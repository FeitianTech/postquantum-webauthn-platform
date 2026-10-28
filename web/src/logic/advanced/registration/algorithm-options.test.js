import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { ALGORITHM_OPTIONS } from './algorithm-options.js';
import { registrationDefaults } from './request.js';
import { repoFile } from '@/test/logic/repo-file.js';

// The list the server's tests read too (tests/app/webauthn/test_cose_algorithms.py).
const { algorithms } = JSON.parse(readFileSync(repoFile('tests/fixtures/registration-algorithms.json'), 'utf8'));

describe('the registration form\'s algorithms', () => {
  it('list the preferred ones first, in the order both servers offer them', () => {
    expect(ALGORITHM_OPTIONS.slice(0, algorithms.length).map((option) => option.alg)).toEqual(algorithms);
    expect(ALGORITHM_OPTIONS.filter((option) => option.preferred).map((option) => option.alg)).toEqual(algorithms);
  });

  it('tick the preferred ones by default', () => {
    expect(registrationDefaults().algorithms).toEqual(algorithms);
  });

  it('offer each algorithm once', () => {
    expect(new Set(ALGORITHM_OPTIONS.map((option) => option.alg)).size).toBe(ALGORITHM_OPTIONS.length);
  });
});
