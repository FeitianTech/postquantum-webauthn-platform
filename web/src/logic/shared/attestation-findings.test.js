import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { FINDING_SENTENCES, describeFinding, describeFindings } from './attestation-findings.js';
import { repoFile } from '@/test/logic/repo-file.js';

// The codes the server's checks report, which its tests read too
// (tests/app/tooling/test_attestation_finding_codes.py).
const { codes } = JSON.parse(readFileSync(repoFile('tests/fixtures/attestation-finding-codes.json'), 'utf8'));

const CJK = /[㐀-鿿]/;

describe('the sentences', () => {
  it('give each code the server reports a sentence, and no other', () => {
    expect(Object.keys(FINDING_SENTENCES).sort()).toEqual(codes);
  });

  it('are in English and in 中文, neither ending in a full stop, so a reason can follow', () => {
    for (const [code, { en, zh }] of Object.entries(FINDING_SENTENCES)) {
      expect(en, code).toMatch(/^[A-Z]/);
      expect(en, code).not.toMatch(CJK);
      expect(zh, code).toMatch(CJK);
      expect([en.at(-1), zh.at(-1)], code).not.toContain('.');
      expect(zh.at(-1), code).not.toBe('。');
    }
  });
});

describe('a finding', () => {
  it('is said by its code\'s sentence, in each language', () => {
    expect(describeFinding('metadata_entry_missing', 'error')).toEqual({
      severity: 'error',
      label: 'Error',
      code: 'metadata_entry_missing',
      known: true,
      en: 'The metadata has no entry for this authenticator',
      zh: '元数据中没有该认证器的条目',
    });
  });

  it('gives the reason the server put after its code, after the sentence', () => {
    expect(describeFinding('certificate_out_of_validity: CN=Leaf,O=Example', 'warning')).toMatchObject({
      severity: 'warning',
      label: 'Warning',
      code: 'certificate_out_of_validity',
      known: true,
      en: 'A certificate in the attestation\'s chain is outside its validity period: CN=Leaf,O=Example',
      zh: '证明证书链中的某个证书不在有效期内: CN=Leaf,O=Example',
    });
    // The reason is all that follows the first ":", colons and all.
    expect(describeFinding('cose_key_error: Unsupported key: alg 9', 'error').en).toBe(
      'The credential\'s public key (a COSE key) could not be read: Unsupported key: alg 9',
    );
  });

  it('gives an MDS status that says the authenticator is not to be trusted after its sentence', () => {
    expect(describeFinding('metadata_status_unsafe: USER_VERIFICATION_BYPASS', 'warning')).toMatchObject({
      code: 'metadata_status_unsafe',
      known: true,
      en: 'FIDO\'s metadata says this authenticator is not to be trusted: USER_VERIFICATION_BYPASS',
      zh: 'FIDO 元数据表明不应信任该认证器: USER_VERIFICATION_BYPASS',
    });
  });

  it('gives no reason where none follows the code', () => {
    expect(describeFinding('  trust_path_missing:  ', 'warning')).toMatchObject({
      code: 'trust_path_missing',
      en: 'The attestation carries no certificate chain (x5c), so no certificate vouches for its key',
    });
  });

  it('is shown as sent when the table does not know its code, an earlier release\'s sentence too', () => {
    expect(describeFinding('No root found for Authenticator', 'error')).toEqual({
      severity: 'error',
      label: 'Error',
      code: 'No root found for Authenticator',
      known: false,
      en: 'No root found for Authenticator',
      zh: 'No root found for Authenticator',
    });
    expect(describeFinding('a_future_code: why', 'warning')).toMatchObject({
      code: 'a_future_code',
      known: false,
      en: 'a_future_code: why',
      zh: 'a_future_code: why',
    });
  });

  it('is never read as a property every object has', () => {
    expect(describeFinding('constructor', 'error')).toMatchObject({ known: false, en: 'constructor' });
    expect(describeFinding('__proto__: x', 'error')).toMatchObject({ known: false, en: '__proto__: x' });
  });
});

describe('the findings', () => {
  it('list the errors first, then the warnings, each kind in the server\'s order', () => {
    const shown = describeFindings({
      errors: ['metadata_entry_missing', 'attestation_root_not_found'],
      warnings: ['metadata_not_available'],
    });
    expect(shown.map(({ severity, code }) => [severity, code])).toEqual([
      ['error', 'metadata_entry_missing'],
      ['error', 'attestation_root_not_found'],
      ['warning', 'metadata_not_available'],
    ]);
  });

  it('are none for none', () => {
    expect(describeFindings({ errors: [], warnings: [] })).toEqual([]);
  });
});
