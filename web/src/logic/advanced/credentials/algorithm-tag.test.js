import { describe, expect, it } from 'vitest';

import {
  describeCredentialAlgorithmTagWith,
  describeCredentialAlgorithmWith,
  resolveCredentialAlgorithmIdentifier,
} from './algorithm-tag.js';
import { describeCoseAlgorithm } from '../cose-labels.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// The saved record register-complete answers, as the characterization goldens hold it.
function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

const ES256 = storedCredential('simple-register-es256');
const MLDSA65 = storedCredential('simple-register-mldsa65');
const RS256 = storedCredential('simple-register-rs256');

// HSS-LMS (-46) is in the IANA registry but in neither the tags nor the labels.
const HSS_LMS = -46;

describe('resolveCredentialAlgorithmIdentifier', () => {
  it('reads the algorithm the server saved', () => {
    expect(resolveCredentialAlgorithmIdentifier(MLDSA65)).toBe(-49);
  });

  it('reads the COSE key when the record names no algorithm', () => {
    expect(resolveCredentialAlgorithmIdentifier({ publicKeyCose: ES256.publicKeyCose })).toBe(-7);
  });

  it('finds none in a COSE key without an algorithm', () => {
    const coseKey = { ...ES256.publicKeyCose };
    delete coseKey[3];
    expect(resolveCredentialAlgorithmIdentifier({ publicKeyCose: coseKey })).toBeNull();
  });

  it('skips an empty field and reads the next one', () => {
    expect(resolveCredentialAlgorithmIdentifier({ publicKeyAlgorithm: '  ', algorithm: -8 })).toBe(-8);
  });

  it('skips a WebCrypto algorithm object and reads the next field', () => {
    expect(resolveCredentialAlgorithmIdentifier({
      algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
      cose_alg: -7,
    })).toBe(-7);
  });

  it('reads a number written as text', () => {
    expect(resolveCredentialAlgorithmIdentifier({ coseAlgorithm: ' -257 ' })).toBe(-257);
  });

  it('reads the last number in a label', () => {
    expect(resolveCredentialAlgorithmIdentifier({ algorithm: 'ES256 (-7)' })).toBe(-7);
  });

  it('finds none in a number too large to be one', () => {
    expect(resolveCredentialAlgorithmIdentifier({ algorithm: '9'.repeat(400) })).toBeNull();
  });

  it('finds none without a record', () => {
    expect(resolveCredentialAlgorithmIdentifier(null)).toBeNull();
  });
});

describe('describeCredentialAlgorithmWith', () => {
  it('describes the saved algorithm with the COSE labels', () => {
    expect(describeCredentialAlgorithmWith(RS256, describeCoseAlgorithm)).toBe('RS256 (-257)');
  });

  it('hands the describer the raw field when it holds no number', () => {
    expect(describeCredentialAlgorithmWith({ publicKeyAlgorithm: 'EdDSA' }, (alg) => `[${alg}]`)).toBe('[EdDSA]');
  });
});

describe('describeCredentialAlgorithmTagWith', () => {
  it('tags a known algorithm with its short name', () => {
    expect(describeCredentialAlgorithmTagWith(MLDSA65, describeCoseAlgorithm)).toBe('MLDSA65');
  });

  it('tags a record without an algorithm Unknown, as the COSE labels describe it', () => {
    expect(describeCredentialAlgorithmTagWith({}, describeCoseAlgorithm)).toBe('Unknown');
  });

  it('tags an algorithm the COSE labels do not name by its identifier, not by their word "Algorithm"', () => {
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: HSS_LMS }, describeCoseAlgorithm)).toBe('COSE-46');
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: '-46' }, describeCoseAlgorithm)).toBe('COSE-46');
  });

  it('tags an unlisted algorithm with the name before its description\'s parenthesis', () => {
    const describeAlgorithm = (alg) => `HSS-LMS (${alg})`;
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: HSS_LMS }, describeAlgorithm)).toBe('HSSLMS');
  });

  it('tags an unlisted algorithm by its identifier when there is no description', () => {
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: HSS_LMS }, () => '')).toBe('COSE-46');
  });

  it('tags by the identifier when nothing comes before the description\'s parenthesis', () => {
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: HSS_LMS }, (alg) => `(${alg})`)).toBe('COSE-46');
  });

  it('tags by the identifier when the name holds no letter or digit', () => {
    expect(describeCredentialAlgorithmTagWith({ publicKeyAlgorithm: HSS_LMS }, (alg) => `— (${alg})`)).toBe('COSE-46');
  });

  it('tags a record without an algorithm or a description Unknown', () => {
    expect(describeCredentialAlgorithmTagWith({}, () => undefined)).toBe('Unknown');
  });
});
