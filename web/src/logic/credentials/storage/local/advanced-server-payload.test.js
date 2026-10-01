import { describe, expect, it } from 'vitest';

import {
  prepareAdvancedCredentialsForServerFromSource,
} from './advanced-server-payload.js';

// From tests/app/characterization/golden/routes/advanced-register-none-es256.json.
const CREDENTIAL_ID = 'THBi3GyG-MexchMynbz3x5NvGe5iGSPJDYpBGvL7i9Y';
const PUBLIC_KEY = 'pQECAyYgASFYIDMAqV_ceu7i7Gw9sutq4PjEPKbbjqmToYzZWR03vPwCIlggivkDu6wVP_oBEKxHEVurqEqp4Q7zkRyxRmqawViw2Lg';

function credential(fields = {}) {
  return { type: 'advanced', credentialId: CREDENTIAL_ID, publicKey: PUBLIC_KEY, ...fields };
}

describe('the advanced credentials sent to the server', () => {
  it('are none when there is no list', () => {
    expect(prepareAdvancedCredentialsForServerFromSource(null)).toEqual([]);
  });

  it('are none when the list is empty', () => {
    expect(prepareAdvancedCredentialsForServerFromSource([])).toEqual([]);
  });

  it('leave out a credential without an id', () => {
    expect(prepareAdvancedCredentialsForServerFromSource([
      credential({ credentialId: undefined }),
    ])).toEqual([]);
  });

  it('take the public key from its bytes when no other spelling is there', () => {
    const [prepared] = prepareAdvancedCredentialsForServerFromSource([
      credential({ publicKey: undefined, publicKeyBytes: PUBLIC_KEY }),
    ]);

    expect(prepared.publicKey).toBe(PUBLIC_KEY);
  });

  it('leave out a credential that holds no public key the server can read', () => {
    expect(prepareAdvancedCredentialsForServerFromSource([
      credential({ publicKey: undefined, publicKeyCose: { 1: 2, 3: -7 } }),
    ])).toEqual([]);
  });

  it('send the algorithm the record names, or its COSE key\'s', () => {
    const [named, cose] = prepareAdvancedCredentialsForServerFromSource([
      credential({ publicKeyAlgorithm: -8 }),
      credential({ credentialId: 'AQID', publicKeyCose: { 1: 2, 3: -7 } }),
    ]);

    expect([named.algorithm, cose.algorithm]).toEqual([-8, -7]);
  });

  it('send the AAGUID in base64url', () => {
    const [prepared] = prepareAdvancedCredentialsForServerFromSource([
      credential({ aaguid: 'ABEiM0RVZneImaq7zN3u/w==' }),
    ]);

    expect(prepared.aaguid).toBe('ABEiM0RVZneImaq7zN3u_w');
  });

  it('count a sign count that is not a number as zero', () => {
    const [prepared] = prepareAdvancedCredentialsForServerFromSource([
      credential({ signCount: '7' }),
    ]);

    expect(prepared.signCount).toBe(0);
  });

  it('keep the copy with the higher sign count when an id repeats', () => {
    const prepared = prepareAdvancedCredentialsForServerFromSource([
      credential({ signCount: 5, authenticatorAttachment: 'platform' }),
      credential({ signCount: 2, authenticatorAttachment: 'cross-platform' }),
    ]);

    expect(prepared).toHaveLength(1);
    expect(prepared[0]).toMatchObject({ signCount: 5, authenticatorAttachment: 'platform' });
  });
});
