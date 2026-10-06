import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { prepareAdvancedCredentialsForServerFromSource } from './advanced-server-payload.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';

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


describe("stored credentials: advanced", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prepares advanced payloads with dedupe and the highest counter", async () => {
    const advancedServerPayload = prepareAdvancedCredentialsForServerFromSource([
          {
            credentialId: 'advanced-ready',
            publicKey: 'cHVibGlj',
            signCount: 4,
            authenticatorAttachment: 'platform',
            residentKey: true,
          },
          {
            credentialId: 'advanced-ready',
            publicKey: 'cHVibGlj',
            signCount: 10,
            authenticatorAttachment: 'cross-platform',
            resident: false,
          },
          {
            credentialId: 'missing-key',
          },
        ]);
    expect(advancedServerPayload).toEqual([
          {
            credentialId: 'advanced-ready',
            publicKey: 'cHVibGlj',
            aaguid: null,
            signCount: 10,
            algorithm: undefined,
            authenticatorAttachment: 'cross-platform',
            resident: false,
          },
        ]);
  });

  it("builds advanced server payloads with the COSE key's algorithm and keeps highest signCount variant", async () => {
    const payload = prepareAdvancedCredentialsForServerFromSource([
          {
            credentialId: 'cose-derived',
            publicKey: 'pQE',
            publicKeyCose: { 1: 2, 3: -8 },
            signCount: 3,
            relyingParty: { residentKey: true },
          },
          {
            credentialId: 'cose-derived',
            publicKey: 'pQE',
            publicKeyCose: { 1: 2, 3: -8 },
            signCount: 9,
            authenticatorAttachment: 'platform',
          },
        ]);
    expect(payload).toHaveLength(1);
    expect(payload[0]).toEqual(
          expect.objectContaining({
            credentialId: 'cose-derived',
            signCount: 9,
            algorithm: -8,
            authenticatorAttachment: 'platform',
          }),
        );
    expect(payload[0].publicKey).toBe('pQE');
    expect(payload[0].resident).toBe(false);
  });
});
