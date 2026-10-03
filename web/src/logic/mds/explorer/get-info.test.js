import { describe, expect, it } from 'vitest';

import { authenticatorInfoSection } from './get-info.js';

describe('the Authenticator Get Info section', () => {
  it('shows getInfo, its AAGUID dashed, its numbers, chips and options', () => {
    const info = authenticatorInfoSection({
      aaguid: 'F1D0F1D0000040008000000000000001',
      maxMsgSize: 1200,
      maxCredentialCountInList: 8,
      maxCredentialIdLength: 128,
      maxSerializedLargeBlobArray: 1024,
      minPINLength: 4,
      firmwareVersion: 0,
      maxCredBlobLength: 32,
      maxRPIDsForSetMinPINLength: 1,
      remainingDiscoverableCredentials: 25,
      versions: ['FIDO_2_0'],
      extensions: ['credProtect'],
      transports: ['usb'],
      algorithms: [{ type: 'public-key', alg: -7 }],
      pinUvAuthProtocols: [1, 2],
      options: { rk: true, up: false, uv: null },
    });
    expect(info.title).toBe('Authenticator Get Info');
    expect(info.fields).toEqual([
      { label: 'AAGUID', value: 'f1d0f1d0-0000-4000-8000-000000000001', identifier: true },
      { label: 'Max Message Size', value: '1200' },
      { label: 'Max Credential Count', value: '8' },
      { label: 'Max Credential ID Length', value: '128' },
      { label: 'Max Serialized Large Blob Array', value: '1024' },
      { label: 'Min PIN Length', value: '4' },
      { label: 'Firmware Version', value: '0' },
      { label: 'Max Cred Blob Length', value: '32' },
      { label: 'Max RP IDs for Set Min PIN Length', value: '1' },
      { label: 'Remaining Discoverable Credentials', value: '25' },
    ]);
    expect(info.chipLists).toEqual([
      { label: 'Versions', values: ['FIDO_2_0'] },
      { label: 'Extensions', values: ['credProtect'] },
      { label: 'Transports', values: ['usb'] },
      { label: 'Algorithms', values: ['{"type":"public-key","alg":-7}'] },
      { label: 'pinUvAuth Protocols', values: ['1', '2'] },
      { label: 'Options', values: ['rk: true', 'up: false'] },
    ]);

    // An AAGUID that is not one is shown as written; an empty getInfo still has its heading.
    expect(authenticatorInfoSection({ aaguid: 'nope', options: 'x' })).toEqual({
      key: 'authenticatorGetInfo',
      title: 'Authenticator Get Info',
      fields: [{ label: 'AAGUID', value: 'nope', identifier: true }],
      chipLists: [],
    });
    expect(authenticatorInfoSection({}).fields).toEqual([]);
    expect(authenticatorInfoSection({ options: {} }).chipLists).toEqual([]);
  });
});
