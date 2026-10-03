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

  it('shows every member a later CTAP version added, and one no version has, named from its key', () => {
    const info = authenticatorInfoSection({
      maxPINLength: 63,
      forcePINChange: false,
      uvModality: 2,
      preferredPlatformUvAttempts: 3,
      uvCountSinceLastPinEntry: 0,
      certifications: { FIDO: 2, 'FIPS-CMVP-2': 2, none: null },
      authenticatorConfigCommands: [1, 2, 3],
      vendorPrototypeConfigCommands: [255],
      transportsForReset: ['usb', 'nfc'],
      attestationFormats: ['packed', 'none'],
      longTouchForReset: false,
      pinComplexityPolicy: true,
      pinComplexityPolicyURL: '68747470733a2f2f666978747572652e6578616d706c652f70696e',
      encIdentifier: 'AAEC',
      encCredStoreState: '',
      laterMember: { kept: true },
      laterNothing: null,
    });
    expect(info.fields).toEqual([
      { label: 'Max PIN Length', value: '63' },
      { label: 'Preferred Platform UV Attempts', value: '3' },
      { label: 'UV Modality', value: '2' },
      { label: 'UV Count Since Last PIN Entry', value: '0' },
      { label: 'Force PIN Change', value: 'false' },
      { label: 'Long Touch for Reset', value: 'false' },
      { label: 'PIN Complexity Policy', value: 'true' },
      { label: 'PIN Complexity Policy URL', value: '68747470733a2f2f666978747572652e6578616d706c652f70696e' },
      { label: 'Encrypted Identifier', value: 'AAEC' },
      { label: 'Later Member', value: '{"kept":true}' },
    ]);
    expect(info.chipLists).toEqual([
      { label: 'Transports for Reset', values: ['usb', 'nfc'] },
      { label: 'Attestation Formats', values: ['packed', 'none'] },
      { label: 'Authenticator Config Commands', values: ['1', '2', '3'] },
      { label: 'Vendor Prototype Config Commands', values: ['255'] },
      { label: 'Certifications', values: ['FIDO: 2', 'FIPS-CMVP-2: 2'] },
    ]);
    expect(authenticatorInfoSection({ certifications: ['FIDO'] }).chipLists).toEqual([]);
  });
});
