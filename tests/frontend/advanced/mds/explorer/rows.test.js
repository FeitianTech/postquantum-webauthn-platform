import { describe, expect, it } from 'vitest';

import {
  MISSING_CELL_TEXT,
  NO_ICON_TEXT,
  certificationParts,
  iconAltText,
  identifierLabel,
} from '../../../../../frontend/static/scripts/advanced/mds/explorer/rows.js';

describe('table cells', () => {
  it('keeps the fallbacks', () => {
    expect(MISSING_CELL_TEXT).toBe('—');
    expect(NO_ICON_TEXT).toBe('N/A');
  });

  it('names the icon after the entry', () => {
    expect(iconAltText({ name: 'YubiKey 5' })).toBe('YubiKey 5 icon');
    expect(iconAltText({ name: '' })).toBe('Authenticator icon');
    expect(iconAltText(null)).toBe('Authenticator icon');
  });

  it('splits the certification into one badge and its detail', () => {
    expect(
      certificationParts({
        certification: 'FIDO Certified L1 • Security Key by Yubico • (U2F110020191017010)',
        certificationStatus: 'FIDO_CERTIFIED_L1',
      }),
    ).toEqual({ level: 'FIDO Certified L1', detail: 'Security Key by Yubico • (U2F110020191017010)', tone: 'success' });
    expect(certificationParts({ certification: 'NOT FIDO Certified', certificationStatus: 'NOT_FIDO_CERTIFIED' })).toEqual({
      level: 'NOT FIDO Certified',
      detail: '',
      tone: 'neutral',
    });
    expect(certificationParts({ certification: 'Revoked', certificationStatus: 'REVOKED' }).tone).toBe('danger');
    expect(certificationParts({ certification: 'Attestation Key Compromise' }).tone).toBe('danger');
    expect(certificationParts({ certification: 'FIDO Certified L2 • Old' }).tone).toBe('success');
    expect(certificationParts({ certification: 'Update Available' }).tone).toBe('neutral');
  });

  it('shows a dash for no certification', () => {
    expect(certificationParts({ certification: '  ' })).toEqual({ level: '—', detail: '', tone: 'neutral' });
    expect(certificationParts(undefined)).toEqual({ level: '—', detail: '', tone: 'neutral' });
  });

  it('names what the ID column holds', () => {
    expect(identifierLabel({ entryId: 'aaguid:fcb1bcb4-f370-078c-6993-bc24d0ae3fbe' })).toBe('AAGUID');
    expect(identifierLabel({ entryId: 'aaid:4e4e#4005' })).toBe('AAID');
    expect(identifierLabel({ entryId: 'akid:bf7cdd35' })).toBe('key identifier');
    expect(identifierLabel({ entryId: 'entry:0123' })).toBe('identifier');
    expect(identifierLabel({})).toBe('identifier');
  });
});
