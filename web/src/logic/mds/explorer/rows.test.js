import { describe, expect, it } from 'vitest';

import {
  certificationParts,
  iconAltText,
  identifierLabel,
  statusParts,
} from './rows.js';

describe('table cells', () => {

  it('names the icon after the entry', () => {
    expect(iconAltText({ name: 'YubiKey 5' })).toBe('YubiKey 5 icon');
    expect(iconAltText({ name: '' })).toBe('Authenticator icon');
    expect(iconAltText(null)).toBe('Authenticator icon');
  });

  it('splits the certification into one badge and its detail', () => {
    expect(
      certificationParts({
        certification: 'FIDO Certified L1 • Security Key by Yubico • (U2F110020191017010)',
        latestStatus: 'FIDO Certified L1',
      }),
    ).toEqual({ level: 'FIDO Certified L1', detail: 'Security Key by Yubico • (U2F110020191017010)', tone: 'success' });
  });

  it('tones the level by what the latest status says of it', () => {
    const tone = latestStatus => certificationParts({ certification: 'FIDO Certified L2 • Key', latestStatus }).tone;
    expect(tone('FIDO Certified L2')).toBe('success');
    expect(tone('FIDO Certified L3plus')).toBe('success');
    expect(tone('Update Available')).toBe('success');
    expect(tone('Revoked')).toBe('neutral');
    expect(tone('USER KEY Physical Compromise')).toBe('neutral');
    expect(tone('NOT FIDO Certified')).toBe('neutral');
    expect(tone(undefined)).toBe('neutral');
  });

  it('shows a dash for no certification', () => {
    expect(certificationParts({ certification: '  ' })).toEqual({ level: '—', detail: '', tone: 'neutral' });
    expect(certificationParts(undefined)).toEqual({ level: '—', detail: '', tone: 'neutral' });
  });

  it('puts the latest status in one badge, in its tone', () => {
    expect(statusParts({ latestStatus: ' Revoked ' })).toEqual({ status: 'Revoked', tone: 'danger' });
    expect(statusParts({ latestStatus: 'USER KEY Remote Compromise' }).tone).toBe('danger');
    expect(statusParts({ latestStatus: 'FIDO Certified L1plus' })).toEqual({ status: 'FIDO Certified L1plus', tone: 'success' });
    expect(statusParts({ latestStatus: 'Update Available' }).tone).toBe('neutral');
    expect(statusParts({ latestStatus: '' })).toEqual({ status: '—', tone: 'neutral' });
    expect(statusParts(null)).toEqual({ status: '—', tone: 'neutral' });
  });

  it('names what the ID column holds', () => {
    expect(identifierLabel({ entryId: 'aaguid:fcb1bcb4-f370-078c-6993-bc24d0ae3fbe' })).toBe('AAGUID');
    expect(identifierLabel({ entryId: 'aaid:4e4e#4005' })).toBe('AAID');
    expect(identifierLabel({ entryId: 'akid:bf7cdd35' })).toBe('key identifier');
    expect(identifierLabel({ entryId: 'entry:0123' })).toBe('identifier');
    expect(identifierLabel({})).toBe('identifier');
  });
});
