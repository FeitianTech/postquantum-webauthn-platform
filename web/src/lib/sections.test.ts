import { certificateHashPath, entryHashPath, hashPath, routeFromHash, sectionFromHash } from './sections';

describe('the sections in the hash', () => {
  it('reads a section, and what is open in it, a segment at a time', () => {
    expect(routeFromHash('#mds')).toEqual({ section: 'mds', path: [] });
    expect(routeFromHash('mds')).toEqual({ section: 'mds', path: [] });
    expect(routeFromHash('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001')).toEqual({
      section: 'mds',
      path: ['aaguid:f1d0f1d0-0000-4000-8000-000000000001'],
    });
    expect(routeFromHash('#mds/aaid:F1D0%230012')).toEqual({ section: 'mds', path: ['aaid:F1D0#0012'] });
    expect(routeFromHash('#mds/aaid:F1D0%230012/certificate/2')).toEqual({
      section: 'mds',
      path: ['aaid:F1D0#0012', 'certificate', '2'],
    });
    expect(routeFromHash('#mds/')).toEqual({ section: 'mds', path: [] });
    expect(routeFromHash('#mds/x//certificate/')).toEqual({ section: 'mds', path: ['x', 'certificate'] });
  });

  it('keeps a segment that is not well encoded as written', () => {
    expect(routeFromHash('#mds/bad%E0%A4%A')).toEqual({ section: 'mds', path: ['bad%E0%A4%A'] });
  });

  it('reads nothing from an unknown section', () => {
    expect(routeFromHash('#elsewhere/x')).toBeNull();
    expect(routeFromHash('')).toBeNull();
    expect(sectionFromHash('#codec')).toBe('codec');
    expect(sectionFromHash('#mds/aaguid:x')).toBe('mds');
    expect(sectionFromHash('#nope')).toBeNull();
  });

  it('writes an entry id into the hash, its # and / encoded and its colons readable', () => {
    expect(entryHashPath('aaguid:f1d0f1d0-0000-4000-8000-000000000001')).toBe('mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(entryHashPath('aaid:F1D0#0012')).toBe('mds/aaid:F1D0%230012');
    expect(routeFromHash(`#${entryHashPath('aaid:F1D0#0012')}`)?.path).toEqual(['aaid:F1D0#0012']);
    expect(routeFromHash(`#${entryHashPath('entry:a/b')}`)?.path).toEqual(['entry:a/b']);
    expect(hashPath('codec')).toBe('codec');
  });

  it('writes a certificate under its entry', () => {
    expect(certificateHashPath('aaid:F1D0#0012', 3)).toBe('mds/aaid:F1D0%230012/certificate/3');
    expect(routeFromHash(`#${certificateHashPath('aaid:F1D0#0012', 3)}`)?.path).toEqual(['aaid:F1D0#0012', 'certificate', '3']);
  });
});
