import { entryHashPath, routeFromHash, sectionFromHash } from './sections';

describe('the sections in the hash', () => {
  it('reads a section, and what follows it', () => {
    expect(routeFromHash('#mds')).toEqual({ section: 'mds', subPath: '' });
    expect(routeFromHash('mds')).toEqual({ section: 'mds', subPath: '' });
    expect(routeFromHash('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001')).toEqual({
      section: 'mds',
      subPath: 'aaguid:f1d0f1d0-0000-4000-8000-000000000001',
    });
    expect(routeFromHash('#mds/aaid:F1D0%230012')).toEqual({ section: 'mds', subPath: 'aaid:F1D0#0012' });
    expect(routeFromHash('#mds/')).toEqual({ section: 'mds', subPath: '' });
  });

  it('keeps a sub-path that is not well encoded as written', () => {
    expect(routeFromHash('#mds/bad%E0%A4%A')).toEqual({ section: 'mds', subPath: 'bad%E0%A4%A' });
  });

  it('reads nothing from an unknown section', () => {
    expect(routeFromHash('#elsewhere/x')).toBeNull();
    expect(routeFromHash('')).toBeNull();
    expect(sectionFromHash('#codec')).toBe('codec');
    expect(sectionFromHash('#mds/aaguid:x')).toBe('mds');
    expect(sectionFromHash('#nope')).toBeNull();
  });

  it('writes an entry id into the hash, its # encoded and its colons readable', () => {
    expect(entryHashPath('aaguid:f1d0f1d0-0000-4000-8000-000000000001')).toBe('mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(entryHashPath('aaid:F1D0#0012')).toBe('mds/aaid:F1D0%230012');
    expect(routeFromHash(`#${entryHashPath('aaid:F1D0#0012')}`)?.subPath).toBe('aaid:F1D0#0012');
  });
});
