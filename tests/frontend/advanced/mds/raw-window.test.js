import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { openAuthenticatorRawWindow } from '../../../../frontend/static/scripts/advanced/mds/raw-window.js';

const PAYLOAD = '<img src=x onerror="document.documentElement.dataset.xss=1">';

function makeViewer() {
  const doc = document.implementation.createHTMLDocument('');
  const write = vi.spyOn(doc, 'write');
  return {
    document: doc,
    write,
    closed: false,
    focus: vi.fn(),
    resizeTo: vi.fn(),
  };
}

function open(state, overrides = {}) {
  openAuthenticatorRawWindow({
    state,
    formatDetailSubtitle: () => 'AAGUID 0000',
    getAuthenticatorRawData: (entry) => entry.raw,
    stringifyAuthenticatorRawData: (raw) => JSON.stringify(raw, null, 2),
    ...overrides,
  });
}

describe('authenticator raw window', () => {
  let viewer;

  beforeEach(() => {
    viewer = makeViewer();
    window.open = vi.fn(() => viewer);
  });

  afterEach(() => {
    delete document.documentElement.dataset.xss;
  });

  it('builds the viewer with DOM calls and a stylesheet, never from markup', () => {
    const state = { activeDetailEntry: { name: PAYLOAD, raw: { note: PAYLOAD } } };

    open(state);

    const doc = viewer.document;
    expect(viewer.write).not.toHaveBeenCalled();
    expect(doc.querySelector('style')).toBeNull();
    expect(doc.querySelector('[style*="display"]')).toBeNull();
    expect(doc.documentElement.lang).toBe('en');
    expect(doc.querySelector('link[rel="stylesheet"]').getAttribute('href'))
      .toMatch(/\/styles\/advanced\/mds-raw-window\.css$/);
    expect(doc.title).toBe(`${PAYLOAD} – Authenticator Raw Data`);
    expect(doc.getElementById('mds-raw-title').textContent).toBe(`${PAYLOAD} – Authenticator Raw Data`);
    expect(doc.getElementById('mds-raw-subtitle').textContent).toBe('AAGUID 0000');
    expect(doc.getElementById('mds-raw-subtitle').style.display).toBe('');
    const textarea = doc.getElementById('mds-raw-textarea');
    expect(textarea.value).toBe(JSON.stringify({ note: PAYLOAD }, null, 2));
    expect(textarea.readOnly).toBe(true);
    expect(textarea.getAttribute('wrap')).toBe('off');
    expect(textarea.getAttribute('aria-label')).toBe('Raw authenticator metadata');
    expect(doc.querySelector('img')).toBeNull();
    expect(document.documentElement.dataset.xss).toBeUndefined();
    expect(state.authenticatorRawWindow).toBe(viewer);
  });

  it('hides the subtitle when there is none', () => {
    open({ activeDetailEntry: { raw: { a: 1 } } }, { formatDetailSubtitle: () => '' });

    const subtitle = viewer.document.getElementById('mds-raw-subtitle');
    expect(subtitle.textContent).toBe('');
    expect(subtitle.style.display).toBe('none');
    expect(viewer.document.title).toBe('Authenticator Raw Data');
  });

  it('reuses an open viewer and replaces what it showed', () => {
    const state = { activeDetailEntry: { name: 'First', raw: { a: 1 } } };
    open(state);
    state.activeDetailEntry = { name: 'Second', raw: { b: 2 } };

    open(state);

    expect(window.open).toHaveBeenCalledTimes(1);
    expect(viewer.focus).toHaveBeenCalled();
    expect(viewer.document.querySelectorAll('.raw-window')).toHaveLength(1);
    expect(viewer.document.getElementById('mds-raw-title').textContent).toBe('Second – Authenticator Raw Data');
    expect(viewer.document.getElementById('mds-raw-textarea').value).toBe(JSON.stringify({ b: 2 }, null, 2));
  });

  it('does nothing without raw data or when the popup is blocked', () => {
    open({ activeDetailEntry: { raw: null } });
    expect(window.open).not.toHaveBeenCalled();

    window.open = vi.fn(() => null);
    const state = { activeDetailEntry: { raw: { a: 1 } } };
    open(state);
    expect(state.authenticatorRawWindow).toBeUndefined();
  });

  it('forgets the viewer when it unloads', () => {
    const state = { activeDetailEntry: { raw: { a: 1 } } };
    open(state);

    viewer.onbeforeunload();

    expect(state.authenticatorRawWindow).toBeNull();
  });
});
