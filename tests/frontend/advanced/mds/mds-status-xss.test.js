import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setStatus } from '../../../../frontend/static/scripts/advanced/mds/status-controls.js';

const IMG_PAYLOAD = '<img src=x onerror="window.__xss=1">';

function createState() {
  const statusEl = document.createElement('div');
  statusEl.id = 'mds-status';
  statusEl.className = 'mds-status mds-status-info';
  document.body.appendChild(statusEl);

  return {
    statusEl,
    defaultStatus: null,
    statusResetTimer: null,
  };
}

describe('mds status rendering escapes untrusted messages', () => {
  let state;

  beforeEach(() => {
    document.body.innerHTML = '';
    delete window.__xss;
    state = createState();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('would detect an unescaped interpolation', () => {
    state.statusEl.innerHTML = IMG_PAYLOAD;

    expect(state.statusEl.querySelector('img')).not.toBeNull();
  });

  it('renders a script-bearing error message as text instead of an element', () => {
    setStatus(state, IMG_PAYLOAD, 'error');

    expect(state.statusEl.querySelector('img')).toBeNull();
    expect(state.statusEl.textContent).toBe(IMG_PAYLOAD);
    expect(state.statusEl.classList.contains('mds-status-error')).toBe(true);
    expect(window.__xss).toBeUndefined();
  });

  it('renders a script-bearing metadata-derived message as text', () => {
    setStatus(state, `Loaded 2 authenticators. ${IMG_PAYLOAD}`, 'success');

    expect(state.statusEl.querySelector('img')).toBeNull();
    expect(state.statusEl.textContent).toContain('Loaded 2 authenticators.');
    expect(state.statusEl.textContent).toContain(IMG_PAYLOAD);
  });

  it('replays the stored default status as text, not markup', () => {
    vi.useFakeTimers();
    state.defaultStatus = { text: IMG_PAYLOAD, variant: 'info', title: '' };

    setStatus(state, 'Temporary notice.', 'success', { restoreDefault: true, delay: 10 });
    expect(state.statusEl.textContent).toBe('Temporary notice.');

    vi.advanceTimersByTime(20);

    expect(state.statusEl.querySelector('img')).toBeNull();
    expect(state.statusEl.textContent).toBe(IMG_PAYLOAD);
    expect(state.statusEl.classList.contains('mds-status-info')).toBe(true);
    expect(window.__xss).toBeUndefined();
  });

  it('restores the default title alongside the default text', () => {
    vi.useFakeTimers();
    state.defaultStatus = { text: 'Loaded 3 authenticators.', variant: 'success', title: 'Legal header' };

    setStatus(state, 'Refreshing…', 'info', { restoreDefault: true, delay: 5 });
    vi.advanceTimersByTime(10);

    expect(state.statusEl.textContent).toBe('Loaded 3 authenticators.');
    expect(state.statusEl.getAttribute('title')).toBe('Legal header');
    expect(state.statusEl.classList.contains('mds-status-success')).toBe(true);
  });

  it('renders an empty string for nullish messages', () => {
    setStatus(state, 'Something', 'info');
    setStatus(state, null, 'info');

    expect(state.statusEl.textContent).toBe('');
  });

  it('ignores calls without a status element', () => {
    expect(() => setStatus({ statusEl: null }, IMG_PAYLOAD, 'error')).not.toThrow();
  });
});
