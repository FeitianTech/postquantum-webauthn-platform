import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import {
  clearCeremonyResult,
  showCeremonyResult,
} from '../../../../frontend/static/scripts/shared/ui/ceremony-result.js';

const SIMPLE_TAB = readFileSync('frontend/templates/simple/tab.html', 'utf8');
const ADVANCED_HEADER = readFileSync('frontend/templates/advanced/tab/header.html', 'utf8');

function panel(tab) {
  return document.getElementById(`${tab}-ceremony-result`);
}

function rows(tab) {
  return Array.from(panel(tab).querySelectorAll('dt')).map((dt) => [dt.textContent, dt.nextElementSibling.textContent]);
}

describe('ceremony result panel', () => {
  beforeEach(() => {
    document.body.innerHTML = `<div id="simple-tab">${SIMPLE_TAB}</div><div id="advanced-tab">${ADVANCED_HEADER}</div>`;
  });

  it('is in both tabs, hidden, announced politely, and not a status toast', () => {
    for (const tab of ['simple', 'advanced']) {
      expect(panel(tab).hidden).toBe(true);
      expect(panel(tab).getAttribute('role')).toBe('status');
      expect(panel(tab).getAttribute('aria-live')).toBe('polite');
      expect(panel(tab).classList.contains('status')).toBe(false);
    }
  });

  it.each([
    ['ok', 'Signature counter', '7 Higher than the last counter the server saw for this credential, as it should be.'],
    ['not-supported', 'Signature counter', '0 This authenticator keeps no counter: it reported 0, as synced passkeys do, so the counter cannot show whether it was cloned.'],
  ])('says what %s means beside the counter', (signCountStatus, label, text) => {
    showCeremonyResult('simple', {
      title: 'Last authentication',
      signCount: signCountStatus === 'ok' ? 7 : 0,
      signCountStatus,
    });

    expect(panel('simple').hidden).toBe(false);
    expect(panel('simple').querySelector('.ceremony-result__title').textContent).toBe('Last authentication');
    expect(rows('simple')).toEqual([[label, text]]);
    expect(panel('simple').dataset.verdict).toBeUndefined();
  });

  it('warns that a regressed counter may mean a cloned authenticator, and says what was done', () => {
    showCeremonyResult('simple', {
      signCount: 3,
      signCountStatus: 'regressed',
      consequence: 'Authentication was rejected.',
    });

    expect(rows('simple')).toEqual([[
      'Signature counter',
      '3 Not higher than the counter the server stored: the authenticator may have been cloned. Authentication was rejected.',
    ]]);
    expect(panel('simple').dataset.verdict).toBe('warning');
    expect(panel('simple').querySelector('.ceremony-result__title').textContent).toBe('Last ceremony');
  });

  it('shows a state it does not know as the server wrote it, as text', () => {
    showCeremonyResult('simple', { signCountStatus: '<img src=x onerror=alert(1)>' });

    expect(rows('simple')).toEqual([[
      'Signature counter',
      'The server reported "<img src=x onerror=alert(1)>".',
    ]]);
    expect(panel('simple').querySelector('img')).toBeNull();
  });

  it('says when the server gave a counter but no verdict', () => {
    showCeremonyResult('simple', { signCount: 12 });

    expect(rows('simple')[0][1]).toBe('12 The server did not say how this counter compares with the stored one.');
  });

  it.each([
    ['server-session', 'fresh', 'server-session Issued by this server for this ceremony. First use.'],
    ['client-supplied', 'not-tracked', 'client-supplied Taken from the request, not issued by this server. Not tracked for reuse.'],
    ['server-session', 'expired', 'server-session Issued by this server for this ceremony. Expired before it was used.'],
    ['somewhere-else', 'odd', 'somewhere-else The server reported "somewhere-else". The server reported "odd".'],
    [null, 'fresh', 'Its source was not reported. First use.'],
    [null, null, 'Not reported by the server.'],
  ])('says where the challenge came from: %s, %s', (challengeSource, challengeStatus, text) => {
    showCeremonyResult('advanced', { title: 'Last registration', showChallenge: true, challengeSource, challengeStatus });

    expect(rows('advanced')).toEqual([['Challenge', text]]);
  });

  it('marks a replayed challenge as a warning', () => {
    showCeremonyResult('advanced', {
      showChallenge: true,
      challengeSource: 'server-session',
      challengeStatus: 'replayed',
      signCount: 9,
      signCountStatus: 'ok',
    });

    expect(rows('advanced').map(([label]) => label)).toEqual(['Signature counter', 'Challenge']);
    expect(panel('advanced').dataset.verdict).toBe('warning');
  });

  it('hides itself when there is nothing to say, and when cleared', () => {
    showCeremonyResult('advanced', { signCount: 1, signCountStatus: 'regressed' });
    expect(panel('advanced').hidden).toBe(false);

    showCeremonyResult('advanced', {});
    expect(panel('advanced').hidden).toBe(true);
    expect(panel('advanced').dataset.verdict).toBeUndefined();

    showCeremonyResult('advanced', { signCount: 1 });
    clearCeremonyResult('advanced');
    expect(panel('advanced').hidden).toBe(true);
    expect(panel('advanced').childNodes).toHaveLength(0);
  });

  it('does nothing where the page has no panel', () => {
    document.body.innerHTML = '';

    expect(() => showCeremonyResult('simple', { signCount: 1 })).not.toThrow();
    expect(() => clearCeremonyResult('simple')).not.toThrow();
  });
});
