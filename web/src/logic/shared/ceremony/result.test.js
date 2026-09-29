import { describe, expect, it } from 'vitest';

import { describeCeremonyResult } from './result.js';

// What the result panel under each tab's buttons says (shared/ceremony/result.js).

describe('the signature counter', () => {
  it('says nothing without a number or a verdict', () => {
    expect(describeCeremonyResult()).toBeNull();
    expect(describeCeremonyResult({ title: 'Last authentication', signCount: Number.NaN })).toBeNull();
  });

  it('gives the number and the server\'s verdict, under the caller\'s title', () => {
    expect(describeCeremonyResult({ title: 'Last authentication', signCount: 6, signCountStatus: 'ok' })).toEqual({
      title: 'Last authentication',
      rows: [{
        label: 'Signature counter',
        value: '6',
        text: 'Higher than the last counter the server saw for this credential, as it should be.',
        after: null,
      }],
      warning: false,
    });
  });

  it('says a counter the authenticator does not keep', () => {
    const [row] = describeCeremonyResult({ signCount: 0, signCountStatus: 'not-supported' }).rows;
    expect(row.text).toBe(
      'This authenticator keeps no counter: it reported 0, as synced passkeys do, so the counter cannot show whether it was cloned.',
    );
  });

  it('warns of a counter that went backwards, with what the tab did about it', () => {
    const described = describeCeremonyResult({ signCountStatus: 'regressed', consequence: 'Authentication was rejected.' });
    expect(described.warning).toBe(true);
    expect(described.rows[0]).toEqual({
      label: 'Signature counter',
      value: null,
      text: 'Not higher than the counter the server stored: the authenticator may have been cloned.',
      after: 'Authentication was rejected.',
    });
  });

  it('adds a consequence only to a counter that went backwards', () => {
    expect(describeCeremonyResult({ signCountStatus: 'ok', consequence: 'Authentication was rejected.' }).rows[0].after).toBeNull();
  });

  it('repeats a verdict it does not know, and says when there is none', () => {
    expect(describeCeremonyResult({ signCountStatus: 'toString' }).rows[0].text).toBe('The server reported "toString".');
    expect(describeCeremonyResult({ signCount: 3 }).rows[0].text).toBe(
      'The server did not say how this counter compares with the stored one.',
    );
  });

  it('is titled "Last ceremony" when the caller gives no title', () => {
    expect(describeCeremonyResult({ signCount: 1 }).title).toBe('Last ceremony');
  });
});

describe('the challenge', () => {
  it('is shown only when the caller asks for it', () => {
    expect(describeCeremonyResult({ challengeSource: 'server-session' })).toBeNull();
  });

  it('says where it came from and whether it was used before', () => {
    const [row] = describeCeremonyResult({ showChallenge: true, challengeSource: 'server-session', challengeStatus: 'fresh' }).rows;
    expect(row).toEqual({
      label: 'Challenge',
      value: 'server-session',
      text: 'Issued by this server for this ceremony.',
      after: 'First use.',
    });
  });

  it('warns of a replayed challenge', () => {
    const described = describeCeremonyResult({ showChallenge: true, challengeSource: 'server-session', challengeStatus: 'replayed' });
    expect(described.warning).toBe(true);
    expect(described.rows[0].text).toBe('Issued by this server for this ceremony.');
    expect(described.rows[0].after).toBe('Used before: this is a replay.');
  });

  it('says what the server did not report', () => {
    expect(describeCeremonyResult({ showChallenge: true }).rows[0]).toEqual({
      label: 'Challenge',
      value: null,
      text: 'Not reported by the server.',
      after: null,
    });
    const [row] = describeCeremonyResult({ showChallenge: true, challengeStatus: 'expired' }).rows;
    expect([row.value, row.text, row.after]).toEqual([null, 'Its source was not reported.', 'Expired before it was used.']);
  });

  it('repeats a source or status it does not know, and leaves out a missing status', () => {
    const [row] = describeCeremonyResult({ showChallenge: true, challengeSource: 'elsewhere', challengeStatus: 'odd' }).rows;
    expect([row.text, row.after]).toEqual(['The server reported "elsewhere".', 'The server reported "odd".']);
    expect(describeCeremonyResult({ showChallenge: true, challengeSource: 'server-session' }).rows[0].after).toBeNull();
  });

  it('follows the counter when both are shown', () => {
    const described = describeCeremonyResult({ signCount: 2, signCountStatus: 'ok', showChallenge: true });
    expect(described.rows.map((row) => row.label)).toEqual(['Signature counter', 'Challenge']);
  });
});
