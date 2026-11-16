import { describe, expect, it } from 'vitest';

import { describeCeremonyResult } from './ceremony-result.js';

// What the result panel under each tab's buttons says (shared/ceremony-result.js).

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
      findings: null,
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

describe('the user handle', () => {
  it('says what the server found of it against the saved credential\'s', () => {
    const text = (userHandleStatus) => describeCeremonyResult({ userHandleStatus }).rows[0];

    expect(text('match')).toEqual({ label: 'User handle', value: 'match', text: 'The same as the saved credential\'s.', after: null });
    expect(text('mismatch').text).toBe('Not the saved credential\'s.');
    expect(text('absent').text).toBe('The authenticator returned none.');
    expect(text('not-compared').text).toBe('The saved credential keeps none to compare.');
    expect(text('elsewhere').text).toBe('The server reported "elsewhere".');
  });

  it('is shown only when the server said, after the challenge', () => {
    expect(describeCeremonyResult({ signCount: 2, signCountStatus: 'ok' }).rows.map((row) => row.label)).toEqual(['Signature counter']);
    const described = describeCeremonyResult({ signCount: 2, signCountStatus: 'ok', showChallenge: true, userHandleStatus: 'absent' });
    expect(described.rows.map((row) => row.label)).toEqual(['Signature counter', 'Challenge', 'User handle']);
    expect(described.warning).toBe(false);
  });

  it('is a warning with the finding that it is not the saved credential\'s', () => {
    const findings = { errors: ['user_handle_mismatch'], warnings: [] };
    expect(describeCeremonyResult({ userHandleStatus: 'mismatch', findings }).warning).toBe(true);
  });
});

describe('a registration\'s attestation findings', () => {
  it('are shown under the panel\'s title even without a row, an error making it a warning', () => {
    const findings = { errors: ['attestation_root_not_found'], warnings: ['metadata_not_available'] };
    expect(describeCeremonyResult({ title: 'Last registration', findings })).toEqual({
      title: 'Last registration',
      rows: [],
      findings,
      warning: true,
    });
  });

  it('are no warning when they are warnings only', () => {
    const findings = { errors: [], warnings: ['metadata_not_available'] };
    expect(describeCeremonyResult({ title: 'Last registration', findings }).warning).toBe(false);
  });

  it('follow the challenge', () => {
    const findings = { errors: ['metadata_entry_missing'], warnings: [] };
    const described = describeCeremonyResult({ showChallenge: true, challengeSource: 'server-session', challengeStatus: 'fresh', findings });
    expect(described.rows.map((row) => row.label)).toEqual(['Challenge']);
    expect([described.findings, described.warning]).toEqual([findings, true]);
  });

  it('leave the panel with nothing to say when there are none', () => {
    expect(describeCeremonyResult({ title: 'Last registration', findings: { errors: [], warnings: [] } })).toBeNull();
    expect(describeCeremonyResult({ title: 'Last registration', findings: null })).toBeNull();
  });
});

describe('a credential this browser could not keep', () => {
  const NOT_KEPT = 'This browser could not keep the credential.';

  it('is said in a row of its own, as a warning, after the others', () => {
    const described = describeCeremonyResult({ title: 'Last registration', showChallenge: true, challengeSource: 'server-session', notKept: NOT_KEPT });
    expect(described.rows.map((row) => row.label)).toEqual(['Challenge', 'This browser']);
    expect(described.rows[1]).toEqual({ label: 'This browser', value: null, text: NOT_KEPT, after: null });
    expect(described.warning).toBe(true);
  });

  it('is said beside the attestation\'s findings', () => {
    const findings = { errors: [], warnings: ['metadata_not_available'] };
    expect(describeCeremonyResult({ title: 'Last registration', findings, notKept: NOT_KEPT })).toEqual({
      title: 'Last registration',
      rows: [{ label: 'This browser', value: null, text: NOT_KEPT, after: null }],
      findings,
      warning: true,
    });
  });

  it('says nothing when the credential was kept', () => {
    expect(describeCeremonyResult({ title: 'Last registration', notKept: null })).toBeNull();
  });
});
