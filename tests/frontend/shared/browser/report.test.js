import { describe, expect, it } from 'vitest';

import {
  CAPABILITY_GROUPS,
  COPIED,
  IDENTITY_FIELDS,
  NOT_REPORTED,
  NO_CAPABILITIES,
  buildReport,
  copyFailedMessage,
  copyReport,
  gatherAnalysis,
  groupCapabilities,
  omittedNote,
  reportText,
  writeToClipboard,
} from '../../../../frontend/static/scripts/shared/browser/report.js';

function capability(key, kind, state = 'yes') {
  return { key, kind, label: key, state };
}

function analysisWith(clientCapabilities) {
  return {
    generatedAt: '2026-09-25T00:00:00.000Z',
    page: 'https://example.test',
    inputs: { userAgent: 'UA', platform: 'MacIntel' },
    identity: {
      name: 'Safari',
      version: '26',
      engine: 'WebKit',
      system: 'macOS',
      sources: { name: 'user-agent', version: 'user-agent', engine: 'user-agent', system: 'user-agent' },
      onAppleWebKit: false,
    },
    webauthn: {
      facts: { secureContext: { state: 'yes' } },
      clientCapabilities,
    },
  };
}

describe('Analyze Browser report data', () => {
  it('names the identity fields and the words the views share', () => {
    expect(IDENTITY_FIELDS).toEqual(['name', 'version', 'engine', 'system']);
    expect(NOT_REPORTED).toBe('Not reported');
    expect(NO_CAPABILITIES).toBe('The browser returned no capabilities.');
    expect(COPIED).toBe('Report copied to the clipboard.');
    expect(CAPABILITY_GROUPS.map((group) => [group.kind, group.title])).toEqual([
      ['defined', 'Defined by WebAuthn Level 3'],
      ['extension', 'Extensions'],
      ['unrecognised', 'Not recognised by this page, as the browser wrote them'],
    ]);
  });

  it('gathers identity and WebAuthn facts from the scope it is given', async () => {
    function PublicKeyCredential() {}
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
    const scope = {
      isSecureContext: true,
      PublicKeyCredential,
      location: { origin: 'https://rp.example' },
      navigator: {
        userAgent:
          'Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        platform: 'Linux x86_64',
        maxTouchPoints: 0,
        credentials: { create() {}, get() {} },
      },
    };

    const analysis = await gatherAnalysis(scope);

    expect(analysis.page).toBe('https://rp.example');
    expect(Number.isNaN(Date.parse(analysis.generatedAt))).toBe(false);
    expect(analysis.inputs.userAgent).toBe(scope.navigator.userAgent);
    expect(analysis.identity.name).toBe('Mozilla Firefox');
    expect(analysis.identity.system).toBe('Linux');
    expect(analysis.webauthn.facts.userVerifyingPlatformAuthenticator).toEqual({ state: 'no' });
    expect(analysis.webauthn.clientCapabilities.state).toBe('unavailable');
  });

  it('groups capabilities, keeps defined keys in the spec order and drops empty groups', () => {
    const groups = groupCapabilities([
      capability('extension:prf', 'extension'),
      capability('signalUnknownCredential', 'defined'),
      capability('futureThing', 'unrecognised'),
      capability('conditionalGet', 'defined'),
      capability('extension:largeBlob', 'extension'),
    ]);

    expect(groups.map((group) => group.kind)).toEqual(['defined', 'extension', 'unrecognised']);
    expect(groups[0].entries.map((entry) => entry.key)).toEqual(['conditionalGet', 'signalUnknownCredential']);
    expect(groups[1].entries.map((entry) => entry.key)).toEqual(['extension:prf', 'extension:largeBlob']);
    expect(groups[1].title).toBe('Extensions');

    expect(groupCapabilities([capability('futureThing', 'unrecognised')]).map((group) => group.kind)).toEqual([
      'unrecognised',
    ]);
    expect(groupCapabilities([])).toEqual([]);
  });

  it('names the defined keys the browser left out, or nothing', () => {
    expect(omittedNote(['relatedOrigins', 'signalCurrentUserDetails'])).toBe(
      'Left out by the browser, so not known: relatedOrigins, signalCurrentUserDetails.',
    );
    expect(omittedNote([])).toBeNull();
  });

  it('builds the report from the raw findings, with a note only when there is one', () => {
    const withNote = analysisWith({
      state: 'unavailable',
      note: 'getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.',
      returned: null,
      capabilities: [],
      omitted: [],
    });
    const report = buildReport(withNote);

    expect(report).toEqual({
      report: 'Analyze Browser',
      generatedAt: '2026-09-25T00:00:00.000Z',
      page: 'https://example.test',
      identity: {
        name: 'Safari',
        version: '26',
        engine: 'WebKit',
        system: 'macOS',
        sources: withNote.identity.sources,
        inputs: withNote.inputs,
      },
      webauthn: {
        facts: withNote.webauthn.facts,
        clientCapabilities: {
          state: 'unavailable',
          note: 'getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer.',
          returned: null,
          omitted: [],
        },
      },
    });

    const withoutNote = buildReport(
      analysisWith({ state: 'yes', returned: { conditionalGet: true }, capabilities: [], omitted: ['relatedOrigins'] }),
    );
    expect(withoutNote.webauthn.clientCapabilities).toEqual({
      state: 'yes',
      returned: { conditionalGet: true },
      omitted: ['relatedOrigins'],
    });
    expect(Object.keys(withoutNote.identity)).not.toContain('onAppleWebKit');

    const text = reportText(withNote);
    expect(JSON.parse(text)).toEqual(report);
    expect(text).toContain('\n  "report": "Analyze Browser"');
  });

  describe('the clipboard', () => {
    const analysis = analysisWith({ state: 'yes', returned: {}, capabilities: [], omitted: [] });

    it('writes the text and says nothing went wrong', async () => {
      const written = [];
      const nav = { clipboard: { writeText: async (text) => written.push(text) } };

      expect(await writeToClipboard('hello', nav)).toBeNull();
      expect(written).toEqual(['hello']);

      const result = await copyReport(analysis, nav);
      expect(result).toEqual({ copied: true, message: 'Report copied to the clipboard.', text: reportText(analysis) });
      expect(written[1]).toBe(reportText(analysis));
    });

    it('says the clipboard is not available when there is none, or it cannot be read', async () => {
      expect(await writeToClipboard('x', {})).toBe('the clipboard is not available on this page');
      expect(await writeToClipboard('x', { clipboard: {} })).toBe('the clipboard is not available on this page');
      expect(await writeToClipboard('x', undefined)).toBe('the clipboard is not available on this page');
      const throwing = {};
      Object.defineProperty(throwing, 'clipboard', {
        get() {
          throw new Error('denied');
        },
      });
      expect(await writeToClipboard('x', throwing)).toBe('the clipboard is not available on this page');
    });

    it('gives the error when writing is refused, and the report to copy by hand', async () => {
      const nav = {
        clipboard: {
          writeText: async () => {
            throw new DOMException('Write permission denied.', 'NotAllowedError');
          },
        },
      };

      expect(await writeToClipboard('x', nav)).toBe('NotAllowedError: Write permission denied.');
      expect(await copyReport(analysis, nav)).toEqual({
        copied: false,
        message:
          'Could not copy the report: NotAllowedError: Write permission denied. The report is below, selected, to copy by hand.',
        text: reportText(analysis),
      });
    });

    it('ends the reason with a full stop unless it already ends a sentence', () => {
      expect(copyFailedMessage('the clipboard is not available on this page')).toBe(
        'Could not copy the report: the clipboard is not available on this page. The report is below, selected, to copy by hand.',
      );
      expect(copyFailedMessage('Blocked!')).toBe(
        'Could not copy the report: Blocked! The report is below, selected, to copy by hand.',
      );
      expect(copyFailedMessage('Why?')).toContain('report: Why? The report');
    });
  });
});
