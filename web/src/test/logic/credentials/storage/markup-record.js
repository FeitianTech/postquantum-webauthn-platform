const MARKUP = '<section><img src=x onerror="window.__xss=1"></section>';

export function savedRecord() {
  return {
    type: 'advanced',
    credentialId: 'AQID',
    storageId: 'AQID::storage',
    userName: 'alice',
    registrationDetailSnapshot: {
      schemaVersion: 1,
      html: MARKUP,
      attestationSectionHtml: MARKUP,
      combinedHtml: MARKUP,
      state: { authenticatorDataHex: '0a0b' },
    },
  };
}
