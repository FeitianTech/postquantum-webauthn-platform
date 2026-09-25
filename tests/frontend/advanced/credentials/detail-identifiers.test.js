import { describe, expect, it } from 'vitest';

import { buildUserInfoSection } from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/sections-main.js';

function identifierRows(section) {
  const values = Array.from(section.querySelectorAll('.credential-code-block')).map((node) => node.textContent);
  return { b64: values[0], b64u: values[1], hex: values[2] };
}

describe('the credential ID shown in the detail view', () => {
  it('shows each spelling of the bytes the stored base64url holds', () => {
    // The browser's credential.id, base64url, is what the advanced tab stores.
    const section = buildUserInfoSection({ userName: 'alice', credentialId: '-_8BAg' }, null);

    expect(identifierRows(section)).toEqual({ b64: '+/8BAg==', b64u: '-_8BAg', hex: 'fbff0102' });
  });

  it('shows a value that is not base64url as stored, and says so', () => {
    const section = buildUserInfoSection({ userName: 'alice', userHandle: '+/8BAg==' }, null);

    expect(identifierRows(section).b64).toBe('+/8BAg==');
    expect(section.textContent).toContain('Not valid base64url: shown as stored.');
  });
});
