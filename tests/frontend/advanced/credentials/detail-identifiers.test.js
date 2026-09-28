import { describe, expect, it } from 'vitest';

import { buildUserInfoSection } from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/sections-main.js';
import { buildAaguidSection } from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/sections-aaguid.js';
import { extractCredentialAttestationContext } from '../../../../frontend/static/scripts/advanced/credential-display/attestation-context.js';

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

describe('the AAGUID shown in the detail view', () => {
  it('shows the all-zero AAGUID a record keeps in base64url as sixteen zero bytes', () => {
    const cred = { userName: 'alice', aaguid: 'AAAAAAAAAAAAAAAAAAAAAA' };
    const section = document.createElement('div');
    section.append(buildAaguidSection(cred, extractCredentialAttestationContext(cred)));
    const values = Array.from(section.querySelectorAll('.credential-code-block')).map((node) => node.textContent);

    expect(values).toEqual(['AAAAAAAAAAAAAAAAAAAAAA==', 'AAAAAAAAAAAAAAAAAAAAAA', '0'.repeat(32), '00000000-0000-0000-0000-000000000000']);
  });
});
