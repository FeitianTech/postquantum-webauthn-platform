import { beforeEach, describe, expect, it, vi } from 'vitest';

// Only the hex decoder is stubbed: the real implementation runs the value through
// atob(), which throws on a hostile (non-base64) payload before the markup is ever
// built. Everything else - including base64ToBase64Url, which passes a hostile value
// through almost untouched - stays real.
vi.mock('../../../../frontend/static/scripts/shared/utils/binary.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    base64UrlToHex: vi.fn(() => 'deadbeef'),
  };
});

import {
  buildAttestationFormatSection,
  buildAuthenticatorDataSection,
  buildExtensionsSection,
  buildPublicKeySection,
  buildUserInfoSection,
} from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/sections-main.js';
import { composeRegistrationDetailHtml } from '../../../../frontend/static/scripts/advanced/credential-display/registration-compose-runtime.js';

const IMG_PAYLOAD = '<img src=x onerror="window.__xss=1">';
// describeCoseAlgorithm / resolveCredentialAlgorithmIdentifier coerce any value
// containing digits into a number, so the algorithm payloads must be digit-free to
// actually reach the raw `Algorithm (${alg})` interpolation.
const DIGITLESS_PAYLOAD = '<img src=x onerror="window.__xss=true">';

function render(html) {
  const container = document.createElement('div');
  container.innerHTML = html;
  document.body.appendChild(container);
  return container;
}

function expectRenderedAsText(html, payload) {
  const container = render(html);
  expect(container.querySelector('img')).toBeNull();
  expect(container.querySelector('script')).toBeNull();
  expect(container.textContent).toContain(payload);
  expect(window.__xss).toBeUndefined();
  return container;
}

describe('credential detail sections escape untrusted values', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    delete window.__xss;
  });

  it('would detect an unescaped interpolation', () => {
    const container = render(`<div>${IMG_PAYLOAD}</div>`);

    expect(container.querySelector('img')).not.toBeNull();
  });

  it('renders a script-bearing userName as text instead of an element', () => {
    const html = buildUserInfoSection({ userName: IMG_PAYLOAD }, '');

    expectRenderedAsText(html, IMG_PAYLOAD);
  });

  it('renders a script-bearing displayName as text instead of an element', () => {
    const html = buildUserInfoSection({ userName: 'alice', displayName: IMG_PAYLOAD }, '');

    expectRenderedAsText(html, IMG_PAYLOAD);
  });

  it('renders a script-bearing email fallback as text instead of an element', () => {
    const html = buildUserInfoSection({ email: IMG_PAYLOAD }, '');

    expectRenderedAsText(html, IMG_PAYLOAD);
  });

  it('escapes encoded identifier values taken from storage', () => {
    const html = buildUserInfoSection(
      { userName: 'alice', userHandle: IMG_PAYLOAD, credentialId: IMG_PAYLOAD },
      '',
    );

    const container = render(html);
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain(IMG_PAYLOAD);
    expect(container.querySelectorAll('.credential-code-block').length).toBe(6);
  });

  it('escapes the authenticator-reported attestation format', () => {
    expectRenderedAsText(buildAttestationFormatSection(IMG_PAYLOAD), IMG_PAYLOAD);
  });

  it('escapes authenticator-controlled client extension outputs', () => {
    const html = buildExtensionsSection({
      clientExtensionOutputs: { credProps: IMG_PAYLOAD },
    });

    // JSON.stringify backslash-escapes the payload's quotes, so assert on the
    // tag-opening fragment rather than the whole literal.
    expectRenderedAsText(html, '<img src=x onerror=');
  });

  it('escapes authenticator data flags and the signature counter', () => {
    const html = buildAuthenticatorDataSection({
      flags: {
        at: IMG_PAYLOAD,
        be: true,
        bs: false,
        ed: true,
        up: true,
        uv: true,
      },
      signCount: IMG_PAYLOAD,
    });

    expectRenderedAsText(html, IMG_PAYLOAD);
  });

  it('escapes the COSE key type fallback', () => {
    const html = buildPublicKeySection({
      publicKeyAlgorithm: -7,
      publicKeyType: DIGITLESS_PAYLOAD,
    });

    expectRenderedAsText(html, DIGITLESS_PAYLOAD);
  });

  it('escapes the COSE algorithm fallback', () => {
    const html = buildPublicKeySection({
      publicKeyCose: { 3: DIGITLESS_PAYLOAD },
    });

    expectRenderedAsText(html, DIGITLESS_PAYLOAD);
  });

  it('still renders ordinary credential detail values', () => {
    const container = render([
      buildUserInfoSection({ userName: 'alice', displayName: 'Alice Example' }, ''),
      buildAttestationFormatSection('packed'),
      buildAuthenticatorDataSection({
        flags: { at: true, be: false, bs: false, ed: false, up: true, uv: true },
        signCount: 7,
      }),
      buildPublicKeySection({ publicKeyAlgorithm: -7, publicKeyType: 2 }),
    ].join(''));

    const text = container.textContent;
    expect(text).toContain('alice');
    expect(text).toContain('Alice Example');
    expect(text).toContain('packed');
    expect(text).toContain('Signature Counter: 7');
    expect(text).toContain('AT: true');
    expect(text).toContain('UV: true');
    expect(text).toContain('ES256');
  });
});

describe('registration detail composition escapes before the HTML is persisted', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    delete window.__xss;
  });

  // The composed HTML is written into the localStorage snapshot verbatim
  // (registration-result.js) and replayed into innerHTML on later page loads, so the
  // escaping performed here is what keeps that stored copy inert.
  it('escapes hostile server and credential values in the composed markup', async () => {
    const result = await composeRegistrationDetailHtml({
      credentialJson: { id: IMG_PAYLOAD, type: 'public-key', response: {} },
      relyingPartyInfo: { userName: IMG_PAYLOAD, attestationFmt: IMG_PAYLOAD },
    });

    const container = render(result.combinedHtml || result.html);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    // The payload survives as inert text inside the JSON dumps (its quotes are
    // backslash-escaped by JSON.stringify), never as markup.
    expect(container.textContent).toContain('<img src=x onerror=');
    expect(window.__xss).toBeUndefined();
  });
});
