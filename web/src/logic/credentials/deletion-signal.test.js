import { describe, expect, it, vi } from 'vitest';

import { SIGNAL_TEXT, canSignalDeletion, credentialRpId, signalDeletedCredential } from './deletion-signal.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// Telling the browser a deleted credential is gone (credentials/deletion-signal.js),
// through a stand-in for the page's global: its host, its WebCrypto, and a
// PublicKeyCredential whose signalUnknownCredential is a stub.

// A Simple registration the server answered for the RP ID "localhost".
const REGISTERED = goldenAnswers('simple-register-es256').find(({ body }) => body && body.storedCredential).body.storedCredential;

function page(hostname, signalUnknownCredential = vi.fn(async () => undefined)) {
  return { location: { hostname }, crypto: globalThis.crypto, PublicKeyCredential: { signalUnknownCredential } };
}

async function sha256Hex(text) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('canSignalDeletion', () => {
  it('is whether the browser has signalUnknownCredential', () => {
    expect(canSignalDeletion(page('localhost'))).toBe(true);
    expect(canSignalDeletion({ PublicKeyCredential: { signalUnknownCredential: 'yes' } })).toBe(false);
    expect(canSignalDeletion({ PublicKeyCredential: class {} })).toBe(false);
    expect(canSignalDeletion({})).toBe(false);
  });

  it('reads the page\'s global by default', () => {
    expect(canSignalDeletion()).toBe(typeof globalThis.PublicKeyCredential?.signalUnknownCredential === 'function');
  });

  it('has a sentence for one credential and for all of them', () => {
    expect(SIGNAL_TEXT.one).toBe('This browser will also be told the credential is gone, so its passkey manager may remove it.');
    expect(SIGNAL_TEXT.all).toBe('This browser will also be told the credentials are gone, so its passkey manager may remove them.');
  });
});

describe('credentialRpId', () => {
  it('is the page\'s host whose hash the record keeps', async () => {
    expect(REGISTERED.properties.rpIdHash).toBe(await sha256Hex('localhost'));
    expect(await credentialRpId(REGISTERED, 'localhost', page('localhost'))).toBe('localhost');
  });

  it('is the domain above the host whose hash the record keeps', async () => {
    const record = { relyingParty: { rpIdHash: (await sha256Hex('example.com')).toUpperCase() } };
    expect(await credentialRpId(record, 'login.example.com', page('login.example.com'))).toBe('example.com');
  });

  it('is the page\'s host when the record keeps no hash, or one no domain here has', async () => {
    expect(await credentialRpId({}, 'login.example.com', page('login.example.com'))).toBe('login.example.com');
    const elsewhere = { properties: { rpIdHash: await sha256Hex('example.org') } };
    expect(await credentialRpId(elsewhere, 'login.example.com', page('login.example.com'))).toBe('login.example.com');
  });

  it('hashes with the page\'s own WebCrypto by default', async () => {
    expect(await credentialRpId(REGISTERED, 'localhost')).toBe('localhost');
  });
});

describe('signalDeletedCredential', () => {
  it('tells the browser the credential\'s RP ID and its ID in base64url', async () => {
    const scope = page('localhost');
    expect(await signalDeletedCredential(REGISTERED, scope)).toBe(true);
    expect(scope.PublicKeyCredential.signalUnknownCredential).toHaveBeenCalledExactlyOnceWith({
      rpId: 'localhost',
      credentialId: REGISTERED.credentialIdBase64Url,
    });
  });

  it('reads the credential ID in any spelling a record keeps', async () => {
    const scope = page('example.com');
    expect(await signalDeletedCredential({ credentialId: '010203ff' }, scope)).toBe(true);
    expect(scope.PublicKeyCredential.signalUnknownCredential).toHaveBeenCalledWith({ rpId: 'example.com', credentialId: 'AQID_w' });
  });

  it('tells nothing for a record without a credential ID, or to a browser without the method', async () => {
    const scope = page('localhost');
    expect(await signalDeletedCredential({ userName: 'alice' }, scope)).toBe(false);
    expect(scope.PublicKeyCredential.signalUnknownCredential).not.toHaveBeenCalled();
    expect(await signalDeletedCredential(REGISTERED, { location: { hostname: 'localhost' } })).toBe(false);
    expect(await signalDeletedCredential(REGISTERED)).toBe(canSignalDeletion());
  });

  it('never rejects, whatever the browser does', async () => {
    const refused = page('localhost', vi.fn(async () => {
      throw new DOMException('The RP ID is not valid for this origin.', 'SecurityError');
    }));
    expect(await signalDeletedCredential(REGISTERED, refused)).toBe(false);
    const thrown = page('localhost', vi.fn(() => {
      throw new TypeError('signalUnknownCredential: invalid options');
    }));
    expect(await signalDeletedCredential(REGISTERED, thrown)).toBe(false);
  });
});
