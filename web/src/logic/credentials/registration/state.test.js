import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  addStateCertificate,
  addStateCertificates,
  createRegistrationState,
  resetRegistrationState,
  visibleStateCertificates,
} from './state.js';
import { EMPTY_STATE, decodedCertificate, describedCertificate, preparedState } from '@/test/logic/credentials/registration-state.js';

// What the registration view is built from (credentials/registration/state.js),
// over the server's recorded answers.

/** A certificate the server could not parse, as it describes one. */
const unparsed = (raw) => ({ raw, parsedX5c: { parseError: 'error parsing asn1 value' } });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createRegistrationState and resetRegistrationState', () => {
  it('starts with nothing decoded', () => {
    expect(createRegistrationState()).toEqual(EMPTY_STATE);
  });

  it('empties a state in place', async () => {
    const { state } = await preparedState();
    const same = state;
    resetRegistrationState(state);
    expect(state).toBe(same);
    expect(state).toEqual(EMPTY_STATE);
  });
});

describe('addStateCertificate', () => {
  it('keeps a certificate as the view shows it', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toEqual([
      { parsedX5c: certificate.parsedX5c, pem: certificate.pem, raw: certificate.raw },
    ]);
  });

  it('skips an entry that is not a certificate', () => {
    const state = createRegistrationState();
    addStateCertificate(state, null);
    addStateCertificate(state, 'MIIBtDCCAWagAwIBAgICHq8w');
    expect(state.attestationCertificates).toEqual([]);
  });

  it("keeps one copy of a certificate the decoder and the relying party both describe", () => {
    const state = createRegistrationState();
    addStateCertificate(state, decodedCertificate());
    addStateCertificate(state, describedCertificate());
    expect(state.attestationCertificates).toHaveLength(1);
    expect(state.attestationCertificates[0].parsedX5c).toEqual(decodedCertificate().parsedX5c);
  });

  it('replaces a copy that failed to parse with one that parsed', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, unparsed(certificate.raw));
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toHaveLength(1);
    expect(state.attestationCertificates[0].parsedX5c).toEqual(certificate.parsedX5c);
  });

  it('keeps the parsed copy when a copy that failed follows it', () => {
    const state = createRegistrationState();
    const certificate = decodedCertificate();
    addStateCertificate(state, certificate);
    addStateCertificate(state, unparsed(certificate.raw));
    expect(state.attestationCertificates[0].parsedX5c).toEqual(certificate.parsedX5c);
  });

  it('keeps a copy the state holds without details', () => {
    const certificate = decodedCertificate();
    const state = { ...createRegistrationState(), attestationCertificates: [{ raw: certificate.raw }] };
    addStateCertificate(state, certificate);
    expect(state.attestationCertificates).toEqual([{ raw: certificate.raw }]);
  });

  it('keeps each certificate it has nothing to tell apart by', () => {
    const state = createRegistrationState();
    addStateCertificate(state, decodedCertificate());
    addStateCertificate(state, { parsedX5c: { subject: 'CN=Leaf' } });
    addStateCertificate(state, { parsedX5c: { subject: 'CN=Leaf' } });
    expect(state.attestationCertificates).toHaveLength(3);
  });

  it('keeps one copy of a PEM that holds no certificate', () => {
    const state = createRegistrationState();
    const pem = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----';
    addStateCertificate(state, { pem });
    addStateCertificate(state, { pem });
    expect(state.attestationCertificates).toEqual([{ parsedX5c: { pem }, pem }]);
  });
});

describe('addStateCertificates', () => {
  it('adds each certificate of a list', () => {
    const state = createRegistrationState();
    addStateCertificates(state, [decodedCertificate(), null, { parsedX5c: { subject: 'CN=Leaf' } }]);
    expect(state.attestationCertificates).toHaveLength(2);
  });

  it('adds a single certificate', () => {
    const state = createRegistrationState();
    addStateCertificates(state, decodedCertificate());
    expect(state.attestationCertificates).toHaveLength(1);
  });

  it('adds nothing for no certificates', () => {
    const state = createRegistrationState();
    addStateCertificates(state, null);
    expect(state.attestationCertificates).toEqual([]);
  });
});

describe('visibleStateCertificates', () => {
  const first = { parsedX5c: { subject: 'CN=Leaf' } };
  const second = { parsedX5c: { subject: 'CN=CA' } };

  it('gives the certificates the view lists, in its order', () => {
    const state = { attestationCertificates: [first, second], visibleAttestationCertificateIndices: [1, 0] };
    expect(visibleStateCertificates(state)).toEqual([second, first]);
  });

  it('skips a place that holds no certificate', () => {
    const state = { attestationCertificates: [first, 'x'], visibleAttestationCertificateIndices: [0, 1, 5] };
    expect(visibleStateCertificates(state)).toEqual([first]);
  });

  it('lists none when the state names none', () => {
    expect(visibleStateCertificates({ attestationCertificates: [first], visibleAttestationCertificateIndices: null })).toEqual([]);
  });
});
