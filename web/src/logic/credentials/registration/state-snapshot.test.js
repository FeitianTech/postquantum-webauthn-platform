import { describe, expect, it } from 'vitest';

import { EMPTY_DETAIL_PREPARATION, createRegistrationState } from './state.js';
import {
  applyRegistrationSnapshot,
  captureRegistrationState,
  normaliseDetailPreparationSnapshot,
} from './state-snapshot.js';
import { registration } from '@/test/logic/credentials/registration-detail-answers.js';
import { EMPTY_STATE, decodedCertificate, describedCertificate, preparedState } from '@/test/logic/credentials/registration-state.js';

// A registration state as a saved snapshot keeps it, and back
// (credentials/registration/state-snapshot.js), over the server's recorded answers.

describe('normaliseDetailPreparationSnapshot', () => {
  it('keeps what a snapshot said about the decodes', () => {
    const said = {
      attestationObjectValue: 'o2Nm',
      attestationDecodeError: 'The payload is not valid CBOR.',
      authenticatorDataValue: 'SZYN',
      authenticatorDecodeError: '',
    };
    expect(normaliseDetailPreparationSnapshot({ ...said, extra: true })).toEqual(said);
  });

  it('gives empty sentences for what is not text', () => {
    expect(normaliseDetailPreparationSnapshot({
      attestationObjectValue: 1, attestationDecodeError: null, authenticatorDataValue: {}, authenticatorDecodeError: [],
    })).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('gives a fresh copy of the empty sentences without a snapshot', () => {
    const answer = normaliseDetailPreparationSnapshot(null);
    expect(answer).toEqual(EMPTY_DETAIL_PREPARATION);
    expect(answer).not.toBe(EMPTY_DETAIL_PREPARATION);
  });
});

describe('captureRegistrationState', () => {
  it('copies the state as a snapshot keeps it, with what it said about the decodes', async () => {
    const { state, preparation } = await preparedState('packedX5c');
    state.visibleAttestationCertificateIndices = [0];
    const captured = captureRegistrationState(state, preparation);
    expect(captured).toEqual({
      detailPreparation: preparation,
      attestationObject: state.attestationObject,
      attestationCertificates: state.attestationCertificates,
      visibleAttestationCertificateIndices: [0],
      authenticatorData: state.authenticatorData,
      authenticatorDataHex: state.authenticatorDataHex,
      authenticatorDataHash: state.authenticatorDataHash,
    });
  });

  it('keeps copies the state can no longer change', async () => {
    const { state } = await preparedState('packedX5c');
    const captured = captureRegistrationState(state);
    state.attestationObject.fmt = 'none';
    state.attestationCertificates.push({ parsedX5c: {} });
    expect(captured.attestationObject.fmt).toBe('packed');
    expect(captured.attestationCertificates).toHaveLength(1);
  });

  it('says nothing about the decodes when not told', () => {
    expect(captureRegistrationState(createRegistrationState())).toEqual({ ...EMPTY_STATE, detailPreparation: EMPTY_DETAIL_PREPARATION });
  });

  it('captures empty values for parts of the wrong kind', () => {
    for (const attestationCertificates of [null, { 0: 'MIIB' }]) {
      const captured = captureRegistrationState({
        attestationObject: 'o2Nm',
        attestationCertificates,
        visibleAttestationCertificateIndices: '0',
        authenticatorData: 7,
        authenticatorDataHex: 5,
        authenticatorDataHash: null,
      });
      expect(captured).toEqual({ ...EMPTY_STATE, detailPreparation: EMPTY_DETAIL_PREPARATION });
    }
  });
});

describe('applyRegistrationSnapshot', () => {
  it('restores the state it captured, and what it said about the decodes', async () => {
    const { state, preparation } = await preparedState('packedX5c');
    state.visibleAttestationCertificateIndices = [0];
    const restored = createRegistrationState();
    expect(applyRegistrationSnapshot(restored, captureRegistrationState(state, preparation))).toEqual(preparation);
    expect(restored).toEqual(state);
  });

  it('reads the state a saved snapshot keeps under state', async () => {
    const { state, preparation } = await preparedState('es256');
    const snapshot = { schemaVersion: 2, state: captureRegistrationState(state, preparation) };
    const restored = createRegistrationState();
    expect(applyRegistrationSnapshot(restored, snapshot.state)).toEqual(preparation);
    expect(restored.attestationObject).toEqual(state.attestationObject);
  });

  it('gives empty sentences for a snapshot that kept none', () => {
    expect(applyRegistrationSnapshot(createRegistrationState(), { attestationObject: { fmt: 'none' } })).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('lists every certificate when the snapshot names none', () => {
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, { attestationCertificates: [decodedCertificate(), describedCertificate()] });
    expect(state.visibleAttestationCertificateIndices).toEqual([0, 1]);
  });

  it("gives the authenticator data its hex as raw bytes when it has none", () => {
    const hex = registration('es256').storedCredential.authenticatorDataHex;
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, { authenticatorData: { counter: 0 }, authenticatorDataHex: hex });
    expect(state.authenticatorData).toEqual({ counter: 0, raw: hex });
    applyRegistrationSnapshot(state, { authenticatorData: { raw: 'abcd' }, authenticatorDataHex: hex });
    expect(state.authenticatorData).toEqual({ raw: 'abcd' });
  });

  it('keeps empty values for parts of the wrong kind', () => {
    const state = createRegistrationState();
    applyRegistrationSnapshot(state, {
      attestationObject: 'o2Nm',
      attestationCertificates: { 0: 'MIIB' },
      visibleAttestationCertificateIndices: '0',
      authenticatorData: 'SZYN',
      authenticatorDataHex: 5,
      authenticatorDataHash: null,
    });
    expect(state).toEqual(EMPTY_STATE);
  });
});
