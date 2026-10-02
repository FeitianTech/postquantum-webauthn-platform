// Registration states for the tests of credentials/registration/: the empty
// state, a certificate as the decoder and as register-complete give it, and a
// state prepared from a recorded registration.
import { prepareRegistrationState } from '@/logic/credentials/registration/prepare.js';
import { createRegistrationState } from '@/logic/credentials/registration/state.js';

import { advancedComplete, goldenDecode, registration } from './registration-detail-answers.js';

export const EMPTY_STATE = {
  attestationObject: null,
  attestationCertificates: [],
  visibleAttestationCertificateIndices: [],
  authenticatorData: null,
  authenticatorDataHash: '',
  authenticatorDataHex: '',
};

/** The attestation certificate as the decoder answers it: { parsedX5c, pem, raw }. */
export const decodedCertificate = () => registration('packedX5c').attestationDecode.data.attestationObject.attStmt.x5c[0];

/** The same certificate as register-complete describes it (derBase64, pem, summary, ...). */
export const describedCertificate = () => advancedComplete().relyingParty.attestationCertificate;

/** A state holding a registration: its attestation object and authenticator data, decoded. */
export async function preparedState(name = 'packedX5c') {
  const entry = registration(name);
  const state = createRegistrationState();
  const preparation = await prepareRegistrationState(state, {
    attestationObjectValue: entry.attestationObject,
    authenticatorDataValue: entry.authenticatorData,
  }, { decode: goldenDecode(entry) });
  return { state, preparation };
}
