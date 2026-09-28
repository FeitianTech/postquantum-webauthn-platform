// The current UI's registration state: ./registration-state.js over its one
// state (./state.js), which its certificate and authenticator-data views read
// when their buttons are pressed, decoding through the server's decoder.
import {decodePayloadThroughApi} from './decode-payload.js';
import {
    applyRegistrationSnapshot,
    captureRegistrationState,
    EMPTY_DETAIL_PREPARATION,
    hashAuthenticatorData,
    normaliseDetailPreparationSnapshot,
    prepareRegistrationState,
} from './registration-state.js';
import {registrationDetailState} from './state.js';

export {EMPTY_DETAIL_PREPARATION, normaliseDetailPreparationSnapshot};

export function computeAuthenticatorDataHash() {
    return hashAuthenticatorData(registrationDetailState);
}

export function prepareRegistrationDetailState(options = {}) {
    return prepareRegistrationState(registrationDetailState, options, { decode: decodePayloadThroughApi });
}

export function captureRegistrationDetailState(detailPreparation = EMPTY_DETAIL_PREPARATION) {
    return captureRegistrationState(registrationDetailState, detailPreparation);
}

export function applyRegistrationDetailSnapshot(snapshot) {
    return applyRegistrationSnapshot(registrationDetailState, snapshot);
}
