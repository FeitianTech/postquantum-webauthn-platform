// The current UI's registration certificates: ./registration-state.js over its
// one state (./state.js).
import {
    addStateCertificate,
    addStateCertificates,
    visibleStateCertificates,
} from './registration-state.js';
import {registrationDetailState} from './state.js';

export function addCertificateEntryToState(entry) {
    addStateCertificate(registrationDetailState, entry);
}

export function addCertificatesToRegistrationState(entries) {
    addStateCertificates(registrationDetailState, entries);
}

export function getVisibleAttestationCertificates() {
    return visibleStateCertificates(registrationDetailState);
}
