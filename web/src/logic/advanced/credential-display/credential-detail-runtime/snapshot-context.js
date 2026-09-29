import {applyRegistrationSnapshot} from '../registration-state.js';
import {registrationDetailState} from '../state.js';

// A snapshot that holds the registration as data (schemaVersion 2 and later).
// Anything else -- an older snapshot, or none -- leaves the credential to be
// completed from its server artifact.
export function readSnapshotResponse(snapshot) {
    if (!snapshot || typeof snapshot !== 'object' || !(Number(snapshot.schemaVersion) >= 2)) {
        return null;
    }
    const response = snapshot.response;
    if (!response || typeof response !== 'object') {
        return null;
    }
    const credential = response.credential && typeof response.credential === 'object'
        ? response.credential
        : null;
    const relyingParty = response.relyingParty && typeof response.relyingParty === 'object'
        ? response.relyingParty
        : null;
    return credential || relyingParty ? { credential, relyingParty } : null;
}

// The saved registration detail, as data, applied to `state` (the current UI's
// one by default). Markup is never read from a snapshot or from a record: older
// snapshots carried composed HTML, and records could carry
// registrationDetailHtml-style keys; the view is built from data instead.
export function resolveRegistrationSnapshotContext(cred, state = registrationDetailState) {
    const registrationDetailSnapshot = [
        cred.registrationDetailSnapshot,
        cred.registration_detail_snapshot,
        cred.registrationDetailCopy,
        cred.registration_detail_copy,
    ].find(candidate => candidate && typeof candidate === 'object') || null;

    if (!registrationDetailSnapshot) {
        return {
            detailPreparation: null,
            snapshotState: null,
            snapshotResponse: null,
        };
    }

    const snapshotState = registrationDetailSnapshot.state && typeof registrationDetailSnapshot.state === 'object'
        ? registrationDetailSnapshot.state
        : registrationDetailSnapshot;

    const detailPreparation = applyRegistrationSnapshot(state, registrationDetailSnapshot);

    return {
        detailPreparation,
        snapshotState,
        snapshotResponse: readSnapshotResponse(registrationDetailSnapshot),
    };
}
