import {applyRegistrationSnapshot} from '../registration/state-snapshot.js';

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

// The saved registration detail, as data, applied to `state`. Markup is never
// read from a snapshot: older snapshots carried composed HTML; the view is built
// from data instead.
export function resolveRegistrationSnapshotContext(cred, state) {
    const registrationDetailSnapshot = cred.registrationDetailSnapshot && typeof cred.registrationDetailSnapshot === 'object'
        ? cred.registrationDetailSnapshot
        : null;

    if (!registrationDetailSnapshot) {
        return {
            detailPreparation: null,
            snapshotState: null,
            snapshotResponse: null,
        };
    }

    // A snapshot whose state kept nothing is saved without one: an empty state.
    const snapshotState = registrationDetailSnapshot.state && typeof registrationDetailSnapshot.state === 'object'
        ? registrationDetailSnapshot.state
        : {};

    const detailPreparation = applyRegistrationSnapshot(state, snapshotState);

    return {
        detailPreparation,
        snapshotState,
        snapshotResponse: readSnapshotResponse(registrationDetailSnapshot),
    };
}
