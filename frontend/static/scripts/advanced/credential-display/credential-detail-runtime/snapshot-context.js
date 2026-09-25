import {
    applyRegistrationDetailSnapshot,
    EMPTY_DETAIL_PREPARATION,
} from '../registration-state-runtime.js';
import {
    combineRegistrationHtmlSections,
    pickFirstString,
} from './helpers.js';

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

export function resolveRegistrationSnapshotContext(cred) {
    const registrationDetailSnapshot = (() => {
        const objectCandidates = [
            cred.registrationDetailSnapshot,
            cred.registration_detail_snapshot,
            cred.registrationDetailCopy,
            cred.registration_detail_copy,
        ];

        for (const candidate of objectCandidates) {
            if (candidate && typeof candidate === 'object') {
                return candidate;
            }
        }

        const htmlCopy = pickFirstString(
            cred.registrationDetailHtml,
            cred.registration_detail_html,
            cred.registrationDetailCombinedHtml,
            cred.registration_detail_combined_html,
        );

        if (htmlCopy) {
            return { combinedHtml: htmlCopy };
        }

        return null;
    })();

    if (!registrationDetailSnapshot) {
        return {
            detailPreparation: null,
            snapshotState: null,
            snapshotResponse: null,
            combinedRegistrationHtml: '',
        };
    }

    const snapshotState = registrationDetailSnapshot.state && typeof registrationDetailSnapshot.state === 'object'
        ? registrationDetailSnapshot.state
        : registrationDetailSnapshot;

    const detailPreparation = applyRegistrationDetailSnapshot(registrationDetailSnapshot)
        || { ...EMPTY_DETAIL_PREPARATION };

    const combinedRegistrationHtml = combineRegistrationHtmlSections(
        registrationDetailSnapshot.html,
        registrationDetailSnapshot.attestationSectionHtml,
        registrationDetailSnapshot.combinedHtml,
    );

    return {
        detailPreparation,
        snapshotState,
        snapshotResponse: readSnapshotResponse(registrationDetailSnapshot),
        combinedRegistrationHtml,
    };
}
