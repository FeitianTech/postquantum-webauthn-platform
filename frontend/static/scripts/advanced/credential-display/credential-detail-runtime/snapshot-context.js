import {
    applyRegistrationDetailSnapshot,
    EMPTY_DETAIL_PREPARATION,
} from '../registration-state-runtime.js';
import {
    combineRegistrationHtmlSections,
    pickFirstString,
} from './helpers.js';

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
        combinedRegistrationHtml,
    };
}
