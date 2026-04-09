import {registrationDetailState} from './state.js';
import {
    deriveCertificateIdentity,
    normaliseCertificateEntryForModal,
} from './certificate-core.js';

export function addCertificateEntryToState(entry) {
    const normalised = normaliseCertificateEntryForModal(entry);
    if (!normalised) {
        return;
    }

    const identity = deriveCertificateIdentity(normalised);
    const existing = registrationDetailState.attestationCertificates;

    if (identity) {
        const existingIndex = existing.findIndex(item => deriveCertificateIdentity(item) === identity);
        if (existingIndex !== -1) {
            const currentEntry = existing[existingIndex];
            const currentParsed = currentEntry && typeof currentEntry === 'object' && currentEntry.parsedX5c
                && typeof currentEntry.parsedX5c === 'object'
                ? currentEntry.parsedX5c
                : null;
            const newParsed = normalised.parsedX5c && typeof normalised.parsedX5c === 'object'
                ? normalised.parsedX5c
                : null;
            const currentHasError = Boolean(currentParsed && currentParsed.parseError);
            const newHasError = Boolean(newParsed && newParsed.parseError);

            if (currentHasError && !newHasError) {
                existing[existingIndex] = normalised;
            }
            return;
        }
    } else {
        const duplicate = existing.some(item => {
            if (item === normalised) {
                return true;
            }
            if (item.pem && normalised.pem && item.pem === normalised.pem) {
                return true;
            }
            if (item.raw && normalised.raw && item.raw === normalised.raw) {
                return true;
            }
            return false;
        });

        if (duplicate) {
            return;
        }
    }

    existing.push(normalised);
}

export function addCertificatesToRegistrationState(entries) {
    if (!entries) {
        return;
    }
    if (Array.isArray(entries)) {
        entries.forEach(entry => addCertificateEntryToState(entry));
    } else {
        addCertificateEntryToState(entries);
    }
}

export function getVisibleAttestationCertificates() {
    const indices = Array.isArray(registrationDetailState.visibleAttestationCertificateIndices)
        ? registrationDetailState.visibleAttestationCertificateIndices
        : [];

    return indices
        .map(idx => registrationDetailState.attestationCertificates[idx])
        .filter(entry => entry && typeof entry === 'object');
}
