import {openModal} from '../../shared/ui.js';
import {collectTruthyEntries} from './data-utils.js';

export async function decodePayloadThroughApi(payload) {
    const trimmed = typeof payload === 'string' ? payload.trim() : '';
    if (!trimmed) {
        throw new Error('Decoder payload must be a non-empty string.');
    }

    const response = await fetch('/api/decode', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ payload: trimmed })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Unable to decode payload.');
    }

    const json = await response.json();
    if (json && typeof json === 'object') {
        if (json.error) {
            throw new Error(json.error);
        }
        if (json.data !== undefined) {
            return json;
        }
    }

    throw new Error('Decoder response did not include data.');
}

export async function showRegistrationResultModalRuntime(credentialJson, relyingPartyInfo, options = {}, deps = {}) {
    const {
        composeRegistrationDetailHtml,
        updateAdvancedCredentialRegistrationSnapshot,
        loadSavedCredentials,
        bindRegistrationDetailButtons,
        autoResizeCertificateTextareas,
    } = deps;

    const modalBody = document.getElementById('registrationResultBody');
    if (!modalBody) {
        return;
    }

    const { storageId = null } = options || {};

    const attestationObjectValue = credentialJson?.response?.attestationObject || '';
    const authenticatorDataValue = credentialJson?.response?.authenticatorData || '';

    const fallbackCertificates = collectTruthyEntries(
        relyingPartyInfo?.attestationCertificate,
        relyingPartyInfo?.attestationCertificates,
        relyingPartyInfo?.attestation_certificate,
        relyingPartyInfo?.attestation_certificates,
        relyingPartyInfo?.registrationData?.attestationCertificate,
        relyingPartyInfo?.registrationData?.attestationCertificates,
        relyingPartyInfo?.registrationData?.attestation_certificate,
        relyingPartyInfo?.registrationData?.attestation_certificates,
    );

    const registrationDetail = await composeRegistrationDetailHtml({
        credentialJson,
        relyingPartyInfo,
        attestationObjectValue,
        authenticatorDataValue,
        fallbackCertificates,
    });

    if (storageId && registrationDetail) {
        const snapshotPayload = {
            schemaVersion: 1,
            capturedAt: new Date().toISOString(),
            html: registrationDetail.html || '',
            attestationSectionHtml: registrationDetail.attestationSectionHtml || '',
            combinedHtml: registrationDetail.combinedHtml
                || [registrationDetail.html, registrationDetail.attestationSectionHtml].filter(Boolean).join(''),
            state: registrationDetail.stateSnapshot || {},
        };

        if (await updateAdvancedCredentialRegistrationSnapshot(storageId, snapshotPayload)) {
            await loadSavedCredentials();
        }
    }

    modalBody.innerHTML = registrationDetail.html;
    bindRegistrationDetailButtons(modalBody);

    modalBody.scrollTop = 0;
    if (typeof modalBody.scrollTo === 'function') {
        modalBody.scrollTo(0, 0);
    }
    openModal('registrationResultModal');
    const scheduleResize = () => autoResizeCertificateTextareas(modalBody);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(scheduleResize);
    } else {
        setTimeout(scheduleResize, 0);
    }
}
