import {openModal} from '../../shared/ui/core.js';
import {collectTruthyEntries} from './data-utils.js';

// The decode moved to ./decode-payload.js, which the new UI imports too.
export {decodePayloadThroughApi} from './decode-payload.js';

export async function showRegistrationResultModalRuntime(credentialJson, relyingPartyInfo, options = {}, deps = {}) {
    const {
        composeRegistrationDetail,
        updateAdvancedCredentialRegistrationSnapshot,
        loadSavedCredentials,
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

    const registrationDetail = await composeRegistrationDetail({
        credentialJson,
        relyingPartyInfo,
        attestationObjectValue,
        authenticatorDataValue,
        fallbackCertificates,
    });

    if (storageId && registrationDetail) {
        // The registration is kept as data -- the response and the relying
        // party's view of it, with the decoded attestation in `state` -- and the
        // detail modal builds its view from that. No markup is stored.
        const snapshotPayload = {
            schemaVersion: 2,
            capturedAt: new Date().toISOString(),
            state: registrationDetail.stateSnapshot || {},
            response: {
                credential: credentialJson,
                relyingParty: registrationDetail.relyingPartyCopy || null,
            },
        };

        if (await updateAdvancedCredentialRegistrationSnapshot(storageId, snapshotPayload)) {
            await loadSavedCredentials();
        }
    }

    modalBody.replaceChildren(registrationDetail.view);

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
