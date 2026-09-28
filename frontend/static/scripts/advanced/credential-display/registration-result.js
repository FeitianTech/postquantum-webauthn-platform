import {openModal} from '../../shared/ui/core.js';
import {registrationResultInput, registrationSnapshotPayload} from './registration-view.js';

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

    const registrationDetail = await composeRegistrationDetail({
        credentialJson,
        relyingPartyInfo,
        ...registrationResultInput(credentialJson, relyingPartyInfo),
    });

    if (storageId && registrationDetail) {
        // The registration is kept as data -- the response and the relying
        // party's view of it, with the decoded attestation in `state` -- and the
        // detail modal builds its view from that. No markup is stored.
        const snapshotPayload = registrationSnapshotPayload({
            stateSnapshot: registrationDetail.stateSnapshot,
            credentialJson,
            relyingPartyCopy: registrationDetail.relyingPartyCopy,
        }, new Date().toISOString());

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
