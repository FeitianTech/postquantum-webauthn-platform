import {openModal} from '../../shared/ui/core.js';
import {keepRegistrationSnapshot} from './registration-snapshot.js';

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

    const { composed: registrationDetail, saved } = await keepRegistrationSnapshot(
        { credentialJson, relyingPartyInfo, storageId },
        { compose: composeRegistrationDetail, saveSnapshot: updateAdvancedCredentialRegistrationSnapshot },
    );
    if (saved) {
        await loadSavedCredentials();
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
