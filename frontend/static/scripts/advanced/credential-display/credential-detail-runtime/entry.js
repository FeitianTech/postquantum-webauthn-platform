import {state} from '../../../shared/state.js';
import {openModal} from '../../../shared/ui/core.js';
import {
    applyGlobalCursor,
} from '../cursor.js';
import {decodePayloadThroughApi} from '../decode-payload.js';
import {
    autoResizeCertificateTextareas,
} from '../formatting.js';
import {
    clearAaguidStatus,
} from '../navigation.js';
import {
    renderRegistrationView,
} from '../registration-compose-runtime.js';
import {
    registrationDetailState,
} from '../state.js';
import {
    composeCredentialDetail,
    needsArtifact,
} from './compose.js';
import {
    renderAaguidSection,
} from './sections-aaguid.js';
import {
    buildRegistrationDetailSection,
    COSE_DESCRIBERS,
    renderAttestationFormatSection,
    renderAuthenticatorDataSection,
    renderExtensionsSection,
    renderPublicKeySection,
    renderUserInfoSection,
} from './sections-main.js';
import {
    renderPropertiesSection,
} from './sections-properties.js';

// The current UI's credential detail modal, built from ./compose.js's data over
// its one registration state (../state.js), which the certificate and
// authenticator-data views read when their buttons are pressed.
export async function showCredentialDetailsRuntime(index, deps = {}) {
    const {
        hydrateCredentialFromServer,
    } = deps;

    const cred = state.storedCredentials[index];
    if (!cred) {
        return;
    }

    if (needsArtifact(cred)) {
        const restoreCursor = applyGlobalCursor('progress');
        try {
            if (typeof hydrateCredentialFromServer === 'function') {
                await hydrateCredentialFromServer(cred);
            }
        } finally {
            restoreCursor();
        }
    }

    const modalBody = document.getElementById('modalBody');
    if (!modalBody) {
        return;
    }

    const detail = await composeCredentialDetail(cred, {
        state: registrationDetailState,
        decode: decodePayloadThroughApi,
        describers: COSE_DESCRIBERS,
    });

    modalBody.replaceChildren(
        renderPropertiesSection(detail.properties),
        renderUserInfoSection(detail.userInfo, renderAaguidSection(detail.aaguid)),
        renderAttestationFormatSection(detail.attestationFormat),
        ...[
            renderAuthenticatorDataSection(detail.authenticatorData),
            renderExtensionsSection(detail.extensions),
            renderPublicKeySection(detail.publicKey),
        ].filter(Boolean),
        buildRegistrationDetailSection(renderRegistrationView(detail.registration)),
    );

    const statusEl = modalBody.querySelector('.credential-aaguid-status');
    if (statusEl) {
        clearAaguidStatus(statusEl);
    }

    modalBody.scrollTop = 0;
    if (typeof modalBody.scrollTo === 'function') {
        modalBody.scrollTo(0, 0);
    }

    openModal('credentialModal');

    const scheduleResize = () => autoResizeCertificateTextareas(modalBody);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(scheduleResize);
    } else {
        setTimeout(scheduleResize, 0);
    }
}
