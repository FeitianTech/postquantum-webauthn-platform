import {state} from '../../../shared/state.js';
import {openModal} from '../../../shared/ui/core.js';
import {
    extractCredentialAttestationContext,
} from '../attestation-context.js';
import {
    applyGlobalCursor,
} from '../cursor.js';
import {
    autoResizeCertificateTextareas,
} from '../formatting.js';
import {
    clearAaguidStatus,
} from '../navigation.js';
import {
    composeRegistrationDetail,
} from '../registration-compose-runtime.js';
import {
    resetRegistrationDetailState,
} from '../state.js';
import {
    pickFirstString,
} from './helpers.js';
import {
    buildRegistrationContext,
} from './registration-context.js';
import {
    buildAaguidSection,
} from './sections-aaguid.js';
import {
    buildAttestationFormatSection,
    buildAuthenticatorDataSection,
    buildExtensionsSection,
    buildPublicKeySection,
    buildRegistrationDetailSection,
    buildUserInfoSection,
} from './sections-main.js';
import {
    buildPropertiesSection,
} from './sections-properties.js';
import {
    readSnapshotResponse,
    resolveRegistrationSnapshotContext,
} from './snapshot-context.js';

export async function showCredentialDetailsRuntime(index, deps = {}) {
    const {
        hydrateCredentialFromServer,
    } = deps;

    const cred = state.storedCredentials[index];
    if (!cred) {
        return;
    }

    // Only a snapshot that holds the registration as data spares the artifact
    // request: an older one lacks the response the sections are built from.
    const hasLocalRegistrationData = Boolean(readSnapshotResponse(cred.registrationDetailSnapshot));

    if (cred.type !== 'simple' && !hasLocalRegistrationData) {
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

    resetRegistrationDetailState();

    const {
        detailPreparation,
        snapshotState,
        snapshotResponse,
    } = resolveRegistrationSnapshotContext(cred);

    const {
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataHex,
        fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
        relyingPartyInfo,
        fallbackClientDataString,
        fallbackClientDataObject,
        registrationCredential,
        authenticatorDataForDetail,
    } = buildRegistrationContext(cred, {
        snapshotState,
        detailPreparation,
    });

    const registrationDetail = await composeRegistrationDetail({
        credentialJson: snapshotResponse?.credential
            || (Object.keys(registrationCredential).length ? registrationCredential : null),
        relyingPartyInfo: snapshotResponse?.relyingParty || relyingPartyInfo,
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataValue: authenticatorDataForDetail,
        authenticatorDataHex,
        fallbackCertificates,
        fallbackClientData: fallbackClientDataString,
        fallbackParsedClientData: fallbackClientDataObject,
        preferFallbackCertificates: Array.isArray(fallbackCertificates) && fallbackCertificates.length > 0,
        snapshotState: snapshotResponse ? snapshotState : null,
    });

    const attestationFormatRaw = pickFirstString(
        cred.attestationFormat,
        cred.attestation_format,
        cred.attestationFmt,
        relyingPartyInfo?.attestationFmt,
        attestationObjectDecoded && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '',
    );

    const attestationContext = extractCredentialAttestationContext(cred);

    modalBody.replaceChildren(
        buildPropertiesSection({
            cred,
            attestationContext,
            fallbackCertificates,
            certificateAaguidHex,
            authDataAaguidHex,
        }),
        buildUserInfoSection(cred, buildAaguidSection(cred, attestationContext)),
        buildAttestationFormatSection(attestationFormatRaw || 'none'),
        ...[
            buildAuthenticatorDataSection(cred),
            buildExtensionsSection(cred),
            buildPublicKeySection(cred),
        ].filter(Boolean),
        buildRegistrationDetailSection(registrationDetail.view),
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
