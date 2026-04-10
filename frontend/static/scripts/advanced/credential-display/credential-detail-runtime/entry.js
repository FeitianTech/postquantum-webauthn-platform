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
    bindRegistrationDetailButtons,
    composeRegistrationDetailHtml,
} from '../registration-compose-runtime.js';
import {
    resetRegistrationDetailState,
} from '../state.js';
import {
    combineRegistrationHtmlSections,
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

    const hasLocalRegistrationSnapshot = Boolean(
        cred.type !== 'simple'
        && cred.registrationDetailSnapshot
        && typeof cred.registrationDetailSnapshot === 'object',
    );

    if (cred.type !== 'simple' && !hasLocalRegistrationSnapshot) {
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
        combinedRegistrationHtml: snapshotCombinedRegistrationHtml,
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

    let combinedRegistrationHtml = snapshotCombinedRegistrationHtml;
    if (!combinedRegistrationHtml) {
        const registrationDetailResult = await composeRegistrationDetailHtml({
            credentialJson: Object.keys(registrationCredential).length ? registrationCredential : null,
            relyingPartyInfo,
            attestationObjectValue,
            attestationObjectDecoded,
            authenticatorDataValue: authenticatorDataForDetail,
            authenticatorDataHex,
            fallbackCertificates,
            fallbackClientData: fallbackClientDataString,
            fallbackParsedClientData: fallbackClientDataObject,
            includeAttestationSection: false,
            preferFallbackCertificates: Array.isArray(fallbackCertificates) && fallbackCertificates.length > 0,
        });

        combinedRegistrationHtml = combineRegistrationHtmlSections(
            registrationDetailResult.html,
            registrationDetailResult.attestationSectionHtml,
            registrationDetailResult.combinedHtml,
        );
    }

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
    const aaguidSectionHtml = buildAaguidSection(cred, attestationContext);

    const propertiesSectionHtml = buildPropertiesSection({
        cred,
        attestationContext,
        fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
    });

    const detailsHtml = [
        buildUserInfoSection(cred, aaguidSectionHtml),
        buildAttestationFormatSection(attestationFormatRaw || 'none'),
        buildAuthenticatorDataSection(cred),
        buildExtensionsSection(cred),
        buildPublicKeySection(cred),
        buildRegistrationDetailSection(combinedRegistrationHtml),
    ].filter(Boolean).join('');

    const finalDetailsHtml = [propertiesSectionHtml, detailsHtml].filter(Boolean).join('');

    modalBody.innerHTML = finalDetailsHtml;
    bindRegistrationDetailButtons(modalBody);

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
