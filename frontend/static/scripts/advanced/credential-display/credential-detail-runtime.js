import {state} from '../../shared/state.js';
import {
    base64ToBase64Url,
    base64UrlToHex,
    hexToGuid,
} from '../../shared/binary-utils.js';
import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
    escapeHtml,
    formatBoolean,
    renderAttestationResultRow,
} from '../display-utils.js';
import {
    deriveAaguidDisplayValues,
    deriveAaguidFromCredentialData,
    extractMinPinLengthValue,
    getCoseMapValue,
    normaliseAaguidValue,
} from '../credential-utils.js';
import {openModal} from '../../shared/ui.js';
import {resolveCredentialAlgorithmIdentifier} from './algorithm.js';
import {extractAaguidFromCertificateEntries} from './certificate-core.js';
import {
    computeCredentialAaguidMatchStatus,
    extractCredentialAttestationContext,
    normaliseAttestationResultValue,
    resolveCredentialAttestationValue,
} from './attestation-context.js';
import {
    applyGlobalCursor,
} from './cursor.js';
import {
    collectTruthyEntries,
    cloneJson,
    normalizeClientDataString,
} from './data-utils.js';
import {
    autoResizeCertificateTextareas,
} from './formatting.js';
import {
    clearAaguidStatus,
} from './navigation.js';
import {
    bindRegistrationDetailButtons,
    composeRegistrationDetailHtml,
} from './registration-compose-runtime.js';
import {
    applyRegistrationDetailSnapshot,
    EMPTY_DETAIL_PREPARATION,
} from './registration-state-runtime.js';
import {
    resetRegistrationDetailState,
} from './state.js';

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

    const pickFirstString = (...candidates) => {
        for (const candidate of candidates) {
            if (typeof candidate !== 'string') {
                continue;
            }
            const trimmed = candidate.trim();
            if (trimmed) {
                return trimmed;
            }
        }
        return '';
    };

    const pickFirstObject = (...candidates) => {
        for (const candidate of candidates) {
            if (candidate && typeof candidate === 'object') {
                return candidate;
            }
        }
        return null;
    };

    let detailPreparation = null;
    let registrationDetailHtml = '';
    let attestationSectionHtml = '';
    let combinedRegistrationHtml = '';
    let snapshotState = null;

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

    if (registrationDetailSnapshot) {
        snapshotState = registrationDetailSnapshot.state && typeof registrationDetailSnapshot.state === 'object'
            ? registrationDetailSnapshot.state
            : registrationDetailSnapshot;

        detailPreparation = applyRegistrationDetailSnapshot(registrationDetailSnapshot) || { ...EMPTY_DETAIL_PREPARATION };

        registrationDetailHtml = typeof registrationDetailSnapshot.html === 'string'
            ? registrationDetailSnapshot.html
            : '';
        attestationSectionHtml = typeof registrationDetailSnapshot.attestationSectionHtml === 'string'
            ? registrationDetailSnapshot.attestationSectionHtml
            : '';
        combinedRegistrationHtml = typeof registrationDetailSnapshot.combinedHtml === 'string'
            ? registrationDetailSnapshot.combinedHtml
            : [registrationDetailHtml, attestationSectionHtml].filter(Boolean).join('');
    }

    let attestationObjectValue = pickFirstString(
        cred.attestationObjectRaw,
        cred.attestationObject,
        cred.attestation_object_raw,
        cred.attestation_object,
        cred.attestationObjectBase64,
        cred.attestation_object_base64,
    );

    let attestationObjectDecoded = pickFirstObject(
        cred.attestationObjectDecoded,
        cred.attestation_object_decoded,
        typeof cred.attestationObject === 'object' ? cred.attestationObject : null,
        typeof cred.attestation_object === 'object' ? cred.attestation_object : null,
    );

    let authenticatorDataBase64 = pickFirstString(
        cred.authenticatorDataRaw,
        cred.authenticatorData,
        cred.authenticator_data_raw,
        cred.authenticator_data,
        cred.authenticatorDataBase64,
        cred.authenticatorDataBase64Url,
    );

    let authenticatorDataHex = pickFirstString(
        cred.authenticatorDataHex,
        cred.authenticator_data_hex,
    );

    let fallbackCertificates = collectTruthyEntries(
        cred.attestationCertificate,
        cred.attestationCertificates,
        cred.attestation_certificate,
        cred.attestation_certificates,
        cred.properties?.attestationCertificate,
        cred.properties?.attestationCertificates,
        cred.relyingParty?.attestationCertificate,
        cred.relyingParty?.attestationCertificates,
    );

    if (snapshotState) {
        const attObjSnapshot = cloneJson(snapshotState.attestationObject);
        if (attObjSnapshot && typeof attObjSnapshot === 'object') {
            attestationObjectDecoded = attObjSnapshot;
        }

        const certSnapshot = cloneJson(snapshotState.attestationCertificates);
        if (Array.isArray(certSnapshot)) {
            fallbackCertificates = certSnapshot;
        }

        if (typeof snapshotState.authenticatorDataHex === 'string') {
            authenticatorDataHex = snapshotState.authenticatorDataHex;
        }
    }

    if (detailPreparation) {
        attestationObjectValue = detailPreparation.attestationObjectValue || attestationObjectValue;
        authenticatorDataBase64 = detailPreparation.authenticatorDataValue || authenticatorDataBase64;
    }

    const certificateAaguidHex = normaliseAaguidValue(
        extractAaguidFromCertificateEntries(fallbackCertificates)
    );
    const authDataAaguidHex = normaliseAaguidValue(deriveAaguidFromCredentialData(cred));

    const relyingPartyInfo = pickFirstObject(
        cred.relyingParty,
        cred.registrationRelyingParty,
        cred.registration_relying_party,
        cred.properties?.relyingParty,
    );

    const fallbackClientDataString = pickFirstString(
        cred.clientDataJSON,
        cred.clientDataJson,
        cred.clientData,
        typeof cred.client_data_json === 'string' ? cred.client_data_json : '',
    );

    const fallbackClientDataObject = pickFirstObject(
        typeof cred.client_data_json === 'object' ? cred.client_data_json : null,
        cred.clientDataParsed,
        cred.clientDataObject,
    );

    const registrationResponseStored = pickFirstObject(
        cred.registrationResponse,
        cred.registration_response,
        cred.registrationResult,
        cred.registration_result,
    );

    let registrationCredential = cloneJson(registrationResponseStored);
    if (!registrationCredential || typeof registrationCredential !== 'object') {
        registrationCredential = {};
    }

    if (!registrationCredential.response || typeof registrationCredential.response !== 'object') {
        registrationCredential.response = {};
    }
    const registrationResponse = registrationCredential.response;

    const credentialIdBase64 = pickFirstString(
        cred.credentialId,
        cred.credential_id,
        cred.credentialIdBase64,
    );
    let credentialIdBase64Url = '';
    if (credentialIdBase64) {
        try {
            credentialIdBase64Url = base64ToBase64Url(credentialIdBase64);
        } catch (error) {
            credentialIdBase64Url = credentialIdBase64;
        }
    }

    if (credentialIdBase64Url) {
        if (!registrationCredential.id) {
            registrationCredential.id = credentialIdBase64Url;
        }
        if (!registrationCredential.rawId) {
            registrationCredential.rawId = credentialIdBase64Url;
        }
    }

    if (!registrationCredential.type) {
        registrationCredential.type = 'public-key';
    }

    const storedRegistrationResponse = (() => {
        if (registrationResponseStored && typeof registrationResponseStored === 'object') {
            const nestedResponse = registrationResponseStored.response;
            if (nestedResponse && typeof nestedResponse === 'object') {
                return nestedResponse;
            }
            return registrationResponseStored;
        }
        return null;
    })();

    if (!attestationObjectValue) {
        attestationObjectValue = pickFirstString(
            storedRegistrationResponse?.attestationObject,
            storedRegistrationResponse?.attestation_object,
            storedRegistrationResponse?.attestationObjectRaw,
            storedRegistrationResponse?.attestation_object_raw,
            registrationCredential?.attestationObject,
            registrationCredential?.attestation_object,
            registrationCredential?.attestationObjectRaw,
            registrationCredential?.attestation_object_raw,
        );
    }

    if (!attestationObjectDecoded) {
        attestationObjectDecoded = pickFirstObject(
            storedRegistrationResponse?.attestationObjectDecoded,
            storedRegistrationResponse?.attestation_object_decoded,
            typeof storedRegistrationResponse?.attestationObject === 'object'
                ? storedRegistrationResponse.attestationObject
                : null,
            typeof storedRegistrationResponse?.attestation_object === 'object'
                ? storedRegistrationResponse.attestation_object
                : null,
            typeof registrationCredential?.attestationObject === 'object'
                ? registrationCredential.attestationObject
                : null,
            typeof registrationCredential?.attestation_object === 'object'
                ? registrationCredential.attestation_object
                : null,
        );
    }

    if (!authenticatorDataBase64) {
        authenticatorDataBase64 = pickFirstString(
            storedRegistrationResponse?.authenticatorData,
            storedRegistrationResponse?.authenticator_data,
            storedRegistrationResponse?.authenticatorDataRaw,
            storedRegistrationResponse?.authenticator_data_raw,
            registrationCredential?.authenticatorData,
            registrationCredential?.authenticator_data,
            registrationCredential?.authenticatorDataRaw,
            registrationCredential?.authenticator_data_raw,
        );
    }

    if (!authenticatorDataHex) {
        authenticatorDataHex = pickFirstString(
            storedRegistrationResponse?.authenticatorDataHex,
            storedRegistrationResponse?.authenticator_data_hex,
            registrationCredential?.authenticatorDataHex,
            registrationCredential?.authenticator_data_hex,
        );
    }

    if (attestationObjectValue && !registrationResponse.attestationObject) {
        registrationResponse.attestationObject = attestationObjectValue;
    }

    if (attestationObjectDecoded && !registrationResponse.attestationObjectDecoded) {
        registrationResponse.attestationObjectDecoded = attestationObjectDecoded;
    }

    const normalizedClientDataForResponse = normalizeClientDataString(
        registrationResponse.clientDataJSON || fallbackClientDataString,
    );
    if (normalizedClientDataForResponse && !registrationResponse.clientDataJSON) {
        registrationResponse.clientDataJSON = normalizedClientDataForResponse;
    }

    if (authenticatorDataBase64 && !registrationResponse.authenticatorData) {
        registrationResponse.authenticatorData = authenticatorDataBase64;
    }

    const extensionResults = pickFirstObject(
        registrationCredential.clientExtensionResults,
        cred.clientExtensionOutputs,
        cred.client_extension_outputs,
    );
    if (extensionResults && typeof extensionResults === 'object') {
        registrationCredential.clientExtensionResults = cloneJson(extensionResults) || extensionResults;
    }

    if (cred.authenticatorAttachment && !registrationCredential.authenticatorAttachment) {
        registrationCredential.authenticatorAttachment = cred.authenticatorAttachment;
    }

    const authenticatorDataForDetail = authenticatorDataBase64 || authenticatorDataHex || '';

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

        registrationDetailHtml = registrationDetailResult.html;
        attestationSectionHtml = registrationDetailResult.attestationSectionHtml;
        combinedRegistrationHtml = registrationDetailResult.combinedHtml
            || [registrationDetailHtml, attestationSectionHtml].filter(Boolean).join('');
    }

    const attestationFormatCandidates = [
        cred.attestationFormat,
        cred.attestation_format,
        cred.attestationFmt,
        relyingPartyInfo?.attestationFmt,
        attestationObjectDecoded && typeof attestationObjectDecoded.fmt === 'string' ? attestationObjectDecoded.fmt : '',
    ];
    const attestationFormatRaw = pickFirstString(...attestationFormatCandidates);

    let detailsHtml = '';

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">User info at creation</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Name:</strong> ${cred.userName || cred.email || 'N/A'}</div>
            <div style="margin-bottom: 0.5rem;"><strong>Display name:</strong> ${cred.displayName || cred.userName || cred.email || 'N/A'}</div>
        </div>`;

    if (cred.userHandle) {
        const userHandleB64 = cred.userHandle;
        const userHandleB64u = base64ToBase64Url(userHandleB64);
        const userHandleHex = base64UrlToHex(userHandleB64u);

        detailsHtml += `
        <div style="margin-top: 0.5rem;">
            <div><strong>User handle (User ID):</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;">
                <div><strong>b64</strong></div>
                <div class="credential-code-block">${userHandleB64}</div>
                <div><strong>b64u</strong></div>
                <div class="credential-code-block">${userHandleB64u}</div>
                <div><strong>hex</strong></div>
                <div class="credential-code-block">${userHandleHex}</div>
            </div>
        </div>`;
    }

    if (cred.credentialId) {
        const credentialIdB64 = cred.credentialId;
        const credentialIdB64u = base64ToBase64Url(credentialIdB64);
        const credentialIdHex = base64UrlToHex(credentialIdB64u);

        detailsHtml += `
        <div style="margin-top: 0.5rem;">
            <div><strong>Credential ID:</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;">
                <div><strong>b64</strong></div>
                <div class="credential-code-block">${credentialIdB64}</div>
                <div><strong>b64u</strong></div>
                <div class="credential-code-block">${credentialIdB64u}</div>
                <div><strong>hex</strong></div>
                <div class="credential-code-block">${credentialIdHex}</div>
            </div>
        </div>`;
    }

    let aaguidHex = normaliseAaguidValue(cred.aaguid);

    const discoverableValue = cred.residentKey ?? cred.discoverable ?? false;
    const largeBlobSupported = cred.largeBlob ?? cred.largeBlobSupported ?? false;
    const minPinLengthValue = extractMinPinLengthValue(cred);
    const attestationContext = extractCredentialAttestationContext(cred);
    const { propertiesData, attestationSummaryData, attestationChecksData } = attestationContext;

    const metadataWarningMessage = pickFirstString(
        attestationChecksData?.metadata?.verification_warning,
        attestationChecksData?.metadata?.verificationWarning,
        attestationSummaryData?.metadata?.verification_warning,
        attestationSummaryData?.metadata?.verificationWarning,
        propertiesData?.metadata?.verification_warning,
        propertiesData?.metadata?.verificationWarning,
        cred?.metadata?.verification_warning,
        cred?.metadata?.verificationWarning,
    );

    const attestationSignatureValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'signatureValid',
            'attestationSignatureValid',
            attestationContext,
        ),
    );
    const attestationRootValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rootValid',
            'attestationRootValid',
            attestationContext,
        ),
    );
    let rootChecksRaw = null;
    if (
        attestationContext.attestationChecksData
        && typeof attestationContext.attestationChecksData === 'object'
    ) {
        const checksSource = attestationContext.attestationChecksData;
        if (checksSource.root_checks && typeof checksSource.root_checks === 'object') {
            rootChecksRaw = checksSource.root_checks;
        } else if (checksSource.rootChecks && typeof checksSource.rootChecks === 'object') {
            rootChecksRaw = checksSource.rootChecks;
        }
    }
    let rootChecksHtml = '';
    if (rootChecksRaw && typeof rootChecksRaw === 'object') {
        const rootCheckDescriptors = [
            { key: 'fido_mds', altKey: 'fidoMds', label: 'FIDO MDS' },
            { key: 'chain', altKey: 'chain', label: 'Chain' },
        ];
        const rootCheckParts = [];
        for (const descriptor of rootCheckDescriptors) {
            let rawValue = rootChecksRaw[descriptor.key];
            if (rawValue === undefined) {
                rawValue = rootChecksRaw[descriptor.altKey];
            }
            const status = rawValue === undefined
                ? null
                : normaliseAttestationResultValue(rawValue);
            const color = status === true
                ? '#198754'
                : status === false
                    ? '#dc3545'
                    : '#6c757d';
            rootCheckParts.push(
                `<span style="color: ${color}; font-weight: 600;">${descriptor.label}</span>`,
            );
        }
        if (rootCheckParts.length) {
            rootChecksHtml = ` <span style="margin-left: 0.5rem; color: #6c757d;">(${rootCheckParts.join(', ')})</span>`;
        }
    }
    const attestationRpIdHashValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rpIdHashValid',
            'attestationRpIdHashValid',
            attestationContext,
        ),
    );
    const attestationAaguidMatchValue = computeCredentialAaguidMatchStatus(cred, {
        certificateEntries: fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
        attestationContext,
    });
    const attestationChecksNoticeHtml = `
        <p style="margin: 0 0 0.65rem; color: #6c757d; font-size: 0.9rem; line-height: 1.5;">
            In formal WebAuthn, any <strong>false</strong> result below causes registration to fail.
            This platform keeps registration valid for data inspection purposes. 
        </p>`;
    const attestationRowsHtml = [
        renderAttestationResultRow('Signature Valid', attestationSignatureValue),
        renderAttestationResultRow('Root Valid', attestationRootValue, rootChecksHtml),
        renderAttestationResultRow('RPID Hash Valid', attestationRpIdHashValue),
        renderAttestationResultRow('AAGUID Match', attestationAaguidMatchValue),
    ].join('');

    const fallbackAaguidCandidates = [
        cred.aaguidHex,
        cred.aaguidGuid,
        cred.aaguidRaw,
        propertiesData?.aaguid,
        propertiesData?.aaguidHex,
        propertiesData?.aaguidGuid,
        propertiesData?.aaguidRaw,
        attestationSummaryData?.aaguid,
        attestationSummaryData?.aaguidHex,
        attestationSummaryData?.aaguidGuid,
        attestationChecksData?.metadata?.aaguid,
        attestationChecksData?.metadata?.hex,
        attestationChecksData?.metadata?.raw,
        attestationChecksData?.metadata?.guid,
        propertiesData?.metadata?.aaguid,
        propertiesData?.metadata?.hex,
        propertiesData?.metadata?.raw,
        propertiesData?.metadata?.guid,
        cred?.metadata?.aaguid,
        cred?.metadata?.hex,
        cred?.metadata?.raw,
        cred?.metadata?.guid,
    ];
    const relyingPartyAaguid = cred?.relyingParty?.aaguid;
    if (relyingPartyAaguid && typeof relyingPartyAaguid === 'object') {
        fallbackAaguidCandidates.push(
            relyingPartyAaguid.raw,
            relyingPartyAaguid.hex,
            relyingPartyAaguid.guid,
        );
    } else if (relyingPartyAaguid) {
        fallbackAaguidCandidates.push(relyingPartyAaguid);
    }

    if (!aaguidHex) {
        for (const candidate of fallbackAaguidCandidates) {
            const normalised = normaliseAaguidValue(candidate);
            if (normalised) {
                aaguidHex = normalised;
                break;
            }
        }
    }

    if (!aaguidHex) {
        aaguidHex = deriveAaguidFromCredentialData(cred);
    }

    const { aaguidHex: normalizedAaguidHex, aaguidB64, aaguidB64u } = deriveAaguidDisplayValues(aaguidHex);
    let aaguidGuid = '';
    if (normalizedAaguidHex && normalizedAaguidHex.length === 32) {
        try {
            aaguidGuid = hexToGuid(normalizedAaguidHex);
        } catch (error) {
            aaguidGuid = '';
        }
    }

    const hasAaguid = Boolean(normalizedAaguidHex);

    const renderAaguidValue = (label, value) => `
            <div class="credential-aaguid-value">
                <span class="credential-aaguid-value-label">${label}</span>
                <div class="credential-code-block">${escapeHtml(value || 'N/A')}</div>
            </div>`;

    const sections = [
        renderAaguidValue('b64', hasAaguid && aaguidB64 ? aaguidB64 : 'N/A'),
        renderAaguidValue('b64u', hasAaguid && aaguidB64u ? aaguidB64u : 'N/A'),
        renderAaguidValue('hex', hasAaguid ? normalizedAaguidHex : 'N/A'),
        renderAaguidValue('guid', aaguidGuid || 'N/A'),
    ];

    detailsHtml += `
        <div class="credential-aaguid-row">
            <span class="credential-aaguid-label">AAGUID</span>
        </div>
        <div class="credential-aaguid-status" role="status" aria-live="polite">
            <span class="credential-aaguid-spinner" aria-hidden="true" hidden></span>
            <span class="credential-aaguid-status-text"></span>
        </div>
        <div class="credential-aaguid-values">
            ${sections.join('')}
        </div>`;

    detailsHtml += `</div>`;

    const metadataWarningHtml = metadataWarningMessage
        ? `<div style="margin-top: 0.4rem; color: #c47f16; font-size: 0.85rem;">${escapeHtml(metadataWarningMessage)}</div>`
        : '';

    const propertiesSectionHtml = `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Properties</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Discoverable (resident key):</strong> ${formatBoolean(discoverableValue)}</div>
            <div><strong>Supports largeBlob:</strong> ${formatBoolean(largeBlobSupported)}</div>
            ${minPinLengthValue !== null ? `<div><strong>Authenticator minPinLength:</strong> ${escapeHtml(String(minPinLengthValue))}</div>` : ''}
            <div style="margin-top: 0.5rem; padding-top: 0.75rem; border-top: 1px solid rgba(0, 114, 206, 0.15);">
                ${attestationChecksNoticeHtml}
                ${attestationRowsHtml}
                ${metadataWarningHtml}
            </div>
        </div>
    </div>`;

    const attestationFormatFallback = pickFirstString(cred.attestationFormat, cred.attestation_format);
    const attestationFormatDisplay = attestationFormatRaw || attestationFormatFallback || 'none';

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Format</h4>
        <div style="font-size: 0.9rem;">${attestationFormatDisplay}</div>
    </div>`;

    if (cred.flags) {
        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Authenticator Data (registration)</h4>
            <div style="font-size: 0.9rem; line-height: 1.4;">
                <div><strong>AT:</strong> ${cred.flags.at}, <strong>BE:</strong> ${cred.flags.be}, <strong>BS:</strong> ${cred.flags.bs}, <strong>ED:</strong> ${cred.flags.ed}, <strong>UP:</strong> ${cred.flags.up}, <strong>UV:</strong> ${cred.flags.uv}</div>
                <div><strong>Signature Counter:</strong> ${cred.signCount || 0}</div>
            </div>
        </div>`;
    }

    if (cred.clientExtensionOutputs && Object.keys(cred.clientExtensionOutputs).length > 0) {
        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Client extension outputs (registration)</h4>
            <div class="credential-code-block" style="font-size: 0.9rem; border-radius: 16px;">${JSON.stringify(cred.clientExtensionOutputs, null, 2)}</div>
        </div>`;
    }

    if (cred.publicKeyAlgorithm !== undefined || cred.algorithm !== undefined || (cred.publicKeyCose && Object.keys(cred.publicKeyCose).length > 0)) {
        const coseMap = cred.publicKeyCose || {};
        const resolvedAlgorithm = resolveCredentialAlgorithmIdentifier(cred);
        const fallbackAlgorithm = resolvedAlgorithm !== null ? resolvedAlgorithm : getCoseMapValue(coseMap, 3);
        const algorithmName = describeCoseAlgorithm(fallbackAlgorithm);
        const coseKeyTypeValue = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);
        const coseKeyTypeLine = coseKeyTypeValue !== undefined && coseKeyTypeValue !== null
            ? `<div><strong>COSE key type:</strong> ${describeCoseKeyType(coseKeyTypeValue)}</div>`
            : '';
        const parameterSet = describeMldsaParameterSet(fallbackAlgorithm);

        const parameterSetLine = parameterSet
            ? `<div><strong>ML-DSA parameter set:</strong> ${parameterSet}</div>`
            : '';

        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Public Key</h4>
            <div style="font-size: 0.9rem;">
                <div><strong>Algorithm:</strong> ${algorithmName}</div>
                ${coseKeyTypeLine}
                ${parameterSetLine}
            </div>
        </div>`;
    }

    if (!combinedRegistrationHtml) {
        combinedRegistrationHtml = [registrationDetailHtml, attestationSectionHtml].filter(Boolean).join('');
    }
    if (combinedRegistrationHtml) {
        detailsHtml += `
        <div class="credential-registration-copy">
            ${combinedRegistrationHtml}
        </div>`;
    } else {
        detailsHtml += `
        <div class="credential-registration-copy">
            <div style="font-style: italic; color: #6c757d;">Registration detail data is not available for this credential.</div>
        </div>`;
    }

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
