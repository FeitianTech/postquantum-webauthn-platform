import { state } from './state.js';
import {
    base64ToBase64Url,
    base64ToHex,
    base64UrlToHex,
    base64UrlToJson,
    base64UrlToUtf8String,
    convertFormat,
    currentFormatToJsonFormat,
    hexToBase64,
    hexToBase64Url,
    hexToGuid
} from './binary-utils.js';
import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
    escapeHtml,
    formatBoolean,
    renderAttestationResultRow
} from './display-utils.js';
import {
    deriveAaguidDisplayValues,
    deriveAaguidFromCredentialData,
    extractHexFromJsonFormat,
    extractMinPinLengthValue,
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getCoseMapValue,
    getStoredCredentialAttachment,
    normaliseAaguidValue
} from './credential-utils.js';
import { convertExtensionsForClient, normalizeClientExtensionResults } from './binary-utils.js';
import { openModal, closeModal, updateGlobalScrollLock, resetModalScroll } from './ui.js';
import { showStatus, hideStatus, showProgress, hideProgress } from './status.js';
import { updateJsonEditor } from './json-editor.js';
import { checkLargeBlobCapability } from './forms.js';

function appendKeyValueLines(output, value, indentLevel = 0) {
    if (value === null || value === undefined) {
        return;
    }

    const indent = '    '.repeat(indentLevel);

    if (typeof value === 'string' || typeof value === 'number') {
        if (String(value).trim() !== '') {
            output.push(`${indent}${value}`);
        }
        return;
    }

    if (typeof value === 'boolean') {
        output.push(`${indent}${value}`);
        return;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return;
        }

        const filtered = value.filter(item => item !== null && item !== undefined);
        if (filtered.length === 0) {
            return;
        }

        const allScalars = filtered.every(item => {
            return (
                typeof item === 'string' ||
                typeof item === 'number' ||
                typeof item === 'boolean'
            );
        });

        if (allScalars) {
            filtered.forEach(item => {
                output.push(`${indent}${item}`);
            });
        } else {
            filtered.forEach(item => {
                if (item === null || item === undefined) {
                    return;
                }

                if (typeof item === 'object') {
                    output.push(`${indent}-`);
                    appendKeyValueLines(output, item, indentLevel + 1);
                } else {
                    output.push(`${indent}- ${item}`);
                }
            });
        }
        return;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value).filter(([key, val]) => {
            if (val === null || val === undefined || val === '') {
                return false;
            }
            if (typeof key === 'string' && key.toLowerCase().includes('base64')) {
                return false;
            }
            return true;
        });

        if (entries.length === 0) {
            return;
        }

        entries.forEach(([key, val]) => {
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    if (val.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                } else {
                    const nestedEntries = Object.entries(val).filter(([, nestedVal]) => nestedVal !== null && nestedVal !== undefined && nestedVal !== '');
                    if (nestedEntries.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                }
            } else {
                output.push(`${indent}${key}: ${val}`);
            }
        });
        return;
    }

    output.push(`${indent}${String(value)}`);
}

function hexToColonLines(hexString, bytesPerLine = 16) {
    if (typeof hexString !== 'string') {
        return [];
    }
    let clean = hexString.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (!clean) {
        return [];
    }
    if (clean.length % 2 !== 0) {
        clean = `0${clean}`;
    }
    const pairs = [];
    for (let i = 0; i < clean.length; i += 2) {
        pairs.push(clean.slice(i, i + 2));
    }
    const output = [];
    for (let i = 0; i < pairs.length; i += bytesPerLine) {
        output.push(pairs.slice(i, i + bytesPerLine).join(':'));
    }
    return output;
}

export function formatCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (typeof details.summary === 'string' && details.summary.trim() !== '') {
        return details.summary.trim();
    }

    const lines = [];
    const addLine = line => lines.push(line);
    const addBlankLine = () => {
        if (lines.length && lines[lines.length - 1] !== '') {
            lines.push('');
        }
    };

    const { version } = details;
    if (version) {
        if (typeof version === 'object') {
            const parts = [];
            if (typeof version.display === 'string' && version.display.trim() !== '') {
                parts.push(version.display.trim());
            }
            if (typeof version.hex === 'string' && version.hex.trim() !== '') {
                if (!parts.length || parts[parts.length - 1] !== version.hex.trim()) {
                    parts.push(version.hex.trim());
                }
            }
            if (parts.length > 0) {
                addLine(`Version: ${parts.join(' ')}`);
            }
        } else if (String(version).trim() !== '') {
            addLine(`Version: ${version}`);
        }
    }

    const serialNumber = details.serialNumber;
    if (serialNumber) {
        if (typeof serialNumber === 'object') {
            const parts = [];
            if (typeof serialNumber.decimal === 'string' && serialNumber.decimal.trim() !== '') {
                parts.push(serialNumber.decimal.trim());
            }
            if (typeof serialNumber.hex === 'string' && serialNumber.hex.trim() !== '') {
                parts.push(serialNumber.hex.trim());
            }
            if (parts.length > 0) {
                addLine(`Certificate Serial Number: ${parts.join(' / ')}`);
            }
        } else if (String(serialNumber).trim() !== '') {
            addLine(`Certificate Serial Number: ${serialNumber}`);
        }
    }

    if (typeof details.signatureAlgorithm === 'string' && details.signatureAlgorithm.trim() !== '') {
        addLine(`Signature Algorithm: ${details.signatureAlgorithm.trim()}`);
    }

    if (typeof details.issuer === 'string' && details.issuer.trim() !== '') {
        addLine(`Issuer: ${details.issuer.trim()}`);
    }

    const validity = details.validity;
    if (validity && (validity.notBefore || validity.notAfter)) {
        addBlankLine();
        addLine('Validity:');
        if (validity.notBefore) {
            addLine(`    Not Before: ${validity.notBefore}`);
        }
        if (validity.notAfter) {
            addLine(`    Not After: ${validity.notAfter}`);
        }
    }

    if (typeof details.subject === 'string' && details.subject.trim() !== '') {
        addBlankLine();
        addLine(`Subject: ${details.subject.trim()}`);
    }

    if (details.publicKeyInfo && typeof details.publicKeyInfo === 'object') {
        addBlankLine();
        addLine('Subject Public Key Info:');
        appendKeyValueLines(lines, details.publicKeyInfo, 1);
    }

    if (Array.isArray(details.extensions) && details.extensions.length) {
        addBlankLine();
        addLine('X509v3 extensions:');
        details.extensions.forEach(ext => {
            if (!ext || typeof ext !== 'object') {
                return;
            }

            const includeOid = ext.includeOidInHeader === undefined
                ? true
                : Boolean(ext.includeOidInHeader);
            const headerOverride = typeof ext.displayHeader === 'string'
                ? ext.displayHeader.trim()
                : '';
            const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
            const friendlyName = typeof ext.friendlyName === 'string'
                ? ext.friendlyName.trim()
                : '';
            const extName = typeof ext.name === 'string' ? ext.name.trim() : '';

            let header = headerOverride;
            if (!header) {
                const headerParts = [];
                if (includeOid && oid) {
                    headerParts.push(oid);
                }

                let displayName = friendlyName;
                if (!displayName && extName && extName !== oid) {
                    displayName = extName;
                }

                if (displayName) {
                    if (includeOid && headerParts.length) {
                        headerParts.push(`(${displayName})`);
                    } else {
                        headerParts.push(displayName);
                    }
                }

                if (!headerParts.length) {
                    if (extName) {
                        headerParts.push(extName);
                    } else if (oid) {
                        headerParts.push(oid);
                    } else {
                        headerParts.push('Extension');
                    }
                }

                header = headerParts.join(' ');
            }

            if (ext.critical) {
                header = `${header} [critical]`;
            }

            addLine(`    ${header}:`);
            if ('value' in ext) {
                appendKeyValueLines(lines, ext.value, 2);
            }
        });
    }

    if (details.signature && typeof details.signature === 'object') {
        const algorithm = typeof details.signature.algorithm === 'string'
            ? details.signature.algorithm.trim()
            : '';
        const signatureLines = Array.isArray(details.signature.lines)
            ? details.signature.lines.filter(line => typeof line === 'string' && line.trim() !== '')
            : [];
        const signatureColon = typeof details.signature.colon === 'string'
            ? details.signature.colon.trim()
            : '';

        if (algorithm || signatureLines.length || signatureColon) {
            addBlankLine();
            const algorithmLabel = algorithm || (typeof details.signatureAlgorithm === 'string' ? details.signatureAlgorithm.trim() : 'Signature');
            addLine(`Signature Algorithm: ${algorithmLabel}`);
            if (signatureLines.length) {
                signatureLines.forEach(line => addLine(`    ${line}`));
            } else if (signatureColon) {
                addLine(`    ${signatureColon}`);
            }
        }
    }

    if (details.fingerprints && typeof details.fingerprints === 'object') {
        const fingerprintEntries = Object.entries(details.fingerprints)
            .filter(([, value]) => typeof value === 'string' && value.trim() !== '');

        if (fingerprintEntries.length) {
            addBlankLine();
            addLine('Fingerprint:');
            fingerprintEntries.forEach(([algorithm, value]) => {
                const label = typeof algorithm === 'string' && algorithm.trim() !== ''
                    ? algorithm.trim().toUpperCase()
                    : 'VALUE';
                const colonLines = hexToColonLines(value);
                addLine(`    ${label}:`);
                if (colonLines.length) {
                    colonLines.forEach(line => addLine(`        ${line}`));
                } else {
                    addLine(`        ${value}`);
                }
            });
        }
    }

    const formatted = lines.join('\n').trim();
    return formatted;
}

export function renderCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (details.error) {
        return `<div style="color: #dc3545;">${escapeHtml(details.error)}</div>`;
    }

    const formatted = formatCertificateDetails(details);
    const content = formatted && formatted.trim() !== ''
        ? formatted
        : 'No decoded certificate details available.';

    return `<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${escapeHtml(content)}</textarea>`;
}

export function autoResizeCertificateTextareas(context) {
    const scope = context && typeof context.querySelectorAll === 'function'
        ? context
        : document;
    const textareas = scope.querySelectorAll('.certificate-textarea');
    textareas.forEach(textarea => {
        if (!(textarea instanceof HTMLTextAreaElement)) {
            return;
        }

        const resizeOnce = () => {
            textarea.style.height = 'auto';
            textarea.style.overflowY = 'hidden';
            textarea.style.overflowX = 'hidden';
            const measuredHeight = textarea.scrollHeight;
            if (Number.isFinite(measuredHeight) && measuredHeight > 0) {
                textarea.style.height = `${measuredHeight}px`;
            } else {
                textarea.style.height = '';
            }
        };

        resizeOnce();

        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(resizeOnce);
        }

        setTimeout(resizeOnce, 150);
    });
}

export function updateAllowCredentialsDropdown() {
    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (!allowCredentialsSelect) return;

    const currentValue = allowCredentialsSelect.value;

    allowCredentialsSelect.innerHTML = `
        <option value="all">All credentials</option>
        <option value="empty">Empty (resident key only)</option>
    `;

    if (state.storedCredentials && state.storedCredentials.length > 0) {
        state.storedCredentials.forEach((cred, index) => {
            const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
            if (!credentialIdHex) {
                return;
            }

            const credName = cred.userName || cred.email || `Credential ${index + 1}`;
            const option = document.createElement('option');
            option.value = credentialIdHex;
            option.textContent = `${credName} (${describeCoseAlgorithm(cred.algorithm)})`;
            allowCredentialsSelect.appendChild(option);
        });
    }

    if (currentValue && Array.from(allowCredentialsSelect.options).some(opt => opt.value === currentValue)) {
        allowCredentialsSelect.value = currentValue;
    } else {
        allowCredentialsSelect.value = 'all';
    }

    updateJsonEditor();
}

export async function loadSavedCredentials() {
    try {
        const response = await fetch('/api/credentials', {
            method: 'GET',
            headers: {'Content-Type': 'application/json'}
        });

        if (response.ok) {
            const credentials = await response.json();
            const normalizedCredentials = Array.isArray(credentials)
                ? credentials.map(cred => ({
                    ...cred,
                    credentialIdHex: getCredentialIdHex(cred),
                    userHandleHex: getCredentialUserHandleHex(cred),
                }))
                : [];
            state.storedCredentials = normalizedCredentials;
            updateCredentialsDisplay();
            updateJsonEditor();
        }
    } catch (error) {
        // Silently fail
    }
}

export function updateCredentialsDisplay() {
    const credentialsList = document.getElementById('credentials-list');

    if (!credentialsList) {
        return;
    }

    if (!state.storedCredentials.length) {
        credentialsList.innerHTML = '<p style="color: #6c757d; font-style: normal;">No credentials registered yet.</p>';
        checkLargeBlobCapability();
        updateAllowCredentialsDropdown();
        return;
    }

    credentialsList.innerHTML = state.storedCredentials.map((cred, index) => {
        const features = [];
        if (cred.residentKey === true || cred.discoverable === true) {
            features.push('Discoverable');
        }
        if (cred.largeBlob === true || cred.largeBlobSupported === true) {
            features.push('largeBlob');
        }
        const algorithmValue = cred.publicKeyAlgorithm ?? cred.algorithm;
        if (describeMldsaParameterSet(algorithmValue)) {
            features.push('PQC');
        }

        const featureText = features.length > 0 ? features.join(' • ') : '';

        return `
        <div class="credential-item" role="button" tabindex="0" onclick="showCredentialDetails(${index})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();showCredentialDetails(${index});}">
            <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 600; color: #0f2740; font-size: 0.95rem; margin-bottom: 0.25rem;">${cred.email || cred.username || 'Unknown User'}</div>
                ${featureText ? `<div style="font-size: 0.75rem; color: #5c6c7a;">${featureText}</div>` : ''}
            </div>
            <button class="btn btn-small btn-danger" onclick="event.stopPropagation();deleteCredential('${cred.email || cred.username}', ${index})">Delete</button>
        </div>
        `;
    }).join('');

    checkLargeBlobCapability();
    updateAllowCredentialsDropdown();
}

export function navigateToMdsAuthenticator(aaguid) {
    if (!aaguid) {
        return;
    }

    const switchToMdsTab = typeof window.switchTab === 'function'
        ? window.switchTab
        : null;
    if (switchToMdsTab) {
        switchToMdsTab('mds');
    }

    const highlightRow = typeof window.highlightMdsAuthenticatorRow === 'function'
        ? window.highlightMdsAuthenticatorRow
        : null;

    if (!highlightRow) {
        console.warn('Unable to highlight authenticator row: integration unavailable.');
        return;
    }

    let modalResult;
    try {
        modalResult = highlightRow(aaguid);
    } catch (error) {
        console.error('Failed to highlight authenticator row.', error);
        return;
    }

    const handleEntry = entry => {
        if (entry) {
            closeCredentialModal();
        }
    };

    if (modalResult && typeof modalResult.then === 'function') {
        modalResult
            .then(handleEntry)
            .catch(error => {
                console.error('Failed to highlight authenticator row.', error);
            });
    } else {
        handleEntry(modalResult);
    }
}

export function closeCredentialModal() {
    closeModal('credentialModal');
}

export function closeRegistrationResultModal() {
    closeModal('registrationResultModal');
}

export function showCredentialDetails(index) {
    const cred = state.storedCredentials[index];
    if (!cred) return;

    const modalBody = document.getElementById('modalBody');
    if (!modalBody) {
        return;
    }

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
    const propertiesData = (cred.properties && typeof cred.properties === 'object' && cred.properties !== null)
        ? cred.properties
        : {};
    const attestationSummaryData = (() => {
        if (cred && typeof cred.attestationSummary === 'object' && cred.attestationSummary !== null) {
            return cred.attestationSummary;
        }
        if (typeof propertiesData.attestationSummary === 'object' && propertiesData.attestationSummary !== null) {
            return propertiesData.attestationSummary;
        }
        return null;
    })();
    const attestationChecksData = (() => {
        if (cred && typeof cred.attestationChecks === 'object' && cred.attestationChecks !== null) {
            return cred.attestationChecks;
        }
        if (typeof propertiesData.attestationChecks === 'object' && propertiesData.attestationChecks !== null) {
            return propertiesData.attestationChecks;
        }
        if (
            attestationSummaryData
            && typeof attestationSummaryData.metadata === 'object'
            && attestationSummaryData.metadata !== null
        ) {
            return { metadata: attestationSummaryData.metadata };
        }
        return null;
    })();
    const resolveAttestationValue = (summaryKey, propertyKey) => {
        if (attestationSummaryData && Object.prototype.hasOwnProperty.call(attestationSummaryData, summaryKey)) {
            return attestationSummaryData[summaryKey];
        }
        if (Object.prototype.hasOwnProperty.call(propertiesData, propertyKey)) {
            return propertiesData[propertyKey];
        }
        if (Object.prototype.hasOwnProperty.call(cred, propertyKey)) {
            return cred[propertyKey];
        }
        return null;
    };
    const attestationSignatureValue = resolveAttestationValue('signatureValid', 'attestationSignatureValid');
    const attestationRootValue = resolveAttestationValue('rootValid', 'attestationRootValid');
    const attestationRpIdHashValue = resolveAttestationValue('rpIdHashValid', 'attestationRpIdHashValid');
    const attestationAaguidMatchValue = resolveAttestationValue('aaguidMatch', 'attestationAaguidMatch');
    const attestationRowsHtml = [
        renderAttestationResultRow('Signature Valid', attestationSignatureValue),
        renderAttestationResultRow('Root Valid', attestationRootValue),
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

    const rootVerified = attestationRootValue === true ||
        (typeof attestationRootValue === 'string' && attestationRootValue.trim().toLowerCase() === 'true');

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
    const infoButton = rootVerified && aaguidGuid
        ? `<button type="button" class="credential-info-button credential-aaguid-button" data-aaguid="${escapeHtml(aaguidGuid.toLowerCase())}" aria-label="View authenticator metadata">Info</button>`
        : '';

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
            ${infoButton}
        </div>
        <div class="credential-aaguid-values">
            ${sections.join('')}
        </div>`;

    detailsHtml += `</div>`;

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Properties</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Discoverable (resident key):</strong> ${formatBoolean(discoverableValue)}</div>
            <div><strong>Supports largeBlob:</strong> ${formatBoolean(largeBlobSupported)}</div>
            ${minPinLengthValue !== null ? `<div><strong>Authenticator minPinLength:</strong> ${escapeHtml(String(minPinLengthValue))}</div>` : ''}
            <div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid rgba(0, 114, 206, 0.15);">
                ${attestationRowsHtml}
            </div>
        </div>
    </div>`;

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Format</h4>
        <div style="font-size: 0.9rem;">${cred.attestationFormat || 'none'}</div>
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

    if (cred.publicKeyAlgorithm !== undefined || cred.algorithm !== undefined) {
        const algo = cred.publicKeyAlgorithm ?? cred.algorithm;
        const algorithmName = describeCoseAlgorithm(algo);
        const coseMap = cred.publicKeyCose || {};
        const coseKeyTypeValue = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);
        const coseKeyTypeLine = coseKeyTypeValue !== undefined && coseKeyTypeValue !== null
            ? `<div><strong>COSE key type:</strong> ${describeCoseKeyType(coseKeyTypeValue)}</div>`
            : '';
        const parameterSet = describeMldsaParameterSet(algo);
        const rawPublicKeyEncoded = cred.publicKeyBytes ?? getCoseMapValue(coseMap, -1);

        let pqcKeyBlock = '';
        if (parameterSet && typeof rawPublicKeyEncoded === 'string' && rawPublicKeyEncoded.trim() !== '') {
            const rawKeyB64 = rawPublicKeyEncoded;
            const rawKeyB64u = base64ToBase64Url(rawKeyB64);
            const rawKeyHex = base64ToHex(rawKeyB64);
            pqcKeyBlock = `
                <div style="margin-top: 0.75rem; font-size: 0.9rem; word-break: break-word; overflow-wrap: anywhere;">
                    <div><strong>Raw public key (base64):</strong></div>
                    <div class="credential-code-block">${rawKeyB64}</div>
                    <div><strong>Raw public key (base64url):</strong></div>
                    <div class="credential-code-block">${rawKeyB64u}</div>
                    <div><strong>Raw public key (hex):</strong></div>
                    <div class="credential-code-block">${rawKeyHex}</div>
                </div>`;
        }

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
            ${pqcKeyBlock}
        </div>`;
    }

    const attestationCertificateSection = renderCertificateDetails(cred.attestationCertificate || cred.attestation_certificate);
    if (attestationCertificateSection) {
        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Certificate</h4>
            ${attestationCertificateSection}
        </div>`;
    }

    modalBody.innerHTML = detailsHtml;
    const aaguidButton = modalBody.querySelector('.credential-aaguid-button');
    if (aaguidButton) {
        aaguidButton.addEventListener('click', () => {
            const target = aaguidButton.getAttribute('data-aaguid');
            if (target) {
                navigateToMdsAuthenticator(target);
            }
        });
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

export function showRegistrationResultModal(credentialJson, relyingPartyInfo) {
    const modalBody = document.getElementById('registrationResultBody');
    if (!modalBody) {
        return;
    }

    const credentialDisplay = credentialJson ? JSON.stringify(credentialJson, null, 2) : '';
    const clientDataBase64 = credentialJson?.response?.clientDataJSON;
    const parsedClientData = clientDataBase64 ? base64UrlToJson(clientDataBase64) : null;
    const clientDataDisplay = parsedClientData
        ? JSON.stringify(parsedClientData, null, 2)
        : clientDataBase64
            ? base64UrlToUtf8String(clientDataBase64) || clientDataBase64
            : '';

    let relyingPartyCopy = null;
    let certificateSection = '';
    if (relyingPartyInfo && typeof relyingPartyInfo === 'object') {
        relyingPartyCopy = JSON.parse(JSON.stringify(relyingPartyInfo));
        if (relyingPartyCopy.attestationCertificate) {
            certificateSection = renderCertificateDetails(relyingPartyCopy.attestationCertificate);
            delete relyingPartyCopy.attestationCertificate;
        }
    }

    const relyingPartyDisplay = relyingPartyCopy ? JSON.stringify(relyingPartyCopy, null, 2) : '';

    const credentialSection = credentialDisplay
        ? `<pre class="modal-pre">${escapeHtml(credentialDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No credential response captured.</div>';

    const clientDataSection = clientDataDisplay
        ? `<pre class="modal-pre">${escapeHtml(clientDataDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No clientDataJSON available.</div>';

    const relyingPartySection = relyingPartyDisplay
        ? `<pre class="modal-pre">${escapeHtml(relyingPartyDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No relying party data returned.</div>';

    let html = `
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Authenticator Response</h3>
            <ol style="padding-left: 1.25rem; margin: 0;">
                <li style="margin-bottom: 1rem;">
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Result of navigator.credentials.create()</div>
                    ${credentialSection}
                </li>
                <li>
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Parsed clientDataJSON response</div>
                    ${clientDataSection}
                </li>
            </ol>
        </section>
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Relying Party extracted information</h3>
            ${relyingPartySection}
        </section>
    `;

    if (certificateSection) {
        html += `
            <section>
                <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Attestation Certificate</h3>
                <div style="font-size: 0.95rem; line-height: 1.6;">
                    ${certificateSection}
                </div>
            </section>
        `;
    }

    modalBody.innerHTML = html;
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

export async function deleteCredential(username, index) {
    if (!confirm(`Are you sure you want to delete the credential for ${username}? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch('/api/deletepub', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({"email": username})
        });

        if (response.ok) {
            state.storedCredentials.splice(index, 1);
            updateCredentialsDisplay();
            showStatus('advanced',
                'Credential deleted from server successfully! ',
                'success'
            );
        } else {
            throw new Error('Failed to delete credential from server');
        }
    } catch (error) {
        showStatus('advanced', `Failed to delete credential: ${error.message}`, 'error');
    }
}

export function addCredentialToList(credential) {
    const normalizedCredential = {
        ...credential,
        credentialIdHex: getCredentialIdHex(credential),
        userHandleHex: getCredentialUserHandleHex(credential),
    };
    state.storedCredentials.push(normalizedCredential);
    updateCredentialsList();
}

export function updateCredentialsList() {
    const list = document.getElementById('credentials-list');

    if (!list) {
        return;
    }

    if (state.storedCredentials.length === 0) {
        list.innerHTML = '<p style="color: #6c757d; font-style: normal">No credentials registered yet.</p>';
        return;
    }

    list.innerHTML = '';
    state.storedCredentials.forEach((cred, index) => {
        const credItem = document.createElement('div');
        credItem.className = 'credential-item';
        credItem.onclick = () => toggleCredentialDetails(index);

        let summary = '';
        if (cred.type === 'simple') {
            summary = cred.email || cred.username;
        } else {
            summary = `${cred.userName || cred.userId}`;
            if (cred.displayName) summary += `\n${cred.displayName}`;
        }

        credItem.innerHTML = `
            <div class="credential-summary">${summary}</div>
            <div class="credential-details">
                ${generateCredentialDetails(cred)}
                <button class="credential-delete" onclick="deleteCredential(${index}); event.stopPropagation();">Delete</button>
            </div>
        `;

        list.appendChild(credItem);
    });
}

export function generateCredentialDetails(cred) {
    const algorithmDisplay = describeCoseAlgorithm(cred.algorithm);
    if (cred.type === 'simple') {
        return `
            <strong>Type:</strong> Simple Authentication<br>
            <strong>User:</strong> ${cred.email || cred.username}<br>
            <strong>Credential ID:</strong> ${cred.credentialId}<br>
            <strong>Algorithm:</strong> ${algorithmDisplay}
        `;
    } else {
        return `
            <strong>Type:</strong> Advanced Authentication<br>
            <strong>User ID:</strong> ${cred.userId}<br>
            <strong>User Name:</strong> ${cred.userName}<br>
            <strong>Display Name:</strong> ${cred.displayName || 'N/A'}<br>
            <strong>Credential ID:</strong> ${cred.credentialId}<br>
            <strong>Algorithm:</strong> ${algorithmDisplay}
        `;
    }
}

export function toggleCredentialDetails(index) {
    const credItems = document.querySelectorAll('.credential-item');
    const item = credItems[index];

    if (item.classList.contains('expanded')) {
        item.classList.remove('expanded');
    } else {
        credItems.forEach(item => item.classList.remove('expanded'));
        item.classList.add('expanded');
    }
}
