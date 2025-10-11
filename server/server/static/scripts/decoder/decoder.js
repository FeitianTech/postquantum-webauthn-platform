import { showStatus, hideStatus, showProgress, hideProgress } from '../shared/status.js';

function resetScrollPosition(element) {
    if (element && typeof element.scrollTop === 'number') {
        element.scrollTop = 0;
    }
    if (element && typeof element.scrollLeft === 'number') {
        element.scrollLeft = 0;
    }
}

const SPECIAL_LABELS = {
    aaguid: 'AAGUID',
    alg: 'Algorithm',
    attestationObject: 'Attestation object',
    attStmt: 'Attestation statement',
    authenticatorData: 'Authenticator data',
    authenticatorAttachment: 'Authenticator attachment',
    base64: 'Base64',
    base64url: 'Base64url',
    bin: 'Binary',
    cbor: 'CBOR',
    byteLength: 'Byte length',
    clientDataJSON: 'Client data JSON',
    clientExtensionResults: 'Client extensions',
    cose: 'COSE key',
    counter: 'Counter',
    expandedJson: 'Expanded JSON',
    decodedValue: 'Decoded value',
    ctap: 'CTAP metadata',
    ctapDecoded: 'CTAP decoded',
    ignoredPaddingBytes: 'Ignored padding bytes',
    trailingBytesHex: 'Trailing bytes (hex)',
    makeCredentialResponse: 'MakeCredential response',
    getAssertionResponse: 'GetAssertion response',
    credential: 'Credential',
    credentialId: 'Credential ID',
    credentialIdLength: 'Credential ID length',
    credProps: 'Credential properties',
    data: 'Data',
    derBase64: 'DER (Base64)',
    extensions: 'Extensions',
    fingerprint: 'Fingerprint',
    hex: 'Hex',
    issuer: 'Issuer',
    key_size: 'Key size',
    fmt: 'Format',
    md5: 'MD5',
    not_valid_after: 'Not valid after',
    not_valid_before: 'Not valid before',
    origin: 'Origin',
    parsedX5c: 'Certificate details',
    publicKeyInfo: 'Public key info',
    pem: 'PEM',
    publicKey: 'Public key',
    publicKeyAlgorithm: 'Public key algorithm',
    pub: 'Public key bytes',
    raw: 'Raw',
    rawId: 'Raw ID',
    rawJson: 'Raw JSON',
    responseDetails: 'Response details',
    rpIdHash: 'RP ID hash',
    sig: 'Signature',
    signature: 'Signature',
    signature_algorithm: 'Signature algorithm',
    sha1: 'SHA1',
    sha256: 'SHA256',
    structure: 'Structure',
    signatureLength: 'Signature length',
    subjectPublicKeyInfoBase64: 'Subject public key (Base64)',
    subject: 'Subject',
    subject_key_identifier: 'Subject key identifier',
    subject_public_key_info: 'Subject public key info',
    transports: 'Transports',
    meaning: 'Meaning',
    code: 'Code',
    codeHex: 'Code (hex)',
    kind: 'CTAP type',
    payloadLength: 'Payload length',
    valueSummary: 'Value summary',
    keySummary: 'Key summary',
    type: 'Type',
    userHandle: 'User handle',
    uuid: 'UUID',
    uncompressedPoint: 'Uncompressed point',
    x5c: 'X5C',
};

export async function decodeResponse() {
    const input = document.getElementById('decoder-input');
    if (!input) {
        return;
    }

    const inputValue = input.value;
    if (!inputValue.trim()) {
        showStatus('decoder', 'Decoder is empty. Please paste something to decode.', 'error');
        updateDecoderEmptyState();
        return;
    }

    const decoderOutput = document.getElementById('decoder-output');
    const summaryContainer = document.getElementById('decoded-content');
    const rawContainer = document.getElementById('decoder-raw-container');
    const rawContent = document.getElementById('decoder-raw-content');
    const toggleButton = document.getElementById('decoder-toggle-raw');

    if (summaryContainer) {
        summaryContainer.innerHTML = '';
    }
    if (rawContent) {
        rawContent.value = '';
        rawContent.style.height = '';
    }
    if (rawContainer) {
        rawContainer.style.display = 'none';
    }
    if (toggleButton) {
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
    }
    if (decoderOutput) {
        decoderOutput.style.display = 'none';
    }
    hideStatus('decoder');

    updateDecoderEmptyState();

    showProgress('decoder', 'Decoding…');

    try {
        const response = await fetch('/api/decode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ payload: inputValue }),
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (parseError) {
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            throw new Error('Failed to parse decoder response.');
        }

        if (!response.ok) {
            const message = payload && payload.error
                ? payload.error
                : `Server responded with status ${response.status}`;
            throw new Error(message);
        }

        if (summaryContainer) {
            renderDecodedResult(summaryContainer, payload);
        }
        if (rawContent) {
            rawContent.value = JSON.stringify(payload, null, 2);
            autoSizeRawTextarea(rawContent);
            resetScrollPosition(rawContent);
        }
        if (decoderOutput) {
            decoderOutput.style.display = 'block';
        }
        if (toggleButton) {
            toggleButton.textContent = 'Show raw';
            toggleButton.dataset.expanded = 'false';
        }
        if (rawContainer) {
            rawContainer.style.display = 'none';
        }
        showStatus('decoder', 'Response decoded successfully!', 'success');
    } catch (error) {
        if (decoderOutput) {
            decoderOutput.style.display = 'none';
        }
        if (rawContainer) {
            rawContainer.style.display = 'none';
        }
        if (toggleButton) {
            toggleButton.textContent = 'Show raw';
            toggleButton.dataset.expanded = 'false';
        }
        const message = error instanceof Error ? error.message : String(error);
        showStatus('decoder', `Decoding failed: ${message}`, 'error');
    } finally {
        hideProgress('decoder');
        updateDecoderEmptyState();
    }
}

export function clearDecoder() {
    const input = document.getElementById('decoder-input');
    const output = document.getElementById('decoder-output');
    const decodedContent = document.getElementById('decoded-content');
    const rawContainer = document.getElementById('decoder-raw-container');
    const rawContent = document.getElementById('decoder-raw-content');
    const toggleButton = document.getElementById('decoder-toggle-raw');

    if (input) {
        input.value = '';
        resetScrollPosition(input);
    }
    if (decodedContent) {
        decodedContent.innerHTML = '';
    }
    if (rawContent) {
        rawContent.value = '';
        rawContent.style.height = '';
        resetScrollPosition(rawContent);
    }
    if (rawContainer) {
        rawContainer.style.display = 'none';
    }
    if (toggleButton) {
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
    }
    if (output) {
        output.style.display = 'none';
    }
    hideStatus('decoder');
    hideProgress('decoder');
    updateDecoderEmptyState();
}

export function toggleRawDecoder() {
    const rawContainer = document.getElementById('decoder-raw-container');
    const toggleButton = document.getElementById('decoder-toggle-raw');
    const rawContent = document.getElementById('decoder-raw-content');
    if (!rawContainer || !toggleButton) {
        return;
    }

    const expanded = toggleButton.dataset.expanded === 'true';
    if (expanded) {
        rawContainer.style.display = 'none';
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
    } else {
        rawContainer.style.display = 'block';
        toggleButton.textContent = 'Hide raw';
        toggleButton.dataset.expanded = 'true';
        if (rawContent) {
            autoSizeRawTextarea(rawContent);
        }
    }
}

function autoSizeRawTextarea(textarea) {
    if (!textarea) {
        return;
    }
    textarea.style.overflowY = 'hidden';
    textarea.style.height = 'auto';
    const scrollHeight = textarea.scrollHeight;
    textarea.style.height = scrollHeight ? `${scrollHeight}px` : '';
}

function renderDecodedResult(container, payload) {
    container.innerHTML = '';

    if (!payload || typeof payload !== 'object') {
        const empty = document.createElement('div');
        empty.className = 'decoder-empty';
        empty.textContent = 'No decoded data available.';
        container.appendChild(empty);
        return;
    }

    const header = document.createElement('div');
    header.className = 'decoder-summary-header';

    const statusPill = document.createElement('span');
    statusPill.className = `decoder-pill ${payload.success ? 'success' : 'error'}`;
    statusPill.textContent = payload.success ? 'Success' : 'Error';
    header.appendChild(statusPill);

    const typeEl = document.createElement('span');
    typeEl.className = 'decoder-type';
    typeEl.textContent = payload.type || 'Decoded data';
    header.appendChild(typeEl);

    container.appendChild(header);

    if (Array.isArray(payload.malformed) && payload.malformed.length > 0) {
        const warning = document.createElement('div');
        warning.className = 'decoder-warning';
        warning.textContent = `Malformed segments: ${payload.malformed.join(', ')}`;
        container.appendChild(warning);
    }

    const sectionsWrapper = document.createElement('div');
    sectionsWrapper.className = 'decoder-sections';

    const sections = buildSections(payload.type, payload.data);
    if (sections.length === 0) {
        const emptySection = document.createElement('div');
        emptySection.className = 'decoder-empty';
        emptySection.textContent = 'No structured data available.';
        sectionsWrapper.appendChild(emptySection);
    } else {
        sections.forEach((section) => sectionsWrapper.appendChild(section));
    }

    container.appendChild(sectionsWrapper);
}

function buildSections(type, data) {
    const sections = [];

    if (data === undefined) {
        return sections;
    }

    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        sections.push(createSection(type || 'Data', data));
        return sections;
    }

    const orderMap = {
        PublicKeyCredential: [
            'credential',
            'attestationObject',
            'authenticatorData',
            'clientDataJSON',
            'clientExtensionResults',
            'responseDetails',
        ],
        'Attestation object': ['attestationObject', 'authenticatorData', 'extensions'],
        'Authenticator data': ['authenticatorData'],
        'WebAuthn client data': ['clientDataJSON'],
        'X.509 certificate': ['raw', 'pem', 'parsedX5c', 'certificates'],
        'CBOR': ['ctapDecoded', 'expandedJson', 'decodedValue', 'ctap'],
    };
    const hiddenKeys = new Set();

    const usedKeys = new Set();
    const preferredOrder = orderMap[type] || [];

    preferredOrder.forEach((key) => {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            const section = createSection(key, data[key]);
            if (section) {
                sections.push(section);
                usedKeys.add(key);
            }
        }
    });

    Object.keys(data).forEach((key) => {
        if (usedKeys.has(key) || hiddenKeys.has(key)) {
            return;
        }
        const section = createSection(key, data[key]);
        if (section) {
            sections.push(section);
        }
    });

    return sections;
}

function createSection(key, value) {
    const section = document.createElement('div');
    section.className = 'decoder-section';

    const heading = document.createElement('h4');
    heading.textContent = formatKey(key);
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body';
    if (key === 'expandedJson') {
        const textarea = renderExpandedJson(value);
        body.appendChild(textarea);
        requestAnimationFrame(() => {
            autoSizeRawTextarea(textarea);
            resetScrollPosition(textarea);
        });
    } else {
        body.appendChild(renderValue(value));
    }
    section.appendChild(body);

    return section;
}

function renderValue(value) {
    if (value === null || value === undefined) {
        const span = document.createElement('span');
        span.className = 'decoder-empty';
        span.textContent = String(value);
        return span;
    }

    if (typeof value === 'string') {
        const isMultiline = value.includes('\n') || value.length > 80;
        const element = document.createElement(isMultiline ? 'pre' : 'span');
        element.className = isMultiline ? 'decoder-pre' : 'decoder-inline';
        element.textContent = value;
        return element;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
        const span = document.createElement('span');
        span.className = 'decoder-primitive';
        span.textContent = String(value);
        return span;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            const span = document.createElement('span');
            span.className = 'decoder-empty';
            span.textContent = '[]';
            return span;
        }

        const list = document.createElement('ol');
        list.className = 'decoder-list';
        value.forEach((item) => {
            const listItem = document.createElement('li');
            listItem.appendChild(renderValue(item));
            list.appendChild(listItem);
        });
        return list;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value);
        if (entries.length === 0) {
            const span = document.createElement('span');
            span.className = 'decoder-empty';
            span.textContent = '{}';
            return span;
        }

        const definition = document.createElement('dl');
        definition.className = 'decoder-definition';

        entries.forEach(([childKey, childValue]) => {
            const term = document.createElement('dt');
            term.className = 'decoder-term';
            term.textContent = formatKey(childKey);

            const detail = document.createElement('dd');
            detail.className = 'decoder-details';
            detail.appendChild(renderValue(childValue));

            definition.appendChild(term);
            definition.appendChild(detail);
        });

        return definition;
    }

    const span = document.createElement('span');
    span.className = 'decoder-primitive';
    span.textContent = String(value);
    return span;
}

function renderExpandedJson(value) {
    const textarea = document.createElement('textarea');
    textarea.className = 'form-control decoder-expanded-json';
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('spellcheck', 'false');
    textarea.wrap = 'off';

    const payload = { 'decoded json': value === undefined ? null : value };
    try {
        textarea.value = JSON.stringify(payload, null, 2);
    } catch (error) {
        textarea.value = 'Unable to render expanded JSON';
    }

    return textarea;
}

function formatKey(key) {
    if (typeof key !== 'string' || key.length === 0) {
        return 'Value';
    }

    if (Object.prototype.hasOwnProperty.call(SPECIAL_LABELS, key)) {
        return SPECIAL_LABELS[key];
    }

    if (/^[A-Z0-9]{1,4}$/.test(key)) {
        return key;
    }

    const spaced = key
        .replace(/[_-]+/g, ' ')
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .trim();

    if (spaced.length === 0) {
        return 'Value';
    }

    const words = spaced.split(/\s+/).map((word) => {
        if (/^[a-z]{1,3}$/.test(word)) {
            return word.toUpperCase();
        }
        if (/^[A-Z0-9]+$/.test(word)) {
            return word;
        }
        if (/^[a-z0-9]+$/.test(word)) {
            return word.charAt(0).toUpperCase() + word.slice(1);
        }
        return word.charAt(0).toUpperCase() + word.slice(1);
    });

    return words.join(' ');
}

function updateDecoderEmptyState() {
    const output = document.getElementById('decoder-output');
    const description = document.getElementById('decoder-description');

    if (!description) {
        return;
    }

    const summary = output ? output.querySelector('#decoded-content') : null;
    const hasVisibleOutput = Boolean(
        output &&
            output.style.display !== 'none' &&
            output.offsetParent !== null &&
            summary &&
            summary.childElementCount > 0
    );

    description.style.display = hasVisibleOutput ? 'none' : 'block';
}

function initDecoderEmptyState() {
    updateDecoderEmptyState();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDecoderEmptyState);
} else {
    initDecoderEmptyState();
}
