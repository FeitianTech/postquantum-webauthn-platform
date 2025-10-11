import { showStatus, hideStatus, showProgress, hideProgress } from '../shared/status.js';
import { openModal, closeModal } from '../shared/ui.js';

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
    encodedValue: 'Encoded value',
    ctap: 'CTAP metadata',
    binary: 'Binary summary',
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

let currentCodecMode = 'decode';

const MODE_CONFIG = {
    decode: {
        panelId: 'codec-decode-panel',
        inputId: 'decoder-input',
        outputId: 'decoder-output',
        summaryId: 'decoded-content',
        toggleRawId: 'decoder-toggle-raw',
        rawContentId: 'decoder-raw-content',
        rawModalId: 'decoder-raw-modal',
        statusKey: 'decoder',
        progressId: 'decoder-progress',
        progressTextId: 'decoder-progress-text',
    },
    encode: {
        panelId: 'codec-encode-panel',
        inputId: 'encoder-input',
        outputId: 'encoder-output',
        summaryId: 'encoded-content',
        toggleRawId: 'encoder-toggle-raw',
        rawContentId: 'encoder-raw-content',
        rawModalId: 'encoder-raw-modal',
        statusKey: 'encoder',
        progressId: 'encoder-progress',
        progressTextId: 'encoder-progress-text',
        formatSelectId: 'encoder-format',
    },
};

const ENCODER_FORMAT_ALIASES = new Map([
    ['cbor', 'cbor'],
    ['cbor (binary)', 'cbor'],
    ['json', 'json'],
    ['json (binary)', 'json'],
    ['der', 'der'],
    ['pem', 'pem'],
    ['cose', 'cose'],
]);

export async function processCodec(mode = getSelectedDecoderMode()) {
    const config = MODE_CONFIG[mode] || MODE_CONFIG[currentCodecMode];
    if (!config) {
        return;
    }

    const input = document.getElementById(config.inputId);
    if (!input) {
        return;
    }

    const inputValue = input.value;
    if (!inputValue.trim()) {
        const message = mode === 'encode'
            ? 'Encoder input is empty. Provide JSON to encode.'
            : 'Codec input is empty. Please paste something to process.';
        showStatus(config.statusKey, message, 'error');
        if (mode === 'decode') {
            updateDecoderEmptyState();
        }
        return;
    }

    let targetFormat = null;
    if (mode === 'encode') {
        const formatSelect = config.formatSelectId
            ? document.getElementById(config.formatSelectId)
            : null;
        targetFormat = formatSelect ? formatSelect.value : '';
        if (!targetFormat || !targetFormat.trim()) {
            showStatus(config.statusKey, 'Select an encoding format before encoding.', 'error');
            return;
        }

        let parsedValue;
        try {
            parsedValue = JSON.parse(inputValue);
        } catch (parseError) {
            showStatus(config.statusKey, 'Encoder expects valid JSON input.', 'error');
            return;
        }

        if (!canEncodeToFormat(parsedValue, targetFormat)) {
            showStatus(
                config.statusKey,
                `Input cannot be converted into ${targetFormat}.`,
                'error',
            );
            return;
        }
    }

    const outputPanel = document.getElementById(config.outputId);
    const summaryContainer = document.getElementById(config.summaryId);
    const rawContent = document.getElementById(config.rawContentId);
    const toggleButton = document.getElementById(config.toggleRawId);
    const rawModal = config.rawModalId ? document.getElementById(config.rawModalId) : null;
    const progressText = document.getElementById(config.progressTextId);

    if (summaryContainer) {
        summaryContainer.innerHTML = '';
    }
    if (rawContent) {
        rawContent.textContent = '';
    }
    if (toggleButton) {
        toggleButton.disabled = true;
    }
    if (outputPanel) {
        outputPanel.classList.remove('is-visible');
    }
    if (rawModal && rawModal.classList.contains('open')) {
        closeModal(config.rawModalId);
    }
    hideStatus(config.statusKey);

    if (mode === 'decode') {
        updateDecoderEmptyState();
    }

    const actionText = mode === 'encode' ? 'Encoding…' : 'Decoding…';
    showProgress(config.statusKey, actionText);
    if (progressText) {
        progressText.textContent = actionText;
    }

    try {
        const body = { payload: inputValue, mode };
        if (mode === 'encode') {
            body.format = targetFormat;
        }

        const response = await fetch('/api/codec', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
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
            renderDecodedResult(summaryContainer, payload, mode);
        }
        if (rawContent) {
            rawContent.textContent = JSON.stringify(payload, null, 2);
            resetScrollPosition(rawContent);
        }
        if (outputPanel) {
            outputPanel.classList.add('is-visible');
        }
        if (toggleButton) {
            toggleButton.disabled = !rawContent || rawContent.textContent.trim().length === 0;
        }
        const successMessage = mode === 'encode'
            ? 'Payload encoded successfully!'
            : 'Response decoded successfully!';
        showStatus(config.statusKey, successMessage, 'success');

        if (mode === 'decode') {
            updateDecoderEmptyState();
        }
    } catch (error) {
        if (outputPanel) {
            outputPanel.classList.remove('is-visible');
        }
        if (toggleButton) {
            toggleButton.disabled = true;
        }
        if (rawModal && rawModal.classList.contains('open')) {
            closeModal(config.rawModalId);
        }
        const message = error instanceof Error ? error.message : String(error);
        const failurePrefix = mode === 'encode' ? 'Encoding failed' : 'Decoding failed';
        showStatus(config.statusKey, `${failurePrefix}: ${message}`, 'error');

        if (mode === 'decode') {
            updateDecoderEmptyState();
        }
    } finally {
        hideProgress(config.statusKey);
        if (mode === 'decode') {
            updateDecoderEmptyState();
        }
    }
}

function getSelectedDecoderMode() {
    return currentCodecMode;
}

function updateDecoderModeUI() {
    const mode = getSelectedDecoderMode();
    const decodeTab = document.getElementById('codec-mode-decode');
    const encodeTab = document.getElementById('codec-mode-encode');
    const decodePanel = document.getElementById(MODE_CONFIG.decode.panelId);
    const encodePanel = document.getElementById(MODE_CONFIG.encode.panelId);

    if (decodeTab) {
        decodeTab.classList.toggle('active', mode === 'decode');
        decodeTab.setAttribute('aria-selected', mode === 'decode' ? 'true' : 'false');
    }
    if (encodeTab) {
        encodeTab.classList.toggle('active', mode === 'encode');
        encodeTab.setAttribute('aria-selected', mode === 'encode' ? 'true' : 'false');
    }
    if (decodePanel) {
        decodePanel.classList.toggle('is-active', mode === 'decode');
        decodePanel.hidden = mode !== 'decode';
    }
    if (encodePanel) {
        encodePanel.classList.toggle('is-active', mode === 'encode');
        encodePanel.hidden = mode !== 'encode';
    }
}

export function switchCodecMode(mode) {
    if (mode !== 'decode' && mode !== 'encode') {
        return;
    }
    if (mode === currentCodecMode) {
        return;
    }
    currentCodecMode = mode;
    hideStatus('decoder');
    hideStatus('encoder');
    updateDecoderModeUI();
    const content = document.getElementById('codec-mode-content');
    if (content) {
        content.classList.remove('codec-mode-animating');
        void content.offsetWidth;
        content.classList.add('codec-mode-animating');
        content.addEventListener('animationend', () => {
            content.classList.remove('codec-mode-animating');
        }, { once: true });
    }
}

export function clearCodec(mode = getSelectedDecoderMode()) {
    const config = MODE_CONFIG[mode] || MODE_CONFIG[currentCodecMode];
    if (!config) {
        return;
    }

    const input = document.getElementById(config.inputId);
    const output = document.getElementById(config.outputId);
    const summary = document.getElementById(config.summaryId);
    const rawContent = document.getElementById(config.rawContentId);
    const toggleButton = document.getElementById(config.toggleRawId);
    const rawModal = config.rawModalId ? document.getElementById(config.rawModalId) : null;

    if (input) {
        input.value = '';
        resetScrollPosition(input);
    }
    if (summary) {
        summary.innerHTML = '';
    }
    if (rawContent) {
        rawContent.textContent = '';
        resetScrollPosition(rawContent);
    }
    if (toggleButton) {
        toggleButton.disabled = true;
    }
    if (output) {
        output.classList.remove('is-visible');
    }
    if (rawModal && rawModal.classList.contains('open')) {
        closeModal(config.rawModalId);
    }

    hideStatus(config.statusKey);
    hideProgress(config.statusKey);

    if (mode === 'decode') {
        updateDecoderEmptyState();
    }
    updateDecoderModeUI();
}

export function toggleRawCodec(mode = getSelectedDecoderMode()) {
    const config = MODE_CONFIG[mode] || MODE_CONFIG[currentCodecMode];
    if (!config || !config.rawModalId) {
        return;
    }

    const toggleButton = document.getElementById(config.toggleRawId);
    const rawContent = document.getElementById(config.rawContentId);
    const modal = document.getElementById(config.rawModalId);

    if (!toggleButton || !rawContent || !modal) {
        return;
    }

    if (toggleButton.disabled) {
        return;
    }

    const hasContent = rawContent.textContent && rawContent.textContent.trim().length > 0;
    if (!hasContent) {
        return;
    }

    if (modal.classList.contains('open')) {
        closeModal(config.rawModalId);
    } else {
        openModal(config.rawModalId);
    }
}

function autoSizeRawTextarea(textarea) {
    if (!(textarea instanceof HTMLTextAreaElement)) {
        return;
    }

    textarea.style.overflowY = 'hidden';
    textarea.style.height = 'auto';
    const scrollHeight = textarea.scrollHeight;
    textarea.style.height = scrollHeight ? `${scrollHeight}px` : '';
}

function renderDecodedResult(container, payload, mode = 'decode') {
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

    const sections = mode === 'encode'
        ? buildEncodeSections(payload.type, payload.data)
        : buildSections(payload.type, payload.data);
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

function buildEncodeSections(type, data) {
    const summaryInfo = findEncodedSummary(data);
    if (!summaryInfo) {
        return buildSections(type, data);
    }

    const { label, summary } = summaryInfo;
    const formatBlocks = createEncodedFormatElements(summary);
    if (formatBlocks.length === 0) {
        return buildSections(type, data);
    }

    const section = document.createElement('div');
    section.className = 'decoder-section codec-encoded-section';

    const heading = document.createElement('h4');
    heading.textContent = label || 'Encoded output';
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body codec-encoded-body';

    const formatsContainer = document.createElement('div');
    formatsContainer.className = 'codec-encoded-formats';
    formatBlocks.forEach(block => formatsContainer.appendChild(block));
    body.appendChild(formatsContainer);

    const byteLength = getSummaryByteLength(summary);
    if (typeof byteLength === 'number' && Number.isFinite(byteLength)) {
        const meta = document.createElement('div');
        meta.className = 'codec-encoded-meta';
        meta.textContent = `Byte length: ${byteLength}`;
        body.appendChild(meta);
    }

    section.appendChild(body);
    return [section];
}

function findEncodedSummary(value, label = '') {
    if (value === null || value === undefined) {
        return null;
    }

    if (Array.isArray(value)) {
        for (const item of value) {
            const result = findEncodedSummary(item, label);
            if (result) {
                return result;
            }
        }
        return null;
    }

    if (typeof value !== 'object') {
        return null;
    }

    if (looksLikeBinarySummary(value)) {
        const friendly = label ? formatKey(label) : 'Encoded output';
        return {
            summary: value,
            label: friendly.toLowerCase() === 'binary' ? 'Encoded output' : friendly,
        };
    }

    if (value.binary && looksLikeBinarySummary(value.binary)) {
        const friendly = label ? formatKey(label) : 'Encoded output';
        return {
            summary: value.binary,
            label: friendly.toLowerCase() === 'binary' ? 'Encoded output' : friendly,
        };
    }

    for (const [key, nested] of Object.entries(value)) {
        const result = findEncodedSummary(nested, key);
        if (result) {
            return result;
        }
    }

    return null;
}

function looksLikeBinarySummary(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    if (typeof value.hex === 'string' && value.hex.trim()) {
        return true;
    }
    if (typeof value.base64 === 'string' && value.base64.trim()) {
        return true;
    }
    if (typeof value.base64url === 'string' && value.base64url.trim()) {
        return true;
    }
    return false;
}

function createEncodedFormatElements(summary) {
    if (!summary || typeof summary !== 'object') {
        return [];
    }

    const order = ['hex', 'base64', 'base64url', 'colonHex'];
    const blocks = [];
    const used = new Set();
    const skipKeys = new Set(['encoding']);

    order.forEach(key => {
        const value = summary[key];
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (trimmed) {
                blocks.push(createEncodedFormatBlock(key, value));
                used.add(key);
            }
        }
    });

    Object.entries(summary).forEach(([key, value]) => {
        if (used.has(key)) {
            return;
        }
        if (skipKeys.has(key)) {
            return;
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) {
                return;
            }
            blocks.push(createEncodedFormatBlock(key, value));
            used.add(key);
        }
    });

    return blocks;
}

function createEncodedFormatBlock(key, value) {
    const block = document.createElement('div');
    block.className = 'codec-encoded-format';

    const label = document.createElement('div');
    label.className = 'codec-encoded-label';
    label.textContent = formatKey(key);
    block.appendChild(label);

    const pre = document.createElement('pre');
    pre.className = 'decoder-pre codec-encoded-value';
    pre.textContent = value;
    block.appendChild(pre);

    return block;
}

function getSummaryByteLength(summary) {
    if (!summary || typeof summary !== 'object') {
        return null;
    }
    if (typeof summary.byteLength === 'number') {
        return summary.byteLength;
    }
    if (typeof summary.length === 'number') {
        return summary.length;
    }
    return null;
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
    const baseType = getSectionBaseType(type);
    const preferredOrder = orderMap[baseType] || [];

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

function getSectionBaseType(type) {
    if (typeof type !== 'string') {
        return '';
    }
    const separatorIndex = type.indexOf(' (');
    if (separatorIndex === -1) {
        return type;
    }
    return type.slice(0, separatorIndex);
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

function normalizeEncoderFormat(format) {
    if (typeof format !== 'string') {
        return '';
    }
    return format.trim().toLowerCase();
}

function getCanonicalEncoderFormat(format) {
    const normalized = normalizeEncoderFormat(format);
    if (!normalized) {
        return '';
    }
    return ENCODER_FORMAT_ALIASES.get(normalized) || normalized;
}

function canEncodeToFormat(parsedValue, format) {
    const canonical = getCanonicalEncoderFormat(format);
    if (!canonical) {
        return true;
    }

    if (canonical === 'cbor' || canonical === 'json' || canonical === 'cose') {
        return parsedValue !== undefined;
    }

    if (['der', 'pem'].includes(canonical)) {
        return hasBinaryConvertibleValue(parsedValue);
    }

    return true;
}

function hasBinaryConvertibleValue(value) {
    if (value === null || value === undefined) {
        return false;
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return false;
        }
        if (isPemString(trimmed)) {
            return true;
        }
        if (isLikelyHex(trimmed)) {
            return true;
        }
        if (isLikelyBase64(trimmed) || isLikelyBase64Url(trimmed)) {
            return true;
        }
        return false;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return false;
        }
        if (value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
            return true;
        }
        return value.some((item) => hasBinaryConvertibleValue(item));
    }

    if (typeof value === 'object') {
        const keysToInspect = [
            'value',
            'data',
            'raw',
            'binary',
            'bytes',
            'hex',
            'base64',
            'base64url',
            'derBase64',
            'pem',
        ];

        for (const key of keysToInspect) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
                if (hasBinaryConvertibleValue(value[key])) {
                    return true;
                }
            }
        }

        return Object.values(value).some((entry) => hasBinaryConvertibleValue(entry));
    }

    return false;
}

function isLikelyHex(value) {
    const candidate = value.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
    return candidate.length > 0 && candidate.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(candidate);
}

function isLikelyBase64(value) {
    const candidate = value.replace(/\s+/g, '');
    if (!candidate) {
        return false;
    }
    return /^[A-Za-z0-9+/=]+$/.test(candidate);
}

function isLikelyBase64Url(value) {
    const candidate = value.replace(/\s+/g, '');
    if (!candidate) {
        return false;
    }
    return /^[A-Za-z0-9_\-]+=*$/.test(candidate);
}

function isPemString(value) {
    return /-----BEGIN [^-]+-----/.test(value) && /-----END [^-]+-----/.test(value);
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
            output.classList.contains('is-visible') &&
            summary &&
            summary.childElementCount > 0
    );

    description.style.display = hasVisibleOutput ? 'none' : 'block';
}

function initDecoderEmptyState() {
    updateDecoderEmptyState();
    updateDecoderModeUI();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDecoderEmptyState);
} else {
    initDecoderEmptyState();
}
