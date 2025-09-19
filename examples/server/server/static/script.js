// Import WebAuthn functions from the ponyfill library
import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON,
} from './webauthn-json.browser-ponyfill.js';

// Make functions globally available
window.create = create;
window.get = get;
window.parseCreationOptionsFromJSON = parseCreationOptionsFromJSON;
window.parseRequestOptionsFromJSON = parseRequestOptionsFromJSON;

        let currentSubTab = 'registration';
        let storedCredentials = [];
        let currentJsonMode = null;
        let currentJsonData = null;
        const utf8Decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8') : null;
        const JSON_EDITOR_INDENT_UNIT = '  ';

        const COSE_ALGORITHM_LABELS = {
            '-49': 'ML-DSA-65 (PQC) (-49)',
            '-48': 'ML-DSA-44 (PQC) (-48)',
            '-8': 'EdDSA (-8)',
            '-7': 'ES256 (-7)',
            '-37': 'PS256 (-37)',
            '-35': 'ES384 (-35)',
            '-36': 'ES512 (-36)',
            '-47': 'ES256K (-47)',
            '-257': 'RS256 (-257)',
            '-258': 'RS384 (-258)',
            '-259': 'RS512 (-259)',
            '-65535': 'RS1 (-65535)'
        };

const COSE_KEY_TYPE_LABELS = {
    '1': 'OKP (1)',
    '2': 'EC2 (2)',
    '3': 'RSA (3)',
    '4': 'Symmetric (4)',
    '7': 'ML-DSA (7)'
};

function formatBoolean(value) {
    if (value === true) {
        return '<span style="color: #0a8754; font-weight: 600;">true</span>';
    }
    if (value === false) {
        return '<span style="color: #c62828; font-weight: 600;">false</span>';
    }
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (normalized === 'true') {
            return '<span style="color: #0a8754; font-weight: 600;">true</span>';
        }
        if (normalized === 'false') {
            return '<span style="color: #c62828; font-weight: 600;">false</span>';
        }
    }
    if (value === null || value === undefined) {
        return '<span style="color: #6c757d;">N/A</span>';
    }
    const safeValue = String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    return `<span style="color: #6c757d;">${safeValue}</span>`;
}

function renderAttestationResultRow(label, value) {
    const safeLabel = String(label)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    return `
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
            <span style="min-width: 180px;"><strong>${safeLabel}:</strong></span>
            <span>${formatBoolean(value)}</span>
        </div>
    `.trim();
}

function describeCoseAlgorithm(alg) {
    if (alg === null || alg === undefined || (typeof alg === 'number' && Number.isNaN(alg))) {
        return 'Unknown';
    }
            const key = String(alg);
            return COSE_ALGORITHM_LABELS[key] || `Algorithm (${alg})`;
        }

        function describeCoseKeyType(keyType) {
            if (keyType === null || keyType === undefined || (typeof keyType === 'number' && Number.isNaN(keyType))) {
                return 'Unknown';
            }
            const key = String(keyType);
            return COSE_KEY_TYPE_LABELS[key] || `${keyType}`;
        }

        function describeMldsaParameterSet(alg) {
            if (alg === -48 || alg === '-48') {
                return 'ML-DSA-44';
            }
            if (alg === -49 || alg === '-49') {
                return 'ML-DSA-65';
            }
            return '';
        }

        function getCoseMapValue(coseMap, key) {
            if (!coseMap || typeof coseMap !== 'object') {
                return undefined;
            }
            if (Object.prototype.hasOwnProperty.call(coseMap, key)) {
                return coseMap[key];
            }
            const stringKey = String(key);
            if (Object.prototype.hasOwnProperty.call(coseMap, stringKey)) {
                return coseMap[stringKey];
            }
            return undefined;
        }

        // Info popup functionality
        let hideTimeout;
        
        function showInfoPopup(iconElement) {
            const popup = iconElement.querySelector('.info-popup');
            if (!popup) {
                return;
            }
            
            // Clear any pending hide timeout
            if (hideTimeout) {
                clearTimeout(hideTimeout);
                hideTimeout = null;
            }
            
            // Hide all other popups first
            document.querySelectorAll('.info-popup.show').forEach(p => p.classList.remove('show'));
            // Show this popup
            popup.classList.add('show');
            
            // Store English dimensions on first show (when English is active by default)
            if (!popup.hasAttribute('data-english-dimensions')) {
                // Wait for next frame to ensure popup is fully rendered
                requestAnimationFrame(() => {
                    const enText = popup.querySelector('.text-en.active');
                    if (enText) {
                        const enComputedStyle = window.getComputedStyle(enText);
                        const popupComputedStyle = window.getComputedStyle(popup);
                        
                        popup.setAttribute('data-english-width', popupComputedStyle.width);
                        popup.setAttribute('data-english-height', popupComputedStyle.height);
                        popup.setAttribute('data-english-text-height', enComputedStyle.height);
                        popup.setAttribute('data-english-dimensions', 'true');
                        
                        // Apply fixed dimensions to maintain consistency
                        popup.style.width = popupComputedStyle.width;
                        popup.style.minWidth = popupComputedStyle.width;
                        popup.style.height = popupComputedStyle.height;
                        popup.style.minHeight = popupComputedStyle.height;
                    }
                });
            }
            
            // Add event listeners if not already added
            if (!popup.hasAttribute('data-listeners-added')) {
                popup.addEventListener('mouseenter', () => {
                    if (hideTimeout) {
                        clearTimeout(hideTimeout);
                        hideTimeout = null;
                    }
                    popup.classList.add('show');
                });
                
                popup.addEventListener('mouseleave', () => {
                    hideTimeout = setTimeout(() => {
                        popup.classList.remove('show');
                    }, 200);
                });
                
                popup.setAttribute('data-listeners-added', 'true');
            }
        }
        
        function hideInfoPopup(iconElement) {
            const popup = iconElement.querySelector('.info-popup');
            if (!popup) {
                return;
            }
            // Add a delay to allow moving cursor to popup
            hideTimeout = setTimeout(() => {
                if (!popup.matches(':hover') && !iconElement.matches(':hover')) {
                    popup.classList.remove('show');
                }
            }, 200);
        }

        // Language toggle functionality
        function toggleLanguage(toggleElement) {
            // Handle both .info-popup and .alert containers
            const popup = toggleElement.closest('.info-popup') || toggleElement.closest('.alert');
            if (!popup) {
                console.error('Could not find parent container for language toggle');
                return;
            }
            
            const enText = popup.querySelector('.text-en');
            const zhText = popup.querySelector('.text-zh');
            
            if (!enText || !zhText) {
                console.error('Could not find text elements for language toggle');
                return;
            }
            
            // Store English dimensions on first toggle if not already stored
            if (!popup.hasAttribute('data-english-dimensions')) {
                const enComputedStyle = window.getComputedStyle(enText);
                const popupComputedStyle = window.getComputedStyle(popup);
                
                popup.setAttribute('data-english-width', popupComputedStyle.width);
                popup.setAttribute('data-english-height', popupComputedStyle.height);
                popup.setAttribute('data-english-text-height', enComputedStyle.height);
                popup.setAttribute('data-english-dimensions', 'true');
                
                // Apply fixed dimensions to maintain consistency
                popup.style.width = popupComputedStyle.width;
                popup.style.height = popupComputedStyle.height;
                popup.style.minHeight = popupComputedStyle.height;
            }
            
            if (enText.classList.contains('active')) {
                // Switch to Chinese
                enText.classList.remove('active');
                enText.classList.add('hidden');
                zhText.classList.remove('hidden');
                zhText.classList.add('active');
                toggleElement.textContent = '中';
                
                // Ensure Chinese text uses same dimensions as English
                const storedHeight = popup.getAttribute('data-english-text-height');
                if (storedHeight) {
                    zhText.style.height = storedHeight;
                    zhText.style.minHeight = storedHeight;
                }
            } else {
                // Switch to English
                zhText.classList.remove('active');
                zhText.classList.add('hidden');
                enText.classList.remove('hidden');
                enText.classList.add('active');
                toggleElement.textContent = 'ENG';
                
                // Restore English text dimensions
                const storedHeight = popup.getAttribute('data-english-text-height');
                if (storedHeight) {
                    enText.style.height = storedHeight;
                    enText.style.minHeight = storedHeight;
                }
            }
        }



        function isValidHex(str) {
            return /^[0-9a-fA-F]*$/.test(str) && str.length > 0;
        }

        function generateRandomHex(bytes) {
            const array = new Uint8Array(bytes);
            crypto.getRandomValues(array);
            return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Convert hex string to base64url format for WebAuthn JSON
        function hexToBase64Url(hexString) {
            if (!hexString) return '';
            
            // Ensure hex string has even length
            if (hexString.length % 2 !== 0) {
                hexString = '0' + hexString;
            }
            
            // Convert hex to bytes
            const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            
            // Convert to base64
            const base64 = btoa(String.fromCharCode(...bytes));
            
            // Convert to base64url (URL-safe base64)
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        // Convert base64url back to hex string
        function base64UrlToHex(base64url) {
            if (!base64url) return '';
            
            // Convert base64url to regular base64
            let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            
            // Add padding if needed
            while (base64.length % 4) {
                base64 += '=';
            }
            
            // Decode base64 to bytes
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Convert bytes to hex
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Convert base64 to base64url
        function base64ToBase64Url(base64) {
            if (!base64) return '';
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        // Convert hex to regular base64
        function hexToBase64(hexString) {
            if (!hexString) return '';
            
            // Convert hex to bytes
            const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            
            // Convert to base64
            return btoa(String.fromCharCode(...bytes));
        }

        // Convert hex to GUID format (for AAGUID display)
        function hexToGuid(hexString) {
            if (!hexString || hexString.length !== 32) return '';
            
            // Format as GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            return [
                hexString.substring(0, 8),
                hexString.substring(8, 12),
                hexString.substring(12, 16),
                hexString.substring(16, 20),
                hexString.substring(20, 32)
            ].join('-');
        }

        // Convert hex to JavaScript Uint8Array format
        function hexToJs(hexString) {
            if (!hexString) return '';
            
            // Convert hex to bytes
            const bytes = [];
            for (let i = 0; i < hexString.length; i += 2) {
                bytes.push(parseInt(hexString.substr(i, 2), 16));
            }
            
            return `new Uint8Array([${bytes.join(', ')}])`;
        }

        // Convert base64 to hex
        function base64ToHex(base64) {
            if (!base64) return '';
            
            // Decode base64 to bytes
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Convert bytes to hex
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Convert base64url to hex
        function base64UrlToHexFixed(base64url) {
            if (!base64url) return '';
            
            // Convert base64url to regular base64
            let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            
            // Add padding if needed
            while (base64.length % 4) {
                base64 += '=';
            }
            
            return base64ToHex(base64);
        }

        // Convert JavaScript Uint8Array format to hex
        function jsToHex(jsString) {
            if (!jsString) return '';
            
            // Extract numbers from the Uint8Array string
            const match = jsString.match(/new Uint8Array\(\[([0-9, ]+)\]\)/);
            if (!match) return '';
            
            const numbers = match[1].split(',').map(n => parseInt(n.trim()));
            return numbers.map(n => n.toString(16).padStart(2, '0')).join('');
        }

        // Convert value from one format to another
        function convertFormat(value, fromFormat, toFormat) {
            if (!value || fromFormat === toFormat) return value;

            // First convert to hex as intermediate format
            let hexValue = '';
            switch (fromFormat) {
                case 'hex':
                    hexValue = value;
                    break;
                case 'b64':
                    hexValue = base64ToHex(value);
                    break;
                case 'b64u':
                    hexValue = base64UrlToHexFixed(value);
                    break;
                case 'js':
                    hexValue = jsToHex(value);
                    break;
            }

            // Then convert from hex to target format
            switch (toFormat) {
                case 'hex':
                    return hexValue;
                case 'b64':
                    return hexToBase64(hexValue);
                case 'b64u':
                    return hexToBase64Url(hexValue);
                case 'js':
                    return hexToJs(hexValue);
                default:
                    return hexValue;
            }
        }

        function hexToUint8Array(hex) {
            if (!hex) return null;
            const normalized = hex.replace(/\s+/g, '').toLowerCase();
            if (normalized.length % 2 !== 0) {
                return null;
            }

            const bytes = new Uint8Array(normalized.length / 2);
            for (let i = 0; i < normalized.length; i += 2) {
                const byte = parseInt(normalized.substr(i, 2), 16);
                if (Number.isNaN(byte)) {
                    return null;
                }
                bytes[i / 2] = byte;
            }
            return bytes;
        }

        function base64ToUint8Array(base64) {
            if (!base64) return null;
            const normalized = base64.replace(/\s+/g, '');
            const binaryString = atob(normalized);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }

        function base64UrlToUint8Array(base64url) {
            if (!base64url) return null;
            let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) {
                base64 += '=';
            }
            return base64ToUint8Array(base64);
        }

        function base64UrlToUtf8String(base64url) {
            if (!base64url) return null;
            if (!utf8Decoder) return null;
            const bytes = base64UrlToUint8Array(base64url);
            if (!bytes) return null;
            try {
                return utf8Decoder.decode(bytes);
            } catch (error) {
                return null;
            }
        }

        function base64UrlToJson(base64url) {
            try {
                const decoded = base64UrlToUtf8String(base64url);
                if (!decoded) return null;
                return JSON.parse(decoded);
            } catch (error) {
                return null;
            }
        }

        function escapeHtml(value) {
            if (value === undefined || value === null) {
                return '';
            }
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function bufferSourceToUint8Array(value) {
            if (value instanceof ArrayBuffer) {
                return new Uint8Array(value);
            }

            if (ArrayBuffer.isView(value)) {
                return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
            }

            return null;
        }

        function arrayBufferToHex(buffer) {
            if (!buffer) {
                return '';
            }

            const view = bufferSourceToUint8Array(buffer);
            if (!view) {
                return '';
            }

            return Array.from(view).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        function normalizeClientExtensionResults(results) {
            if (results == null) {
                return results;
            }

            const bufferView = bufferSourceToUint8Array(results);
            if (bufferView) {
                return { $hex: arrayBufferToHex(bufferView) };
            }

            if (Array.isArray(results)) {
                return results.map(item => normalizeClientExtensionResults(item));
            }

            if (typeof results === 'object') {
                const normalized = {};
                Object.entries(results).forEach(([key, value]) => {
                    normalized[key] = normalizeClientExtensionResults(value);
                });
                return normalized;
            }

            return results;
        }

        function jsonValueToUint8Array(jsonValue) {
            if (!jsonValue) return null;

            const directBuffer = bufferSourceToUint8Array(jsonValue);
            if (directBuffer) {
                return directBuffer;
            }

            if (ArrayBuffer.isView(jsonValue)) {
                return new Uint8Array(jsonValue.buffer.slice(jsonValue.byteOffset, jsonValue.byteOffset + jsonValue.byteLength));
            }

            if (typeof jsonValue === 'string') {
                const trimmed = jsonValue.trim();
                if (!trimmed) {
                    return null;
                }

                if (isValidHex(trimmed) && trimmed.length % 2 === 0) {
                    return hexToUint8Array(trimmed);
                }

                // Interpret strings as base64url by default
                return base64UrlToUint8Array(trimmed);
            }

            if (typeof jsonValue === 'object') {
                if (jsonValue.$hex) {
                    return hexToUint8Array(jsonValue.$hex);
                }
                if (jsonValue.$base64url) {
                    return base64UrlToUint8Array(jsonValue.$base64url);
                }
                if (jsonValue.$base64) {
                    return base64ToUint8Array(jsonValue.$base64);
                }
                if (jsonValue.$js) {
                    try {
                        const parsed = JSON.parse(jsonValue.$js);
                        if (Array.isArray(parsed)) {
                            return new Uint8Array(parsed);
                        }
                    } catch (e) {
                        console.warn('Unable to parse $js value into Uint8Array', e);
                    }
                }
            }

            return null;
        }

        function jsonValueToArrayBuffer(jsonValue) {
            const bytes = jsonValueToUint8Array(jsonValue);
            return bytes ? bytes.buffer : null;
        }

        function convertCredProtectValue(value) {
            const numberToPolicy = {
                1: 'userVerificationOptional',
                2: 'userVerificationOptionalWithCredentialIDList',
                3: 'userVerificationRequired'
            };

            const stringNormalization = {
                userVerificationOptional: 'userVerificationOptional',
                userVerificationOptionalWithCredentialIDList: 'userVerificationOptionalWithCredentialIDList',
                userVerificationOptionalWithCredentialIdList: 'userVerificationOptionalWithCredentialIDList',
                userVerificationRequired: 'userVerificationRequired'
            };

            if (typeof value === 'number') {
                return numberToPolicy[value] ?? value;
            }

            if (typeof value === 'string') {
                return stringNormalization[value] ?? value;
            }

            return value;
        }

        function convertLargeBlobExtension(extValue) {
            if (extValue == null) {
                return extValue;
            }

            if (typeof extValue === 'string') {
                return { support: extValue };
            }

            if (typeof extValue !== 'object') {
                return extValue;
            }

            const converted = { ...extValue };

            if (extValue.write !== undefined) {
                const buffer = jsonValueToArrayBuffer(extValue.write);
                if (buffer) {
                    converted.write = buffer;
                }
            }

            if (extValue.support && typeof extValue.support === 'object') {
                // Support might be expressed using JSON helper format
                const supportValue = jsonValueToUint8Array(extValue.support);
                if (!supportValue) {
                    // If conversion failed treat as string via best effort
                    if (typeof extValue.support.$js === 'string') {
                        converted.support = extValue.support.$js;
                    }
                }
            }

            return converted;
        }

        function convertPrfExtension(extValue) {
            if (extValue == null || typeof extValue !== 'object') {
                return extValue;
            }

            const converted = {};

            if (extValue.eval) {
                const evalResult = {};
                if (extValue.eval.first) {
                    const firstBuffer = jsonValueToArrayBuffer(extValue.eval.first);
                    if (firstBuffer) {
                        evalResult.first = firstBuffer;
                    }
                }
                if (extValue.eval.second) {
                    const secondBuffer = jsonValueToArrayBuffer(extValue.eval.second);
                    if (secondBuffer) {
                        evalResult.second = secondBuffer;
                    }
                }
                if (Object.keys(evalResult).length > 0) {
                    converted.eval = evalResult;
                }
            }

            if (extValue.evalByCredential) {
                const evalByCredential = {};
                Object.entries(extValue.evalByCredential).forEach(([credentialId, evaluation]) => {
                    if (evaluation && typeof evaluation === 'object') {
                        const evalEntry = {};
                        if (evaluation.first) {
                            const firstBuffer = jsonValueToArrayBuffer(evaluation.first);
                            if (firstBuffer) {
                                evalEntry.first = firstBuffer;
                            }
                        }
                        if (evaluation.second) {
                            const secondBuffer = jsonValueToArrayBuffer(evaluation.second);
                            if (secondBuffer) {
                                evalEntry.second = secondBuffer;
                            }
                        }
                        if (Object.keys(evalEntry).length > 0) {
                            evalByCredential[credentialId] = evalEntry;
                        }
                    }
                });
                if (Object.keys(evalByCredential).length > 0) {
                    converted.evalByCredential = evalByCredential;
                }
            }

            // Preserve any additional properties that aren't explicitly handled
            Object.entries(extValue).forEach(([key, value]) => {
                if (!(key in converted)) {
                    converted[key] = value;
                }
            });

            return converted;
        }

        function convertExtensionsForClient(extensionsJson) {
            if (!extensionsJson || typeof extensionsJson !== 'object') {
                return undefined;
            }

            const converted = {};

            Object.entries(extensionsJson).forEach(([name, value]) => {
                switch (name) {
                    case 'credProtect':
                    case 'credentialProtectionPolicy':
                        converted.credentialProtectionPolicy = convertCredProtectValue(value);
                        break;
                    case 'enforceCredProtect':
                    case 'enforceCredentialProtectionPolicy':
                        converted.enforceCredentialProtectionPolicy = !!value;
                        break;
                    case 'largeBlob':
                        converted.largeBlob = convertLargeBlobExtension(value);
                        break;
                    case 'prf':
                        converted.prf = convertPrfExtension(value);
                        break;
                    case 'credProps':
                    case 'minPinLength':
                        converted[name] = !!value;
                        break;
                    default:
                        converted[name] = value;
                        break;
                }
            });

            return Object.keys(converted).length > 0 ? converted : undefined;
        }

        function sortObjectKeys(value) {
            if (Array.isArray(value)) {
                return value.map(item => sortObjectKeys(item));
            }

            if (value && Object.prototype.toString.call(value) === '[object Object]') {
                const sorted = {};
                Object.keys(value)
                    .sort((a, b) => a.localeCompare(b))
                    .forEach(key => {
                        sorted[key] = sortObjectKeys(value[key]);
                    });
                return sorted;
            }

            return value;
        }

        function wrapSelectionWithPair(editor, opening, closing) {
            const start = editor.selectionStart;
            const end = editor.selectionEnd;
            const value = editor.value;
            const before = value.slice(0, start);
            const selected = value.slice(start, end);
            const after = value.slice(end);
            editor.value = before + opening + selected + closing + after;

            if (selected.length > 0) {
                editor.selectionStart = start + opening.length;
                editor.selectionEnd = end + opening.length;
            } else {
                const caret = start + opening.length;
                editor.selectionStart = caret;
                editor.selectionEnd = caret;
            }
        }

        function applyJsonEditorAutoIndent(editor) {
            const value = editor.value;
            const selectionStart = editor.selectionStart;
            const selectionEnd = editor.selectionEnd;
            const before = value.slice(0, selectionStart);
            const after = value.slice(selectionEnd);
            const lineStart = before.lastIndexOf('\n') + 1;
            const currentLine = before.slice(lineStart);
            const trimmedLine = currentLine.trimEnd();
            const baseIndentMatch = currentLine.match(/^\s*/);
            const baseIndent = baseIndentMatch ? baseIndentMatch[0] : '';
            const closesImmediately = /^\s*[\}\]]/.test(after);

            let extraIndent = '';
            if (trimmedLine.endsWith('{') || trimmedLine.endsWith('[')) {
                extraIndent = JSON_EDITOR_INDENT_UNIT;
            }

            if (closesImmediately && extraIndent) {
                const inserted = `\n${baseIndent}${extraIndent}\n${baseIndent}`;
                editor.value = before + inserted + after;
                const caretPosition = before.length + 1 + baseIndent.length + extraIndent.length;
                editor.selectionStart = caretPosition;
                editor.selectionEnd = caretPosition;
                return;
            }

            if (closesImmediately && currentLine.trim() === '') {
                const dedentLength = Math.max(0, baseIndent.length - JSON_EDITOR_INDENT_UNIT.length);
                const dedentIndent = baseIndent.slice(0, dedentLength);
                const inserted = `\n${dedentIndent}`;
                editor.value = before + inserted + after;
                const caretPosition = before.length + inserted.length;
                editor.selectionStart = caretPosition;
                editor.selectionEnd = caretPosition;
                return;
            }

            const inserted = `\n${baseIndent}${extraIndent}`;
            editor.value = before + inserted + after;
            const caretPosition = before.length + inserted.length;
            editor.selectionStart = caretPosition;
            editor.selectionEnd = caretPosition;
        }

        function applyTabIndentation(editor, isShift) {
            const value = editor.value;
            const selectionStart = editor.selectionStart;
            const selectionEnd = editor.selectionEnd;
            const hasSelection = selectionStart !== selectionEnd;

            if (hasSelection && value.slice(selectionStart, selectionEnd).includes('\n')) {
                const selectedText = value.slice(selectionStart, selectionEnd);
                const lines = selectedText.split('\n');

                if (isShift) {
                    const dedentedLines = lines.map(line => {
                        if (line.startsWith(JSON_EDITOR_INDENT_UNIT)) {
                            return line.slice(JSON_EDITOR_INDENT_UNIT.length);
                        }
                        if (line.startsWith('\t')) {
                            return line.slice(1);
                        }
                        const match = line.match(/^ {1,2}/);
                        if (match) {
                            return line.slice(match[0].length);
                        }
                        return line;
                    });

                    const dedentedText = dedentedLines.join('\n');
                    const diff = selectedText.length - dedentedText.length;
                    editor.value = value.slice(0, selectionStart) + dedentedText + value.slice(selectionEnd);
                    editor.selectionStart = selectionStart;
                    editor.selectionEnd = selectionEnd - diff;
                } else {
                    const indentedText = lines.map(line => JSON_EDITOR_INDENT_UNIT + line).join('\n');
                    const diff = indentedText.length - selectedText.length;
                    editor.value = value.slice(0, selectionStart) + indentedText + value.slice(selectionEnd);
                    editor.selectionStart = selectionStart;
                    editor.selectionEnd = selectionEnd + diff;
                }
                return;
            }

            if (isShift) {
                const lineStart = value.lastIndexOf('\n', selectionStart - 1) + 1;
                if (value.slice(lineStart, lineStart + JSON_EDITOR_INDENT_UNIT.length) === JSON_EDITOR_INDENT_UNIT) {
                    editor.value = value.slice(0, lineStart) + value.slice(lineStart + JSON_EDITOR_INDENT_UNIT.length);
                    const newPos = Math.max(lineStart, selectionStart - JSON_EDITOR_INDENT_UNIT.length);
                    editor.selectionStart = newPos;
                    editor.selectionEnd = newPos;
                } else if (value[lineStart] === '\t') {
                    editor.value = value.slice(0, lineStart) + value.slice(lineStart + 1);
                    const newPos = Math.max(lineStart, selectionStart - 1);
                    editor.selectionStart = newPos;
                    editor.selectionEnd = newPos;
                } else {
                    const leadingSpaces = value.slice(lineStart, selectionStart).match(/^ +/);
                    if (leadingSpaces && leadingSpaces[0].length > 0) {
                        const removeCount = Math.min(leadingSpaces[0].length, JSON_EDITOR_INDENT_UNIT.length);
                        editor.value = value.slice(0, lineStart) + value.slice(lineStart + removeCount);
                        const newPos = Math.max(lineStart, selectionStart - removeCount);
                        editor.selectionStart = newPos;
                        editor.selectionEnd = newPos;
                    }
                }
            } else {
                const insertion = JSON_EDITOR_INDENT_UNIT;
                editor.value = value.slice(0, selectionStart) + insertion + value.slice(selectionEnd);
                const newPos = selectionStart + insertion.length;
                editor.selectionStart = newPos;
                editor.selectionEnd = newPos;
            }
        }

        function handleJsonEditorKeydown(event) {
            const editor = event.target;
            if (!(editor instanceof HTMLTextAreaElement)) {
                return;
            }

            if (event.key === 'Tab') {
                event.preventDefault();
                applyTabIndentation(editor, event.shiftKey);
                return;
            }

            if (event.key === 'Enter') {
                event.preventDefault();
                applyJsonEditorAutoIndent(editor);
                return;
            }

            if (event.ctrlKey || event.metaKey || event.altKey) {
                return;
            }

            const pairMap = {
                '{': '}',
                '[': ']',
            };

            const closing = pairMap[event.key];
            if (closing) {
                event.preventDefault();
                wrapSelectionWithPair(editor, event.key, closing);
            }
        }

        function normalizeToHex(value) {
            if (!value) {
                return '';
            }

            if (typeof value === 'string') {
                const trimmed = value.trim();
                if (!trimmed) {
                    return '';
                }

                if (isValidHex(trimmed) && trimmed.length % 2 === 0) {
                    return trimmed.toLowerCase();
                }

                try {
                    return base64UrlToHexFixed(trimmed).toLowerCase();
                } catch (error) {
                    return '';
                }
            }

            if (typeof value === 'object') {
                if (value.$hex) {
                    return normalizeToHex(value.$hex);
                }
                if (value.$base64url) {
                    return normalizeToHex(value.$base64url);
                }
                if (value.$base64) {
                    return normalizeToHex(value.$base64);
                }
                if (value.$js) {
                    return normalizeToHex(jsToHex(value.$js));
                }
            }

            return '';
        }

        function getCredentialIdHex(credential) {
            if (!credential) {
                return '';
            }

            const candidates = [
                credential.credentialIdHex,
                credential.credentialId,
                credential.credentialID,
                credential.id,
                credential.rawId
            ];

            for (const candidate of candidates) {
                const hex = normalizeToHex(candidate);
                if (hex) {
                    return hex.toLowerCase();
                }
            }

            return '';
        }

        function getCredentialUserHandleHex(credential) {
            if (!credential) {
                return '';
            }

            const candidates = [
                credential.userHandleHex,
                credential.userHandle,
                credential.userId,
                credential.userHandleBase64,
                credential.userHandleBase64Url
            ];

            for (const candidate of candidates) {
                const hex = normalizeToHex(candidate);
                if (hex) {
                    return hex.toLowerCase();
                }
            }

            return '';
        }

        // Get current binary format
        function getCurrentBinaryFormat() {
            return document.getElementById('binary-format').value;
        }

        // Change binary format for all relevant fields
        function changeBinaryFormat() {
            const newFormat = getCurrentBinaryFormat();
            const oldFormat = window.currentBinaryFormat || 'hex';
            
            // Update all hex input fields
            const fieldIds = [
                'user-id', 'challenge-reg', 'challenge-auth',
                'prf-eval-first-reg', 'prf-eval-second-reg',
                'prf-eval-first-auth', 'prf-eval-second-auth',
                'large-blob-write'
            ];
            
            fieldIds.forEach(fieldId => {
                const input = document.getElementById(fieldId);
                if (input && input.value) {
                    const convertedValue = convertFormat(input.value, oldFormat, newFormat);
                    input.value = convertedValue;
                }
            });
            
            // Update field labels
            updateFieldLabels(newFormat);
            
            // Update JSON editor
            updateJsonEditor();
            
            // Store current format for next change
            window.currentBinaryFormat = newFormat;
        }

        // Update field labels to show current format
        function updateFieldLabels(format) {
            const labelMappings = [
                { id: 'user-id', text: `User ID (${format})` },
                { id: 'challenge-reg', text: `Challenge (${format})` },
                { id: 'challenge-auth', text: `Challenge (${format})` },
                { id: 'prf-eval-first-reg', text: `prf eval first (${format})` },
                { id: 'prf-eval-second-reg', text: `prf eval second (${format})` },
                { id: 'prf-eval-first-auth', text: `prf eval first (${format})` },
                { id: 'prf-eval-second-auth', text: `prf eval second (${format})` },
                { id: 'large-blob-write', text: `largeBlob write (${format})` }
            ];
            
            labelMappings.forEach(mapping => {
                const input = document.getElementById(mapping.id);
                if (input) {
                    const label = document.querySelector(`label[for="${mapping.id}"]`);
                    if (label) {
                        label.textContent = mapping.text;
                    }
                }
            });
        }

        function validateHexInput(inputId, errorId, minBytes = 0) {
            const input = document.getElementById(inputId);
            const error = document.getElementById(errorId);
            const value = input.value.trim();
            const format = getCurrentBinaryFormat();
            
            if (!value) {
                error.style.display = 'none';
                input.classList.remove('error');
                return true;
            }
            
            let isValid = false;
            let hexValue = '';
            
            try {
                // Convert to hex for validation
                switch (format) {
                    case 'hex':
                        isValid = /^[0-9a-fA-F]+$/.test(value) && value.length >= minBytes * 2;
                        hexValue = value;
                        break;
                    case 'b64':
                        hexValue = base64ToHex(value);
                        isValid = hexValue.length >= minBytes * 2;
                        break;
                    case 'b64u':
                        hexValue = base64UrlToHexFixed(value);
                        isValid = hexValue.length >= minBytes * 2;
                        break;
                    case 'js':
                        hexValue = jsToHex(value);
                        isValid = hexValue.length >= minBytes * 2;
                        break;
                }
            } catch (e) {
                isValid = false;
            }
            
            if (!isValid) {
                error.style.display = 'block';
                input.classList.add('error');
                return false;
            } else {
                error.style.display = 'none';
                input.classList.remove('error');
                return true;
            }
        }

        // Tab switching functionality
        function switchTab(tab) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.toggle('active', content.id === `${tab}-tab`);
            });

            // Activate the corresponding nav button
            document.querySelectorAll('.nav-tab').forEach(navTab => {
                navTab.classList.toggle('active', navTab.dataset.tab === tab);
            });

            // Update JSON editor if in advanced tab
            if (tab === 'advanced') {
                updateJsonEditor();
            }

            document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab } }));
        }

        // Sub-tab switching for Registration/Authentication
        function switchSubTab(subTab) {
            currentSubTab = subTab;
            
            // Update sub-tab buttons
            document.querySelectorAll('.sub-tab').forEach(btn => {
                btn.classList.remove('active');
            });
            document.getElementById(subTab + '-tab-btn').classList.add('active');
            
            // Update sub-tab content
            document.querySelectorAll('.sub-tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(subTab + '-form').classList.add('active');
            
            // Update JSON editor
            updateJsonEditor();
        }

        // Section toggle functionality
        function toggleSection(sectionId) {
            const header = event.currentTarget;
            const content = document.getElementById(sectionId);
            const icon = header.querySelector('.expand-icon');
            
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded');
                header.classList.remove('expanded');
                icon.classList.remove('rotated');
            } else {
                content.classList.add('expanded');
                header.classList.add('expanded');
            }
        }

        // Randomization functions
        function randomizeUserId() {
            const userId = generateRandomHex(32);
            const format = getCurrentBinaryFormat();
            const formattedValue = convertFormat(userId, 'hex', format);
            document.getElementById('user-id').value = formattedValue;
            updateJsonEditor();
        }

        function randomizeChallenge(type) {
            const challenge = generateRandomHex(32);  // 32 bytes = 64 hex chars
            const format = getCurrentBinaryFormat();
            const formattedValue = convertFormat(challenge, 'hex', format);
            document.getElementById('challenge-' + type).value = formattedValue;
            updateJsonEditor();
        }

        function randomizePrfEval(evalType, formType) {
            const prfValue = generateRandomHex(32);  // 32 bytes = 64 hex chars
            const format = getCurrentBinaryFormat();
            const formattedValue = convertFormat(prfValue, 'hex', format);
            document.getElementById('prf-eval-' + evalType + '-' + formType).value = formattedValue;
            
            // Enable/disable second PRF eval based on first
            if (evalType === 'first') {
                const secondInput = document.getElementById('prf-eval-second-' + formType);
                const secondButton = secondInput.nextElementSibling;
                if (formattedValue) {
                    secondInput.disabled = false;
                    secondButton.disabled = false;
                } else {
                    secondInput.disabled = true;
                    secondButton.disabled = true;
                    secondInput.value = '';
                }
            }
            
            updateJsonEditor();
        }

        function randomizeLargeBlobWrite() {
            const blobValue = generateRandomHex(32);  // 32 bytes = 64 hex chars
            const format = getCurrentBinaryFormat();
            const formattedValue = convertFormat(blobValue, 'hex', format);
            document.getElementById('large-blob-write').value = formattedValue;
            updateJsonEditor();
        }

        function validatePrfInputs(formType) {
            const firstInput = document.getElementById('prf-eval-first-' + formType);
            const secondInput = document.getElementById('prf-eval-second-' + formType);
            const secondButton = secondInput.nextElementSibling;
            
            if (firstInput.value.trim() === '') {
                secondInput.disabled = true;
                secondButton.disabled = true;
                secondInput.value = '';
            } else {
                secondInput.disabled = false;
                secondButton.disabled = false;
            }
            
            updateJsonEditor();
        }

        function validateUserIdInput() {
            return validateHexInput('user-id', 'user-id-error', 1); // 1-64 bytes
        }

        function validateChallengeInputs() {
            let valid = true;
            const challengeRegInput = document.getElementById('challenge-reg');
            const challengeAuthInput = document.getElementById('challenge-auth');
            
            if (challengeRegInput) valid &= validateHexInput('challenge-reg', 'challenge-reg-error', 16); // min 16 bytes
            if (challengeAuthInput) valid &= validateHexInput('challenge-auth', 'challenge-auth-error', 16); // min 16 bytes
            
            return valid;
        }

        function validatePrfEvalInputs() {
            const prfInputs = [
                'prf-eval-first-reg', 
                'prf-eval-second-reg',
                'prf-eval-first-auth', 
                'prf-eval-second-auth'
            ];
            
            let valid = true;
            prfInputs.forEach(inputId => {
                const input = document.getElementById(inputId);
                if (input && !input.disabled && input.value.trim()) {
                    valid &= validateHexInput(inputId, inputId + '-error', 32); // exactly 32 bytes
                }
            });
            
            return valid;
        }

        function validateLargeBlobWriteInput() {
            const input = document.getElementById('large-blob-write');
            if (input && !input.disabled && input.value.trim()) {
                return validateHexInput('large-blob-write', 'large-blob-write-error', 1); // at least 1 byte
            }
            return true;
        }

        function validateLargeBlobDependency() {
            const largeBlobReg = document.getElementById('large-blob-reg')?.value;
            const residentKey = document.getElementById('resident-key')?.value;
            
            // If largeBlob is set to preferred or required, resident key must be required
            if (largeBlobReg && (largeBlobReg === 'preferred' || largeBlobReg === 'required')) {
                if (residentKey !== 'required') {
                    showStatus('advanced', 'Resident key must be set to "Required" for largeBlob to be enabled. Please change the Resident Key setting to "Required" before proceeding.', 'error');
                    return false;
                }
            }
            return true;
        }

        function checkLargeBlobCapability() {
            // Check if any saved credentials actually support large blob
            let hasLargeBlobCapability = false;
            
            // Check actual credential data for largeBlob support
            if (storedCredentials && storedCredentials.length > 0) {
                hasLargeBlobCapability = storedCredentials.some(cred => cred.largeBlob === true);
            }
            
            const largeBlobSelect = document.getElementById('large-blob-auth');
            const largeBlobWriteInput = document.getElementById('large-blob-write');
            const largeBlobWriteButton = largeBlobWriteInput?.nextElementSibling;
            const messageElement = document.getElementById('large-blob-capability-message');
            const readOption = largeBlobSelect?.querySelector('option[value="read"]');
            const writeOption = largeBlobSelect?.querySelector('option[value="write"]');
            
            if (hasLargeBlobCapability) {
                // Enable largeBlob read/write options
                if (readOption) readOption.disabled = false;
                if (writeOption) writeOption.disabled = false;
                if (messageElement) messageElement.style.display = 'none';
                
                // Enable/disable write input based on selection
                const currentValue = largeBlobSelect?.value;
                if (largeBlobWriteInput && largeBlobWriteButton) {
                    if (currentValue === 'write') {
                        largeBlobWriteInput.disabled = false;
                        largeBlobWriteButton.disabled = false;
                    } else {
                        largeBlobWriteInput.disabled = true;
                        largeBlobWriteButton.disabled = true;
                    }
                }
            } else {
                // Disable largeBlob read/write options
                if (readOption) readOption.disabled = true;
                if (writeOption) writeOption.disabled = true;
                if (largeBlobWriteInput) largeBlobWriteInput.disabled = true;
                if (largeBlobWriteButton) largeBlobWriteButton.disabled = true;
                if (messageElement) messageElement.style.display = 'block';
                
                // Reset selection to default
                if (largeBlobSelect) largeBlobSelect.value = '';
            }
        }

        // Console debug output functions for credential information from actual credential data
        function printRegistrationDebug(credential, createOptions, serverResponse) {
            // Extract actual values from credential response and server data (not request options)
            const clientExtensions = credential.getClientExtensionResults
                ? credential.getClientExtensionResults()
                : (credential.clientExtensionResults || {});
            const serverData = serverResponse || {};
            
            // Resident key - from actual client extension results or server-detected RK flag
            const residentKey = clientExtensions.credProps?.rk || serverData.actualResidentKey || false;
            console.log('Resident key:', residentKey);
            
            // Attestation format from actual server response
            const attestationFormat = serverData.attestationFormat || 'none';
            const attestationRetrieved = attestationFormat !== 'none';
            console.log('Attestation (retrieve or not, plus the format):', `${attestationRetrieved}, ${attestationFormat}`);
            
            // Exclude credentials - from actual server processing
            const excludeCredentials = serverData.excludeCredentialsUsed || false;
            console.log('exclude credentials:', excludeCredentials);
            
            // Fake credential ID length - from our actual setting
            const fakeCredLength = window.lastFakeCredLength || 0;
            console.log('fake credential id length:', fakeCredLength);
            
            // Challenge hex code - from actual response
            let challengeHex = '';
            if (credential.response && credential.response.clientDataJSON) {
                try {
                    const clientData = JSON.parse(atob(credential.response.clientDataJSON));
                    challengeHex = base64UrlToHex(clientData.challenge);
                } catch (e) {
                    // Fallback to empty if parsing fails
                }
            }
            console.log('challenge hex code:', challengeHex);
            
            // pubKeyCredParams used - from actual server processing
            const pubKeyCredParams = serverData.algorithmsUsed || [];
            console.log('pubkeycredparam used:', pubKeyCredParams);
            
            // Hints - from actual server processing
            const hints = serverData.hintsUsed || [];
            console.log('hints:', hints);
            
            // credProps extension - from actual client extension results
            const credPropsRequested = clientExtensions.credProps !== undefined;
            console.log('credprops (requested or not):', credPropsRequested);
            
            // minPinLength extension - from actual client extension results
            const minPinLengthRequested = clientExtensions.minPinLength !== undefined;
            console.log('minpinlength (requested or not):', minPinLengthRequested);
            
            // credProtect setting - from actual server processing
            const credProtectSetting = serverData.credProtectUsed ?? 'none';
            const credProtectLabelMap = {
                1: 'userVerificationOptional',
                2: 'userVerificationOptionalWithCredentialIDList',
                3: 'userVerificationRequired',
                userVerificationOptionalWithCredentialIDList: 'userVerificationOptionalWithCredentialIDList',
                userVerificationOptionalWithCredentialIdList: 'userVerificationOptionalWithCredentialIDList',
            };
            const credProtectDisplay = credProtectLabelMap[credProtectSetting] || credProtectSetting || 'none';
            console.log('credprotect setting:', credProtectDisplay);
            
            // enforce credProtect - from actual server processing
            const enforceCredProtect = serverData.enforceCredProtectUsed || false;
            console.log('enforce credprotect:', enforceCredProtect);
            
            // largeBlob - from actual client extension results
            const largeBlob = clientExtensions.largeBlob?.supported ?? 'none';
            console.log('largeblob:', largeBlob);
            
            // prf - from actual client extension results
            const prfEnabled = clientExtensions.prf !== undefined;
            console.log('prf:', prfEnabled);
            
            // prf eval first hex code - from actual client extension results
            const prfFirstHex = clientExtensions.prf?.results?.first !== undefined
                               ? extractHexFromJsonFormat(clientExtensions.prf.results.first)
                               : '';
            console.log('prf eval first hex code:', prfFirstHex);
            
            // prf eval second hex code - from actual client extension results
            const prfSecondHex = clientExtensions.prf?.results?.second !== undefined
                                ? extractHexFromJsonFormat(clientExtensions.prf.results.second)
                                : '';
            console.log('prf eval second hex code:', prfSecondHex);
        }
        
        function printAuthenticationDebug(assertion, requestOptions, serverResponse) {
            const clientExtensions = assertion.getClientExtensionResults
                ? assertion.getClientExtensionResults()
                : (assertion.clientExtensionResults || {});
            const serverData = serverResponse || {};
            
            // Fake credential ID length - from our actual setting
            const fakeCredLength = window.lastFakeCredLength || 0;
            console.log('Fake credential ID length:', fakeCredLength);
            
            // Challenge hex code - from actual assertion response
            let challengeHex = '';
            if (assertion.response && assertion.response.clientDataJSON) {
                try {
                    const clientData = JSON.parse(atob(assertion.response.clientDataJSON));
                    challengeHex = base64UrlToHex(clientData.challenge);
                } catch (e) {
                    // Fallback to empty if parsing fails
                }
            }
            console.log('challenge hex code:', challengeHex);
            
            // Hints - from actual server processing
            const hints = serverData.hintsUsed || [];
            console.log('hints:', hints);
            
            // largeBlob - from actual client extension results
            const largeBlobRead = clientExtensions.largeBlob?.blob !== undefined;
            const largeBlobWrite = clientExtensions.largeBlob?.written !== undefined;
            const largeBlobType = largeBlobWrite ? 'write' : (largeBlobRead ? 'read' : 'none');
            console.log('largeblob:', largeBlobType);
            
            // largeBlob write hex code - from actual extension results
            const largeBlobWriteHex = clientExtensions.largeBlob?.blob !== undefined
                                     ? extractHexFromJsonFormat(clientExtensions.largeBlob.blob)
                                     : '';
            console.log('largeblob write hex code:', largeBlobWriteHex);
            
            // prf eval first hex code - from actual client extension results
            const prfFirstHex = clientExtensions.prf?.results?.first !== undefined
                               ? extractHexFromJsonFormat(clientExtensions.prf.results.first)
                               : '';
            console.log('prf eval first hex code:', prfFirstHex);
            
            // prf eval second hex code - from actual client extension results
            const prfSecondHex = clientExtensions.prf?.results?.second !== undefined
                                ? extractHexFromJsonFormat(clientExtensions.prf.results.second)
                                : '';
            console.log('prf eval second hex code:', prfSecondHex);
        }
        
        // Helper function to extract hex from JSON format objects
        function extractHexFromJsonFormat(jsonValue) {
            if (!jsonValue) return '';
            const directBuffer = bufferSourceToUint8Array(jsonValue);
            if (directBuffer) return arrayBufferToHex(directBuffer);
            if (jsonValue.$hex) return jsonValue.$hex;
            if (jsonValue.$base64url) return base64UrlToHex(jsonValue.$base64url);
            if (jsonValue.$base64) return base64ToHex(jsonValue.$base64);
            if (typeof jsonValue === 'string') return base64UrlToHex(jsonValue);
            return '';
        }

        // Auto-detect and load PKL credentials
        async function loadSavedCredentials() {
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
                    storedCredentials = normalizedCredentials;
                    updateCredentialsDisplay();
                    updateJsonEditor(); // Update JSON editor in case allowCredentials needs updating
                }
            } catch (error) {
                // Silently fail credential loading
            }
        }

        function updateCredentialsDisplay() {
            const credentialsList = document.getElementById('credentials-list');
            
            if (storedCredentials.length === 0) {
                credentialsList.innerHTML = '<p style="color: #6c757d; font-style: normal;">No credentials registered yet.</p>';
                checkLargeBlobCapability(); // Check capability when no credentials
                updateAllowCredentialsDropdown(); // Update dropdown when no credentials
                return;
            }

            credentialsList.innerHTML = storedCredentials.map((cred, index) => {
                // Determine what features this credential supports
                const features = [];
                if (cred.residentKey === true || cred.discoverable === true) {
                    features.push('Discoverable');
                }
                if (cred.largeBlob === true || cred.largeBlobSupported === true) {
                    features.push('largeBlob');
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
            
            // Check large blob capability after updating display
            checkLargeBlobCapability();
            
            // Update allow credentials dropdown with individual credentials
            updateAllowCredentialsDropdown();
        }

        function updateAllowCredentialsDropdown() {
            const allowCredentialsSelect = document.getElementById('allow-credentials');
            if (!allowCredentialsSelect) return;
            
            // Store current selection
            const currentValue = allowCredentialsSelect.value;
            
            // Clear existing options except the default ones
            allowCredentialsSelect.innerHTML = `
                <option value="all">All credentials</option>
                <option value="empty">Empty (resident key only)</option>
            `;

            // Add individual credential options
            if (storedCredentials && storedCredentials.length > 0) {
                storedCredentials.forEach((cred, index) => {
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
            
            // Restore selection if it's still valid
            if (currentValue && Array.from(allowCredentialsSelect.options).some(opt => opt.value === currentValue)) {
                allowCredentialsSelect.value = currentValue;
            } else {
                allowCredentialsSelect.value = 'all'; // Default to all if current selection is invalid
            }
            
            // Update JSON editor when dropdown is updated
            updateJsonEditor();
        }

        function updateGlobalScrollLock() {
            const overlayActive = document.getElementById('json-editor-overlay')?.classList.contains('active');
            const modalActive = document.querySelector('.modal.open');
            const mdsModalActive = document.querySelector('.mds-modal:not([hidden])');
            const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive);

            const targets = [document.body, document.documentElement].filter(Boolean);
            targets.forEach(target => {
                target.classList.toggle('modal-open', shouldLock);
            });
        }

        function resetModalScroll(modal) {
            if (!modal) {
                return;
            }

            modal.scrollTop = 0;
            modal.querySelectorAll('.modal-content, .modal-body, textarea, pre, code, .credential-code-block').forEach(element => {
                if (element) {
                    element.scrollTop = 0;
                    if (element.scrollLeft !== undefined) {
                        element.scrollLeft = 0;
                    }
                }
            });
        }

        function openModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                resetModalScroll(modal);
                modal.classList.add('open');
                requestAnimationFrame(() => resetModalScroll(modal));
                updateGlobalScrollLock();
            }
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('open');
                requestAnimationFrame(() => resetModalScroll(modal));
                updateGlobalScrollLock();
            }
        }

        function toggleJsonEditorExpansion(forceCollapse = false) {
            const container = document.getElementById('json-editor-container');
            const overlay = document.getElementById('json-editor-overlay');
            const toggleButton = document.getElementById('json-editor-expand');

            if (!container || !overlay || !toggleButton) {
                return;
            }

            const shouldExpand = forceCollapse ? false : !container.classList.contains('expanded');

            if (shouldExpand) {
                container.classList.add('expanded');
                overlay.classList.add('active');
                toggleButton.innerHTML = '<span aria-hidden="true">✕</span>';
                toggleButton.setAttribute('aria-label', 'Close expanded JSON editor');
                toggleButton.setAttribute('title', 'Close expanded JSON editor');
                toggleButton.setAttribute('aria-expanded', 'true');
                const editor = document.getElementById('json-editor');
                if (editor) {
                    editor.scrollTop = 0;
                }
            } else {
                container.classList.remove('expanded');
                overlay.classList.remove('active');
                toggleButton.innerHTML = '<span aria-hidden="true">⛶</span>';
                toggleButton.setAttribute('aria-label', 'Expand JSON editor');
                toggleButton.setAttribute('title', 'Expand JSON editor');
                toggleButton.setAttribute('aria-expanded', 'false');
            }

            updateGlobalScrollLock();
        }

        function showCredentialDetails(index) {
            const cred = storedCredentials[index];
            if (!cred) return;

            const modalBody = document.getElementById('modalBody');

            // Helper functions for format conversion
            
            
            
            
            // Construct the detailed credential information in the exact format requested
            let detailsHtml = '';
            
            // User info at creation
            detailsHtml += `
            <div style="margin-bottom: 1.5rem;">
                <h4 style="color: #0072CE; margin-bottom: 0.5rem;">User info at creation</h4>
                <div style="font-size: 0.9rem; line-height: 1.4;">
                    <div><strong>Name:</strong> ${cred.userName || cred.email || 'N/A'}</div>
                    <div style="margin-bottom: 0.5rem;"><strong>Display name:</strong> ${cred.displayName || cred.userName || cred.email || 'N/A'}</div>
                </div>`;
            
            // User handle (User ID) section
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

            let aaguidHex = '';
            let aaguidGuid = '';
            if (cred.aaguid) {
                if (typeof cred.aaguid === 'string') {
                    aaguidHex = cred.aaguid.replace(/-/g, '').toLowerCase();
                } else if (Array.isArray(cred.aaguid)) {
                    aaguidHex = Array.from(cred.aaguid).map(byte => byte.toString(16).padStart(2, '0')).join('');
                } else if (ArrayBuffer.isView(cred.aaguid)) {
                    aaguidHex = Array.from(new Uint8Array(cred.aaguid.buffer, cred.aaguid.byteOffset, cred.aaguid.byteLength))
                        .map(byte => byte.toString(16).padStart(2, '0'))
                        .join('');
                } else if (cred.aaguid instanceof ArrayBuffer) {
                    aaguidHex = Array.from(new Uint8Array(cred.aaguid))
                        .map(byte => byte.toString(16).padStart(2, '0'))
                        .join('');
                } else if (typeof cred.aaguid.hex === 'function') {
                    aaguidHex = cred.aaguid.hex();
                }

                if (aaguidHex) {
                    aaguidHex = aaguidHex.toLowerCase();
                    aaguidGuid = aaguidHex.length === 32 ? hexToGuid(aaguidHex) : '';
                }
            }

            const discoverableValue = cred.residentKey ?? cred.discoverable ?? false;
            const largeBlobSupported = cred.largeBlob ?? cred.largeBlobSupported ?? false;
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

            if (aaguidHex) {
                const aaguidB64 = hexToBase64(aaguidHex);
                const aaguidB64u = hexToBase64Url(aaguidHex);
                const rootVerified = attestationRootValue === true ||
                    (typeof attestationRootValue === 'string' && attestationRootValue.trim().toLowerCase() === 'true');
                const aaguidNavigateValue = aaguidGuid ? aaguidGuid.toLowerCase() : '';
                const infoButton = rootVerified && aaguidNavigateValue
                    ? `<button type="button" class="credential-info-button credential-aaguid-button" data-aaguid="${escapeHtml(aaguidNavigateValue)}" aria-label="View authenticator metadata">Info</button>`
                    : '';

                const sections = [];
                if (aaguidB64) {
                    sections.push(`
                        <div class="credential-aaguid-value">
                            <span class="credential-aaguid-value-label">b64</span>
                            <div class="credential-code-block">${aaguidB64}</div>
                        </div>`);
                }
                if (aaguidB64u) {
                    sections.push(`
                        <div class="credential-aaguid-value">
                            <span class="credential-aaguid-value-label">b64u</span>
                            <div class="credential-code-block">${aaguidB64u}</div>
                        </div>`);
                }
                sections.push(`
                    <div class="credential-aaguid-value">
                        <span class="credential-aaguid-value-label">hex</span>
                        <div class="credential-code-block">${aaguidHex}</div>
                    </div>`);
                if (aaguidGuid) {
                    sections.push(`
                        <div class="credential-aaguid-value">
                            <span class="credential-aaguid-value-label">guid</span>
                            <div class="credential-code-block">${aaguidGuid}</div>
                        </div>`);
                }

                detailsHtml += `
                    <div class="credential-aaguid-row">
                        <span class="credential-aaguid-label">AAGUID</span>
                        ${infoButton}
                    </div>
                    <div class="credential-aaguid-values">
                        ${sections.join('')}
                    </div>`;
            }

            detailsHtml += `</div>`;

            // Properties section
            detailsHtml += `
            <div style="margin-bottom: 1.5rem;">
                <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Properties</h4>
                <div style="font-size: 0.9rem; line-height: 1.4;">
                    <div><strong>Discoverable (resident key):</strong> ${formatBoolean(discoverableValue)}</div>
                    <div><strong>Supports largeBlob:</strong> ${formatBoolean(largeBlobSupported)}</div>
                    <div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid rgba(0, 114, 206, 0.15);">
                        ${attestationRowsHtml}
                    </div>
                </div>
            </div>`;
            
            // Attestation Format - always show
            detailsHtml += `
            <div style="margin-bottom: 1.5rem;">
                <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Format</h4>
                <div style="font-size: 0.9rem;">${cred.attestationFormat || 'none'}</div>
            </div>`;
            
            // Authenticator Data (registration)
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
            
            // Client extension outputs (registration)
            if (cred.clientExtensionOutputs && Object.keys(cred.clientExtensionOutputs).length > 0) {
                detailsHtml += `
                <div style="margin-bottom: 1.5rem;">
                    <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Client extension outputs (registration)</h4>
                    <div class="credential-code-block" style="font-size: 0.9rem; border-radius: 16px;">${JSON.stringify(cred.clientExtensionOutputs, null, 2)}</div>
                </div>`;
            }
            
            // Public Key section
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

        function navigateToMdsAuthenticator(aaguid) {
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

        function closeCredentialModal() {
            closeModal('credentialModal');
        }

        function closeRegistrationResultModal() {
            closeModal('registrationResultModal');
        }

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

        function formatCertificateDetails(details) {
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

            const hexToColonLines = (hexString, bytesPerLine = 16) => {
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

        function renderCertificateDetails(details) {
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

        function autoResizeCertificateTextareas(context) {
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

        function showRegistrationResultModal(credentialJson, relyingPartyInfo) {
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

        async function deleteCredential(username, index) {
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
                    // Remove from local array
                    storedCredentials.splice(index, 1);
                    updateCredentialsDisplay();
                    
                    // Show success message with important note about authenticator credentials
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



        // Reset functions
        function resetRegistrationForm() {
            // Reset User Identity - randomize userid and username fields
            randomizeUserId();
            const randomUsername = generateRandom10DigitUsername();
            document.getElementById('user-name').value = randomUsername;
            document.getElementById('user-display-name').value = randomUsername;
            
            // Reset Authenticator Selection
            document.getElementById('authenticator-attachment').value = '';
            document.getElementById('resident-key').value = 'discouraged';
            document.getElementById('user-verification-reg').value = 'preferred';
            document.getElementById('attestation').value = 'none';
            document.getElementById('exclude-credentials').checked = true;
            document.getElementById('fake-cred-length-reg').value = '128';
            
            // Reset Other Options - randomize challenge
            randomizeChallenge('reg');
            document.getElementById('timeout-reg').value = '90000';
            document.getElementById('param-eddsa').checked = true;
            document.getElementById('param-es256').checked = true;
            document.getElementById('param-rs256').checked = true;
            document.getElementById('param-es384').checked = false;
            document.getElementById('param-es512').checked = false;
            document.getElementById('param-rs384').checked = false;
            document.getElementById('param-rs512').checked = false;
            document.getElementById('param-rs1').checked = false;
            document.getElementById('hint-client-device').checked = false;
            document.getElementById('hint-hybrid').checked = false;
            document.getElementById('hint-security-key').checked = false;
            
            // Reset Extensions
            document.getElementById('cred-props').checked = true;
            document.getElementById('min-pin-length').checked = false;
            document.getElementById('cred-protect').value = '';
            document.getElementById('enforce-cred-protect').checked = true;
            document.getElementById('enforce-cred-protect').disabled = true;
            document.getElementById('large-blob-reg').value = '';
            document.getElementById('prf-reg').checked = false;
            document.getElementById('prf-eval-first-reg').value = '';
            document.getElementById('prf-eval-second-reg').value = '';
            document.getElementById('prf-eval-second-reg').disabled = true;
            
            updateJsonEditor();
        }

        function resetAuthenticationForm() {
            // Reset Credential Selection
            document.getElementById('user-verification-auth').value = 'preferred';
            document.getElementById('allow-credentials').value = 'all';
            document.getElementById('fake-cred-length-auth').value = '256';
            
            // Reset Other Options - randomize challenge
            randomizeChallenge('auth');
            document.getElementById('timeout-auth').value = '90000';
            document.getElementById('hint-client-device-auth').checked = false;
            document.getElementById('hint-hybrid-auth').checked = false;
            document.getElementById('hint-security-key-auth').checked = false;
            
            // Reset Extensions
            document.getElementById('large-blob-auth').value = '';
            document.getElementById('large-blob-write').value = '';
            document.getElementById('large-blob-write').disabled = true;
            document.getElementById('prf-eval-first-auth').value = '';
            document.getElementById('prf-eval-second-auth').value = '';
            document.getElementById('prf-eval-second-auth').disabled = true;
            
            updateJsonEditor();
        }

        // JSON Editor update function
        function updateJsonEditor() {
            let options = {};
            let title = 'JSON Editor';
            
            if (currentSubTab === 'registration') {
                options = getCredentialCreationOptions();
                title = 'JSON Editor (CredentialCreationOptions)';
            } else if (currentSubTab === 'authentication') {
                options = getCredentialRequestOptions();
                title = 'JSON Editor (CredentialRequestOptions)';
            }
            
            const jsonEditor = document.getElementById('json-editor');
            if (jsonEditor) {
                const sortedOptions = sortObjectKeys(options);
                jsonEditor.value = JSON.stringify(sortedOptions, null, 2);
            }
            
            // Update the title
            const titleElement = document.querySelector('.json-editor-column h3');
            if (titleElement) {
                titleElement.textContent = title;
            }
        }

        // Save JSON Editor changes to settings
        function saveJsonEditor() {
            try {
                const jsonText = document.getElementById('json-editor').value;
                const parsed = JSON.parse(jsonText);
                
                // Validate the structure
                if (!parsed.publicKey) {
                    throw new Error('Invalid JSON structure: Missing "publicKey" property');
                }
                
                const publicKey = parsed.publicKey;
                
                if (currentSubTab === 'registration') {
                    // Validate CredentialCreationOptions structure
                    if (!publicKey.rp || !publicKey.user || !publicKey.challenge) {
                        throw new Error('Invalid CredentialCreationOptions: Missing required properties (rp, user, challenge)');
                    }
                    
                    // Update form fields from JSON
                    updateRegistrationFormFromJson(publicKey);
                } else if (currentSubTab === 'authentication') {
                    // Validate CredentialRequestOptions structure
                    if (!publicKey.challenge) {
                        throw new Error('Invalid CredentialRequestOptions: Missing required challenge property');
                    }
                    
                    // Update form fields from JSON
                    updateAuthenticationFormFromJson(publicKey);
                }
                
                // Show success message
                const statusDiv = document.querySelector('#advanced-tab .status') || 
                                document.querySelector('#advanced-status');
                if (statusDiv) {
                    statusDiv.textContent = 'JSON changes saved successfully!';
                    statusDiv.className = 'status success';
                    statusDiv.style.display = 'block';
                    setTimeout(() => {
                        statusDiv.style.display = 'none';
                    }, 3000);
                }
                
            } catch (error) {
                // Show error message
                const statusDiv = document.querySelector('#advanced-tab .status') || 
                                document.querySelector('#advanced-status');
                if (statusDiv) {
                    statusDiv.textContent = `JSON validation failed: ${error.message}`;
                    statusDiv.className = 'status error';
                    statusDiv.style.display = 'block';
                    setTimeout(() => {
                        statusDiv.style.display = 'none';
                    }, 5000);
                }
            }
        }

        // Reset JSON Editor to match current settings
        function resetJsonEditor() {
            updateJsonEditor();
            
            // Show reset confirmation
            const statusDiv = document.querySelector('#advanced-tab .status') || 
                            document.querySelector('#advanced-status');
            if (statusDiv) {
                statusDiv.textContent = 'JSON editor reset to current settings';
                statusDiv.className = 'status info';
                statusDiv.style.display = 'block';
                setTimeout(() => {
                    statusDiv.style.display = 'none';
                }, 2000);
            }
        }

        // Update registration form fields from JSON
        function updateRegistrationFormFromJson(publicKey) {
            // Update user fields
            if (publicKey.user) {
                if (publicKey.user.id) {
                    let userIdValue = '';
                    if (publicKey.user.id.$base64) {
                        userIdValue = base64UrlToHex(publicKey.user.id.$base64);
                    } else if (publicKey.user.id.$base64url) {
                        userIdValue = base64UrlToHex(publicKey.user.id.$base64url);
                    } else if (publicKey.user.id.$hex) {
                        userIdValue = publicKey.user.id.$hex;
                    } else if (typeof publicKey.user.id === 'string') {
                        userIdValue = base64UrlToHex(publicKey.user.id);
                    }
                    if (userIdValue) {
                        document.getElementById('user-id').value = userIdValue;
                    }
                }
                if (publicKey.user.name) {
                    document.getElementById('user-name').value = publicKey.user.name;
                }
                if (publicKey.user.displayName) {
                    document.getElementById('user-display-name').value = publicKey.user.displayName;
                }
            }
            
            // Update challenge
            if (publicKey.challenge) {
                let challengeValue = '';
                if (publicKey.challenge.$base64) {
                    challengeValue = base64UrlToHex(publicKey.challenge.$base64);
                } else if (publicKey.challenge.$base64url) {
                    challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
                } else if (publicKey.challenge.$hex) {
                    challengeValue = publicKey.challenge.$hex;
                } else if (typeof publicKey.challenge === 'string') {
                    challengeValue = base64UrlToHex(publicKey.challenge);
                }
                if (challengeValue) {
                    document.getElementById('challenge-reg').value = challengeValue;
                }
            }
            
            // Update timeout
            if (publicKey.timeout) {
                document.getElementById('timeout-reg').value = publicKey.timeout.toString();
            }
            
            // Update attestation
            if (Object.prototype.hasOwnProperty.call(publicKey, 'attestation')) {
                document.getElementById('attestation').value = publicKey.attestation || 'none';
            }
            
            // Update pubKeyCredParams (algorithms)
            if (publicKey.pubKeyCredParams && Array.isArray(publicKey.pubKeyCredParams)) {
                // First clear all algorithm checkboxes
                if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = false;
                if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = false;
                document.getElementById('param-eddsa').checked = false;
                document.getElementById('param-es256').checked = false;
                document.getElementById('param-rs256').checked = false;
                document.getElementById('param-es384').checked = false;
                document.getElementById('param-es512').checked = false;
                document.getElementById('param-rs384').checked = false;
                document.getElementById('param-rs512').checked = false;
                document.getElementById('param-rs1').checked = false;

                // Then set the ones specified in the JSON
                publicKey.pubKeyCredParams.forEach(param => {
                    if (param && Object.prototype.hasOwnProperty.call(param, 'alg')) {
                        const rawAlg = param.alg;
                        const algValue = typeof rawAlg === 'string' ? parseInt(rawAlg, 10) : rawAlg;
                        if (Number.isNaN(algValue)) {
                            return;
                        }
                        switch(algValue) {
                            case -48:
                                if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = true;
                                break;
                            case -49:
                                if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = true;
                                break;
                            case -8:
                                document.getElementById('param-eddsa').checked = true;
                                break;
                            case -7:
                                document.getElementById('param-es256').checked = true;
                                break;
                            case -257:
                                document.getElementById('param-rs256').checked = true;
                                break;
                            case -35:
                                document.getElementById('param-es384').checked = true;
                                break;
                            case -36:
                                document.getElementById('param-es512').checked = true;
                                break;
                            case -258:
                                document.getElementById('param-rs384').checked = true;
                                break;
                            case -259:
                                document.getElementById('param-rs512').checked = true;
                                break;
                            case -65535:
                                document.getElementById('param-rs1').checked = true;
                                break;
                        }
                    }
                });
            }
            
            // Update authenticator selection
            if (publicKey.authenticatorSelection) {
                if (publicKey.authenticatorSelection.authenticatorAttachment) {
                    document.getElementById('authenticator-attachment').value = publicKey.authenticatorSelection.authenticatorAttachment;
                }
                const residentKeyElement = document.getElementById('resident-key');
                if (residentKeyElement) {
                    let residentKeySetting = publicKey.authenticatorSelection.residentKey || 'discouraged';
                    if (publicKey.authenticatorSelection.requireResidentKey === true) {
                        residentKeySetting = 'required';
                    }
                    residentKeyElement.value = residentKeySetting;
                }
                if (Object.prototype.hasOwnProperty.call(publicKey.authenticatorSelection, 'userVerification')) {
                    const userVerificationValue = publicKey.authenticatorSelection.userVerification || 'preferred';
                    document.getElementById('user-verification-reg').value = userVerificationValue;
                }
            }

            const excludeCredentialsCheckbox = document.getElementById('exclude-credentials');
            if (excludeCredentialsCheckbox) {
                const excludeArray = Array.isArray(publicKey.excludeCredentials)
                    ? publicKey.excludeCredentials
                    : [];
                excludeCredentialsCheckbox.checked = excludeArray.length > 0;
            }

            // Update extensions
            if (publicKey.extensions) {
                const credPropsCheckbox = document.getElementById('cred-props');
                if (credPropsCheckbox) {
                    credPropsCheckbox.checked = !!publicKey.extensions.credProps;
                }

                const minPinLengthCheckbox = document.getElementById('min-pin-length');
                if (minPinLengthCheckbox) {
                    minPinLengthCheckbox.checked = !!publicKey.extensions.minPinLength;
                }

                const credProtectSelect = document.getElementById('cred-protect');
                const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
                if (credProtectSelect && enforceCredProtectCheckbox) {
                    const policy = publicKey.extensions.credentialProtectionPolicy || '';
                    credProtectSelect.value = policy;
                    if (policy) {
                        enforceCredProtectCheckbox.disabled = false;
                        enforceCredProtectCheckbox.checked = !!publicKey.extensions.enforceCredentialProtectionPolicy;
                    } else {
                        enforceCredProtectCheckbox.checked = true;
                        enforceCredProtectCheckbox.disabled = true;
                    }
                }

                if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
                    if (publicKey.extensions.prf.eval.first) {
                        let prfFirstValue = '';
                        if (publicKey.extensions.prf.eval.first.$base64) {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                        } else if (publicKey.extensions.prf.eval.first.$base64url) {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                        } else if (publicKey.extensions.prf.eval.first.$hex) {
                            prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                        } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                        }
                        if (prfFirstValue) {
                            document.getElementById('prf-eval-first-reg').value = prfFirstValue;
                        }
                    }
                    if (publicKey.extensions.prf.eval.second) {
                        let prfSecondValue = '';
                        if (publicKey.extensions.prf.eval.second.$base64) {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                        } else if (publicKey.extensions.prf.eval.second.$base64url) {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                        } else if (publicKey.extensions.prf.eval.second.$hex) {
                            prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                        } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                        }
                        if (prfSecondValue) {
                            document.getElementById('prf-eval-second-reg').value = prfSecondValue;
                        }
                    }
                }
            } else {
                const credPropsCheckbox = document.getElementById('cred-props');
                if (credPropsCheckbox) {
                    credPropsCheckbox.checked = false;
                }

                const minPinLengthCheckbox = document.getElementById('min-pin-length');
                if (minPinLengthCheckbox) {
                    minPinLengthCheckbox.checked = false;
                }

                const credProtectSelect = document.getElementById('cred-protect');
                const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
                if (credProtectSelect && enforceCredProtectCheckbox) {
                    credProtectSelect.value = '';
                    enforceCredProtectCheckbox.checked = true;
                    enforceCredProtectCheckbox.disabled = true;
                }
            }
        }

        // Update authentication form fields from JSON
        function updateAuthenticationFormFromJson(publicKey) {
            // Update challenge
            if (publicKey.challenge) {
                let challengeValue = '';
                if (publicKey.challenge.$base64) {
                    challengeValue = base64UrlToHex(publicKey.challenge.$base64);
                } else if (publicKey.challenge.$base64url) {
                    challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
                } else if (publicKey.challenge.$hex) {
                    challengeValue = publicKey.challenge.$hex;
                } else if (typeof publicKey.challenge === 'string') {
                    challengeValue = base64UrlToHex(publicKey.challenge);
                }
                if (challengeValue) {
                    document.getElementById('challenge-auth').value = challengeValue;
                }
            }
            
            // Update timeout
            if (publicKey.timeout) {
                document.getElementById('timeout-auth').value = publicKey.timeout.toString();
            }
            
            // Update user verification
            if (Object.prototype.hasOwnProperty.call(publicKey, 'userVerification')) {
                document.getElementById('user-verification-auth').value = publicKey.userVerification || 'preferred';
            }
            
            // Update extensions
            if (publicKey.extensions) {
                if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
                    if (publicKey.extensions.prf.eval.first) {
                        let prfFirstValue = '';
                        if (publicKey.extensions.prf.eval.first.$base64) {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                        } else if (publicKey.extensions.prf.eval.first.$base64url) {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                        } else if (publicKey.extensions.prf.eval.first.$hex) {
                            prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                        } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                            prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                        }
                        if (prfFirstValue) {
                            document.getElementById('prf-eval-first-auth').value = prfFirstValue;
                        }
                    }
                    if (publicKey.extensions.prf.eval.second) {
                        let prfSecondValue = '';
                        if (publicKey.extensions.prf.eval.second.$base64) {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                        } else if (publicKey.extensions.prf.eval.second.$base64url) {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                        } else if (publicKey.extensions.prf.eval.second.$hex) {
                            prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                        } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                            prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                        }
                        if (prfSecondValue) {
                            document.getElementById('prf-eval-second-auth').value = prfSecondValue;
                        }
                    }
                }

                if (publicKey.extensions.largeBlob) {
                    if (publicKey.extensions.largeBlob.read) {
                        document.getElementById('large-blob-auth').value = 'read';
                    } else if (publicKey.extensions.largeBlob.write) {
                        document.getElementById('large-blob-auth').value = 'write';
                        let largeBlobValue = '';
                        if (publicKey.extensions.largeBlob.write.$base64) {
                            largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64);
                        } else if (publicKey.extensions.largeBlob.write.$base64url) {
                            largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64url);
                        } else if (publicKey.extensions.largeBlob.write.$hex) {
                            largeBlobValue = publicKey.extensions.largeBlob.write.$hex;
                        } else if (typeof publicKey.extensions.largeBlob.write === 'string') {
                            largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write);
                        }
                        if (largeBlobValue) {
                            document.getElementById('large-blob-write').value = largeBlobValue;
                        }
                    }
                }
            } else {
                const credPropsCheckbox = document.getElementById('cred-props');
                if (credPropsCheckbox) {
                    credPropsCheckbox.checked = false;
                }

                const minPinLengthCheckbox = document.getElementById('min-pin-length');
                if (minPinLengthCheckbox) {
                    minPinLengthCheckbox.checked = false;
                }

                const credProtectSelect = document.getElementById('cred-protect');
                const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
                if (credProtectSelect && enforceCredProtectCheckbox) {
                    credProtectSelect.value = '';
                    enforceCredProtectCheckbox.checked = true;
                    enforceCredProtectCheckbox.disabled = true;
                }
            }
        }

        // Convert current format value to the appropriate JSON format
        function currentFormatToJsonFormat(value) {
            if (!value) return '';
            const format = getCurrentBinaryFormat();
            
            switch (format) {
                case 'hex':
                    return {
                        "$hex": value
                    };
                case 'b64':
                    return {
                        "$base64": value
                    };
                case 'b64u':
                    return {
                        "$base64url": value
                    };
                case 'js':
                    return {
                        "$js": value
                    };
                default:
                    return {
                        "$base64url": currentFormatToBase64Url(value)
                    };
            }
        }

        // Convert current format value to base64url for JSON
        function currentFormatToBase64Url(value) {
            if (!value) return '';
            const format = getCurrentBinaryFormat();
            const hexValue = convertFormat(value, format, 'hex');
            return hexToBase64Url(hexValue);
        }

        // Get CredentialCreationOptions from form (WebAuthn standard format)
        function getCredentialCreationOptions() {
            const userId = document.getElementById('user-id')?.value || '';
            const userName = document.getElementById('user-name')?.value || '';
            const userDisplayName = document.getElementById('user-display-name')?.value || '';
            const challenge = document.getElementById('challenge-reg')?.value || '';
            
            // Build publicKey object
            const publicKey = {
                rp: {
                    name: "WebAuthn FIDO2 Test Application",
                    id: window.location.hostname
                },
                user: {
                    id: currentFormatToJsonFormat(userId),
                    name: userName,
                    displayName: userDisplayName
                },
                challenge: currentFormatToJsonFormat(challenge),
                pubKeyCredParams: [],
                timeout: parseInt(document.getElementById('timeout-reg')?.value) || 90000,
                authenticatorSelection: {},
                attestation: document.getElementById('attestation')?.value || 'none',
                extensions: {}
            };

            // Add selected algorithms
            if (document.getElementById('param-mldsa44')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -48}); // ML-DSA-44
            }
            if (document.getElementById('param-mldsa65')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -49}); // ML-DSA-65
            }
            if (document.getElementById('param-eddsa')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -8}); // EdDSA
            }
            if (document.getElementById('param-es256')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -7}); // ES256
            }
            if (document.getElementById('param-rs256')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -257}); // RS256
            }
            if (document.getElementById('param-es384')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -35}); // ES384
            }
            if (document.getElementById('param-es512')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -36}); // ES512
            }
            if (document.getElementById('param-rs384')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -258}); // RS384
            }
            if (document.getElementById('param-rs512')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -259}); // RS512
            }
            if (document.getElementById('param-rs1')?.checked) {
                publicKey.pubKeyCredParams.push({type: "public-key", alg: -65535}); // RS1
            }

            // Authenticator selection
            const authAttachment = document.getElementById('authenticator-attachment')?.value;
            if (authAttachment) publicKey.authenticatorSelection.authenticatorAttachment = authAttachment;

            const residentKeyValue = document.getElementById('resident-key')?.value || 'discouraged';
            publicKey.authenticatorSelection.residentKey = residentKeyValue;
            publicKey.authenticatorSelection.requireResidentKey = residentKeyValue === 'required';

            const userVerification = document.getElementById('user-verification-reg')?.value;
            if (userVerification) publicKey.authenticatorSelection.userVerification = userVerification;

            // Exclude credentials always present for consistency with JSON editor expectations
            const excludeList = [];
            if (document.getElementById('exclude-credentials')?.checked) {
                const currentBinaryFormat = getCurrentBinaryFormat();
                const userIdHex = (convertFormat(userId, currentBinaryFormat, 'hex') || '').toLowerCase();

                if (userIdHex && Array.isArray(storedCredentials) && storedCredentials.length > 0) {
                    storedCredentials.forEach(cred => {
                        const handleHex = getCredentialUserHandleHex(cred);
                        const credentialIdHex = getCredentialIdHex(cred);

                        if (handleHex && credentialIdHex && handleHex === userIdHex) {
                            excludeList.push({
                                type: "public-key",
                                id: {
                                    "$hex": credentialIdHex
                                }
                            });
                        }
                    });
                }
            }

            publicKey.excludeCredentials = excludeList;

            // Extensions
            if (document.getElementById('cred-props')?.checked) publicKey.extensions.credProps = true;
            if (document.getElementById('min-pin-length')?.checked) publicKey.extensions.minPinLength = true;

            const credentialProtection = document.getElementById('cred-protect')?.value;
            if (credentialProtection) {
                publicKey.extensions.credentialProtectionPolicy = credentialProtection;
                if (document.getElementById('enforce-cred-protect')?.checked) {
                    publicKey.extensions.enforceCredentialProtectionPolicy = true;
                }
            }
            
            const largeBlobReg = document.getElementById('large-blob-reg')?.value;
            if (largeBlobReg) publicKey.extensions.largeBlob = {support: largeBlobReg};
            
            if (document.getElementById('prf-reg')?.checked) {
                const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
                const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
                if (prfFirst) {
                    publicKey.extensions.prf = {
                        eval: {
                            first: currentFormatToJsonFormat(prfFirst)
                        }
                    };
                    if (prfSecond) {
                        publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
                    }
                }
            }

            // Add hints if any are selected
            const hints = [];
            if (document.getElementById('hint-client-device')?.checked) hints.push('client-device');
            if (document.getElementById('hint-hybrid')?.checked) hints.push('hybrid');
            if (document.getElementById('hint-security-key')?.checked) hints.push('security-key');
            if (hints.length > 0) publicKey.hints = hints;

            return { publicKey };
        }

        // Get CredentialRequestOptions from form (WebAuthn standard format)
        function getCredentialRequestOptions() {
            const challenge = document.getElementById('challenge-auth')?.value || '';
            
            // Build publicKey object  
            const publicKey = {
                challenge: currentFormatToJsonFormat(challenge),
                timeout: parseInt(document.getElementById('timeout-auth')?.value) || 90000,
                rpId: window.location.hostname,
                allowCredentials: [],
                userVerification: document.getElementById('user-verification-auth')?.value || 'preferred',
                extensions: {}
            };

            // Allow credentials handling
            const allowCreds = document.getElementById('allow-credentials')?.value;
            if (allowCreds === 'empty') {
                // Omit allowCredentials parameter entirely for resident key authentication
                // This enables discoverable credential authentication
                delete publicKey.allowCredentials;
            } else if (allowCreds === 'all') {
                // Include all stored credentials
                const allCredentials = (storedCredentials || [])
                    .map(cred => {
                        const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                        if (!credentialIdHex) {
                            return null;
                        }

                        const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                        const formattedId = currentFormatToJsonFormat(formatValue);
                        if (!formattedId || typeof formattedId !== 'object') {
                            return null;
                        }

                        return {
                            type: "public-key",
                            id: formattedId,
                        };
                    })
                    .filter(Boolean);
                publicKey.allowCredentials = allCredentials;
            } else {
                // Specific credential selected - find it by credential ID
                const selectedCred = (storedCredentials || []).find(
                    cred => (cred.credentialIdHex || getCredentialIdHex(cred)) === allowCreds
                );
                if (selectedCred) {
                    const credentialIdHex = selectedCred.credentialIdHex || getCredentialIdHex(selectedCred);
                    const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                    const formattedId = currentFormatToJsonFormat(formatValue);
                    if (formattedId && typeof formattedId === 'object') {
                        publicKey.allowCredentials = [{
                            type: "public-key",
                            id: formattedId,
                        }];
                    }
                } else {
                    // Fallback to all credentials if specific one not found
                    const fallbackCredentials = (storedCredentials || [])
                        .map(cred => {
                            const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                            if (!credentialIdHex) {
                                return null;
                            }

                            const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                            const formattedId = currentFormatToJsonFormat(formatValue);
                            if (!formattedId || typeof formattedId !== 'object') {
                                return null;
                            }

                            return {
                                type: "public-key",
                                id: formattedId,
                            };
                        })
                        .filter(Boolean);
                    publicKey.allowCredentials = fallbackCredentials;
                }
            }

            // Extensions
            const largeBlobAuth = document.getElementById('large-blob-auth')?.value;
            if (largeBlobAuth) {
                if (largeBlobAuth === 'read') {
                    publicKey.extensions.largeBlob = {read: true};
                } else if (largeBlobAuth === 'write') {
                    const largeBlobWrite = document.getElementById('large-blob-write')?.value;
                    if (largeBlobWrite) {
                        publicKey.extensions.largeBlob = {
                            write: currentFormatToJsonFormat(largeBlobWrite)
                        };
                    }
                }
            }
            
            const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
            const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
            if (prfFirst) {
                publicKey.extensions.prf = {
                    eval: {
                        first: currentFormatToJsonFormat(prfFirst)
                    }
                };
                if (prfSecond) {
                    publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
                }
            }

            // Add hints if any are selected
            const hints = [];
            if (document.getElementById('hint-client-device-auth')?.checked) hints.push('client-device');
            if (document.getElementById('hint-hybrid-auth')?.checked) hints.push('hybrid');  
            if (document.getElementById('hint-security-key-auth')?.checked) hints.push('security-key');
            if (hints.length > 0) publicKey.hints = hints;

            return { publicKey };
        }

        // Utility functions
        function showStatus(tabId, message, type) {
            const statusEl = document.getElementById(tabId + '-status');
            statusEl.className = 'status ' + type;
            statusEl.textContent = message;
            statusEl.style.display = 'block';
            
            // Auto-dismiss after 10 seconds
            setTimeout(() => {
                hideStatus(tabId);
            }, 10000);
        }

        function hideStatus(tabId) {
            document.getElementById(tabId + '-status').style.display = 'none';
        }

        function showProgress(tabId, message) {
            const progressEl = document.getElementById(tabId + '-progress');
            const textEl = document.getElementById(tabId + '-progress-text');
            textEl.textContent = message;
            progressEl.classList.add('show');
        }

        function hideProgress(tabId) {
            document.getElementById(tabId + '-progress').classList.remove('show');
        }

        // Simple authentication functions (standalone, no backend required)
        async function simpleRegister() {
            const email = document.getElementById('simple-email').value;
            if (!email) {
                showStatus('simple', 'Please enter a username.', 'error');
                return;
            }

            try {
                hideStatus('simple');
                showProgress('simple', 'Starting registration...');

                // Call server to begin registration
                const response = await fetch(`/api/register/begin?email=${encodeURIComponent(email)}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Server error: ${errorText}`);
                }

                const json = await response.json();
                const originalExtensions = json?.publicKey?.extensions;
                const createOptions = parseCreationOptionsFromJSON(json);

                const convertedExtensions = convertExtensionsForClient(originalExtensions);
                if (convertedExtensions) {
                    createOptions.publicKey = createOptions.publicKey || {};
                    createOptions.publicKey.extensions = {
                        ...(createOptions.publicKey.extensions || {}),
                        ...convertedExtensions
                    };
                }

                // Track fake credential length
                window.lastFakeCredLength = 0; // Simple auth doesn't use fake credentials

                showProgress('simple', 'Connecting your authenticator device...');

                const credential = await create(createOptions);
                
                showProgress('simple', 'Completing registration...');

                // Complete registration with server
                const result = await fetch(`/api/register/complete?email=${encodeURIComponent(email)}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(credential)
                });

                if (result.ok) {
                    const data = await result.json();
                    
                    // Print debug information from actual credential data
                    printRegistrationDebug(credential, createOptions, data);
                    
                    showStatus('simple', `Registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');
                    
                    // Reload credentials from server to get the latest
                    setTimeout(loadSavedCredentials, 1000);
                } else {
                    const errorText = await result.text();
                    throw new Error(`Registration failed: ${errorText}`);
                }

            } catch (error) {
                let errorMessage = error.message;
                if (error.name === 'NotAllowedError') {
                    errorMessage = 'User cancelled or authenticator not available';
                } else if (error.name === 'InvalidStateError') {
                    errorMessage = 'Authenticator is already registered for this account';
                } else if (error.name === 'SecurityError') {
                    errorMessage = 'Security error - check your connection and try again';
                } else if (error.name === 'NotSupportedError') {
                    errorMessage = 'WebAuthn is not supported in this browser';
                }

                showStatus('simple', errorMessage, 'error');
            } finally {
                hideProgress('simple');
            }
        }

        async function simpleAuthenticate() {
            const email = document.getElementById('simple-email').value;
            if (!email) {
                showStatus('simple', 'Please enter a username. ', 'error');
                return;
            }

            try {
                hideStatus('simple');
                showProgress('simple', 'Starting authentication...');

                // Call server to begin authentication
                const response = await fetch(`/api/authenticate/begin?email=${encodeURIComponent(email)}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                if (!response.ok) {
                    if (response.status === 404) {
                        throw new Error('No credentials found for this email. Please register first.');
                    }
                    const errorText = await response.text();
                    throw new Error(`Server error: ${errorText}`);
                }

                const json = await response.json();
                const getOptions = parseRequestOptionsFromJSON(json);

                // Track fake credential length
                window.lastFakeCredLength = 0; // Simple auth doesn't use fake credentials

                showProgress('simple', 'Connecting your authenticator device...');

                const assertion = await get(getOptions);
                
                showProgress('simple', 'Completing authentication...');

                // Complete authentication with server
                const result = await fetch(`/api/authenticate/complete?email=${encodeURIComponent(email)}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(assertion)
                });

                if (result.ok) {
                    const data = await result.json();
                    
                    // Print debug information from actual assertion data
                    printAuthenticationDebug(assertion, getOptions, data);
                    
                    showStatus('simple', 'Authentication successful! You have been verified.', 'success');
                } else {
                    const errorText = await result.text();
                    throw new Error(`Authentication failed: ${errorText}`);
                }

            } catch (error) {
                let errorMessage = error.message;
                if (error.name === 'NotAllowedError') {
                    errorMessage = 'User cancelled or authenticator not available';
                } else if (error.name === 'InvalidStateError') {
                    errorMessage = 'Authenticator error or invalid credential';
                } else if (error.name === 'SecurityError') {
                    errorMessage = 'Security error - check your connection and try again';
                } else if (error.name === 'NotSupportedError') {
                    errorMessage = 'WebAuthn is not supported in this browser';
                }

                showStatus('simple', errorMessage, 'error');
            } finally {
                hideProgress('simple');
            }
        }

        // Credentials management
        function addCredentialToList(credential) {
            const normalizedCredential = {
                ...credential,
                credentialIdHex: getCredentialIdHex(credential),
                userHandleHex: getCredentialUserHandleHex(credential),
            };
            storedCredentials.push(normalizedCredential);
            updateCredentialsList();
        }

        function updateCredentialsList() {
            const list = document.getElementById('credentials-list');
            
            if (storedCredentials.length === 0) {
                list.innerHTML = '<p style="color: #6c757d; font-style: normal">No credentials registered yet.</p>';
                return;
            }

            list.innerHTML = '';
            storedCredentials.forEach((cred, index) => {
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

        function generateCredentialDetails(cred) {
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

        function toggleCredentialDetails(index) {
            const credItems = document.querySelectorAll('.credential-item');
            const item = credItems[index];
            
            if (item.classList.contains('expanded')) {
                item.classList.remove('expanded');
            } else {
                // Close all others
                credItems.forEach(item => item.classList.remove('expanded'));
                // Open this one
                item.classList.add('expanded');
            }
        }





        // Event listeners and initialization
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize binary format system
            window.currentBinaryFormat = 'hex';
            updateFieldLabels('hex');
            
            // Initialize with default hex values as requested
            setTimeout(() => {
                // Generate default hex values for userid, challenge, and largeblob write
                document.getElementById('user-id').value = generateRandomHex(32);
                // Generate random username by default
                const randomUsername = generateRandom10DigitUsername();
                document.getElementById('user-name').value = randomUsername;
                document.getElementById('user-display-name').value = randomUsername;
                document.getElementById('challenge-reg').value = generateRandomHex(32);
                document.getElementById('challenge-auth').value = generateRandomHex(32);
                document.getElementById('large-blob-write').value = generateRandomHex(32);
                document.getElementById('prf-eval-first-reg').value = '';
                document.getElementById('prf-eval-second-reg').value = '';
                document.getElementById('prf-eval-first-auth').value = '';
                document.getElementById('prf-eval-second-auth').value = '';
                
                // Load saved credentials
                loadSavedCredentials();
                
                // Update JSON editor with initial values
                updateJsonEditor();
            }, 100);
            
            // Set up form field listeners for auto-sync
            setTimeout(() => {
                const allInputs = document.querySelectorAll('#advanced-tab input, #advanced-tab select, #advanced-tab input[type="checkbox"]');
                allInputs.forEach(input => {
                    input.addEventListener('input', updateJsonEditor);
                    input.addEventListener('change', updateJsonEditor);
                });

                // Set up display name sync with username
                const usernameInput = document.getElementById('user-name');
                const displayNameInput = document.getElementById('user-display-name');
                if (usernameInput && displayNameInput) {
                    usernameInput.addEventListener('input', () => {
                        displayNameInput.value = usernameInput.value;
                        updateJsonEditor();
                    });
                }

                // Set up large blob select listener
                const largeBlobSelect = document.getElementById('large-blob-auth');
                if (largeBlobSelect) {
                    largeBlobSelect.addEventListener('change', () => {
                        checkLargeBlobCapability(); // Re-check to enable/disable write input
                        updateJsonEditor();
                    });
                }

                const credProtectSelect = document.getElementById('cred-protect');
                const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
                if (credProtectSelect && enforceCredProtectCheckbox) {
                    const handleCredProtectToggle = () => {
                        if (credProtectSelect.value) {
                            enforceCredProtectCheckbox.disabled = false;
                        } else {
                            enforceCredProtectCheckbox.checked = true;
                            enforceCredProtectCheckbox.disabled = true;
                        }
                    };
                    credProtectSelect.addEventListener('change', handleCredProtectToggle);
                    handleCredProtectToggle();
                }

                // Set up allow credentials dropdown listener
                const allowCredentialsSelect = document.getElementById('allow-credentials');
                if (allowCredentialsSelect) {
                    allowCredentialsSelect.addEventListener('change', () => {
                        updateJsonEditor();
                    });
                }

                // Set up resident key dependency for largeBlob
                const residentKeySelect = document.getElementById('resident-key');
                const largeBlobRegSelect = document.getElementById('large-blob-reg');
                if (residentKeySelect && largeBlobRegSelect) {
                    residentKeySelect.addEventListener('change', () => {
                        const residentKey = residentKeySelect.value;
                        if (residentKey !== 'required') {
                            // If resident key is not required, disable largeBlob preferred/required options
                            const largeBlobValue = largeBlobRegSelect.value;
                            if (largeBlobValue === 'preferred' || largeBlobValue === 'required') {
                                largeBlobRegSelect.value = ''; // Reset to unspecified
                            }
                        }
                        updateJsonEditor();
                    });
                }

                // Set up modal close on outside click
                const modals = document.querySelectorAll('.modal');
                modals.forEach(modal => {
                    modal.addEventListener('click', (e) => {
                        if (e.target === modal) {
                            closeModal(modal.id);
                        }
                    });
                });
                
                // Set up specific PRF validation listeners
                const prfFirstInputs = ['prf-eval-first-reg', 'prf-eval-first-auth'];
                prfFirstInputs.forEach(inputId => {
                    const input = document.getElementById(inputId);
                    if (input) {
                        input.addEventListener('input', () => {
                            const formType = inputId.includes('reg') ? 'reg' : 'auth';
                            validatePrfInputs(formType);
                            validatePrfEvalInputs();
                        });
                        input.addEventListener('change', () => {
                            const formType = inputId.includes('reg') ? 'reg' : 'auth';
                            validatePrfInputs(formType);
                            validatePrfEvalInputs();
                        });
                    }
                });

                // Set up validation listeners for hex inputs
                const hexInputs = [
                    'user-id', 'challenge-reg', 'challenge-auth',
                    'prf-eval-first-reg', 'prf-eval-second-reg',
                    'prf-eval-first-auth', 'prf-eval-second-auth',
                    'large-blob-write'
                ];
                hexInputs.forEach(inputId => {
                    const input = document.getElementById(inputId);
                    if (input) {
                        input.addEventListener('input', () => {
                            if (inputId === 'user-id') validateUserIdInput();
                            else if (inputId.includes('challenge')) validateChallengeInputs();
                            else if (inputId.includes('prf-eval')) validatePrfEvalInputs();
                            else if (inputId === 'large-blob-write') validateLargeBlobWriteInput();
                        });
                        input.addEventListener('blur', () => {
                            if (inputId === 'user-id') validateUserIdInput();
                            else if (inputId.includes('challenge')) validateChallengeInputs();
                            else if (inputId.includes('prf-eval')) validatePrfEvalInputs();
                            else if (inputId === 'large-blob-write') validateLargeBlobWriteInput();
                        });
                    }
                });

                const jsonEditorExpandButton = document.getElementById('json-editor-expand');
                if (jsonEditorExpandButton) {
                    jsonEditorExpandButton.addEventListener('click', () => toggleJsonEditorExpansion());
                }

                const jsonEditorOverlay = document.getElementById('json-editor-overlay');
                if (jsonEditorOverlay) {
                    jsonEditorOverlay.addEventListener('click', () => toggleJsonEditorExpansion(true));
                }

                const jsonEditorElement = document.getElementById('json-editor');
                if (jsonEditorElement) {
                    jsonEditorElement.addEventListener('keydown', handleJsonEditorKeydown);
                }

                document.addEventListener('keydown', (event) => {
                    if (event.key === 'Escape') {
                        const container = document.getElementById('json-editor-container');
                        if (container?.classList.contains('expanded')) {
                            toggleJsonEditorExpansion(true);
                        }
                    }
                });
            }, 100);

            // Initialize JSON editor
            setTimeout(updateJsonEditor, 200);
            
            // Load saved credentials
            setTimeout(loadSavedCredentials, 300);
            
            // Ensure decoder tab functionality is properly initialized
            setTimeout(() => {
                // Test decoder elements initialization
                const decoderTab = document.getElementById('decoder-tab');
                const decoderInput = document.getElementById('decoder-input');
                const decoderOutput = document.getElementById('decoder-output');
            }, 500);
        });

        // Make functions globally available
        window.switchTab = switchTab;
        window.updateGlobalScrollLock = updateGlobalScrollLock;
        window.switchSubTab = switchSubTab;
        window.toggleSection = toggleSection;
        window.showInfoPopup = showInfoPopup;
        window.hideInfoPopup = hideInfoPopup;
        window.toggleLanguage = toggleLanguage;
        window.randomizeUserId = randomizeUserId;
        window.randomizeChallenge = randomizeChallenge;
        window.randomizePrfEval = randomizePrfEval;
        window.randomizeLargeBlobWrite = randomizeLargeBlobWrite;
        window.resetRegistrationForm = resetRegistrationForm;
        window.resetAuthenticationForm = resetAuthenticationForm;
        window.randomizeUsername = randomizeUsername;
        window.simpleRegister = simpleRegister;
        window.simpleAuthenticate = simpleAuthenticate;
        window.advancedRegister = advancedRegister;
        window.advancedAuthenticate = advancedAuthenticate;
        window.decodeResponse = decodeResponse;
        window.clearDecoder = clearDecoder;
        window.changeBinaryFormat = changeBinaryFormat;
        window.saveJsonEditor = saveJsonEditor;
        window.resetJsonEditor = resetJsonEditor;
        window.showCredentialDetails = showCredentialDetails;
        window.navigateToMdsAuthenticator = navigateToMdsAuthenticator;
        window.closeCredentialModal = closeCredentialModal;
        window.closeRegistrationResultModal = closeRegistrationResultModal;
        window.deleteCredential = deleteCredential;



        // Simple Authentication Functions

        // Generate a random 10-digit username with letters and numbers
        function generateRandom10DigitUsername() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let result = '';
            for (let i = 0; i < 10; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        }

        function randomizeUsername() {
            const randomUsername = generateRandom10DigitUsername();
            document.getElementById('user-name').value = randomUsername;
            // Auto-update display name
            document.getElementById('user-display-name').value = randomUsername;
            updateJsonEditor();
        }
// Advanced Authentication Functions
        function getAdvancedCreateOptions() {
            // Get current format for conversion
            const currentFormat = getCurrentBinaryFormat();
            
            // Collect basic user information
            const options = {
                username: document.getElementById('user-name').value,
                displayName: document.getElementById('user-display-name').value || document.getElementById('user-name').value,
                userId: convertFormat(document.getElementById('user-id').value, currentFormat, 'hex'),
                
                // Authenticator selection
                attestation: document.getElementById('attestation').value,
                userVerification: document.getElementById('user-verification-reg').value,
                authenticatorAttachment: document.getElementById('authenticator-attachment').value || undefined,
                residentKey: document.getElementById('resident-key').value,
                
                // Credential management
                excludeCredentials: document.getElementById('exclude-credentials').checked,
                fakeCredLength: parseInt(document.getElementById('fake-cred-length-reg').value) || 0,
                
                // Other options
                challenge: convertFormat(document.getElementById('challenge-reg').value, currentFormat, 'hex'),
                timeout: parseInt(document.getElementById('timeout-reg').value) || 90000,
                
                // Public key credential parameters
                pubKeyCredParams: [],
                
                // Hints
                hints: [],
                
                // Extensions
                extensions: {}
            };
            
            // Collect selected algorithms
            if (document.getElementById('param-mldsa44')?.checked) options.pubKeyCredParams.push('ML-DSA-44');
            if (document.getElementById('param-mldsa65')?.checked) options.pubKeyCredParams.push('ML-DSA-65');
            if (document.getElementById('param-eddsa')?.checked) options.pubKeyCredParams.push('EdDSA');
            if (document.getElementById('param-es256')?.checked) options.pubKeyCredParams.push('ES256');
            if (document.getElementById('param-rs256')?.checked) options.pubKeyCredParams.push('RS256');
            if (document.getElementById('param-es384')?.checked) options.pubKeyCredParams.push('ES384');
            if (document.getElementById('param-es512')?.checked) options.pubKeyCredParams.push('ES512');
            if (document.getElementById('param-rs384')?.checked) options.pubKeyCredParams.push('RS384');
            if (document.getElementById('param-rs512')?.checked) options.pubKeyCredParams.push('RS512');
            if (document.getElementById('param-rs1')?.checked) options.pubKeyCredParams.push('RS1');
            
            // Collect hints
            if (document.getElementById('hint-client-device')?.checked) options.hints.push('client-device');
            if (document.getElementById('hint-hybrid')?.checked) options.hints.push('hybrid');
            if (document.getElementById('hint-security-key')?.checked) options.hints.push('security-key');
            
            // Collect extensions
            if (document.getElementById('cred-props')?.checked) {
                options.extensions.credProps = true;
            }
            
            if (document.getElementById('min-pin-length')?.checked) {
                options.extensions.minPinLength = true;
            }

            const credProtect = document.getElementById('cred-protect')?.value;
            if (credProtect && credProtect !== '') {
                options.extensions.credentialProtectionPolicy = credProtect;
                if (document.getElementById('enforce-cred-protect')?.checked) {
                    options.extensions.enforceCredentialProtectionPolicy = true;
                }
            }
            
            const largeBlob = document.getElementById('large-blob-reg')?.value;
            if (largeBlob && largeBlob !== '') {
                options.extensions.largeBlob = { support: largeBlob };
            }

            if (document.getElementById('prf-reg')?.checked) {
                const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
                const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
                if (prfFirst) {
                    options.extensions.prf = {
                        eval: {
                            first: currentFormatToJsonFormat(prfFirst)
                        }
                    };
                    if (prfSecond) {
                        options.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
                    }
                }
            }
            
            return options;
        }

        function getAdvancedAssertOptions() {
            const allowCreds = document.getElementById('allow-credentials').value;
            const currentFormat = getCurrentBinaryFormat();
            
            const options = {
                userVerification: document.getElementById('user-verification-auth').value,
                allowCredentials: allowCreds,
                fakeCredLength: parseInt(document.getElementById('fake-cred-length-auth').value) || 0,
                challenge: convertFormat(document.getElementById('challenge-auth').value, currentFormat, 'hex'),
                timeout: parseInt(document.getElementById('timeout-auth').value) || 90000,
                extensions: {}
            };
            
            // Handle specific credential selection
            if (allowCreds !== 'all' && allowCreds !== 'empty') {
                // This is a specific credential ID
                options.specificCredentialId = allowCreds;
            }
            
            // Collect extensions for authentication
            const largeBlob = document.getElementById('large-blob-auth')?.value;
            if (largeBlob === 'read') {
                options.extensions.largeBlob = { read: true };
            } else if (largeBlob === 'write') {
                const largeBlobWrite = document.getElementById('large-blob-write')?.value;
                if (largeBlobWrite) {
                    options.extensions.largeBlob = {
                        write: currentFormatToJsonFormat(largeBlobWrite)
                    };
                }
            }

            // Check if we have prf inputs for authentication
            const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
            const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
            if (prfFirst || prfSecond) {
                const prfEval = {};
                if (prfFirst) {
                    prfEval.first = currentFormatToJsonFormat(prfFirst);
                }
                if (prfSecond) {
                    prfEval.second = currentFormatToJsonFormat(prfSecond);
                }
                if (Object.keys(prfEval).length > 0) {
                    options.extensions.prf = { eval: prfEval };
                }
            }
            
            return options;
        }

        // Helper function to extract binary values from various formats (for backward compatibility)
        function extractBinaryValue(value) {
            if (!value) return '';
            
            if (typeof value === 'string') {
                return value;
            }
            
            if (typeof value === 'object') {
                if (value.$hex) return value.$hex;
                if (value.$base64) return base64ToHex(value.$base64);
                if (value.$base64url) return base64UrlToHex(value.$base64url);
                if (value.$js) return value.$js;
            }
            
            return '';
        }

        async function advancedRegister() {
            try {
                // Parse JSON from editor as primary source of truth
                const jsonText = document.getElementById('json-editor').value;
                const parsed = JSON.parse(jsonText);
                
                // Validate JSON structure for CredentialCreationOptions
                if (!parsed.publicKey) {
                    throw new Error('Invalid JSON structure: Missing "publicKey" property');
                }
                
                const publicKey = parsed.publicKey;
                
                // Validate required CredentialCreationOptions properties
                if (!publicKey.rp) {
                    throw new Error('Invalid CredentialCreationOptions: Missing required "rp" property');
                }
                if (!publicKey.user) {
                    throw new Error('Invalid CredentialCreationOptions: Missing required "user" property');
                }
                if (!publicKey.challenge) {
                    throw new Error('Invalid CredentialCreationOptions: Missing required "challenge" property');
                }
                
                // Send the complete parsed JSON directly to backend - NO TRANSFORMATION
                // This preserves all custom extensions and enables full extensibility
                hideStatus('advanced');
                showProgress('advanced', 'Starting advanced registration...');

                const response = await fetch('/api/advanced/register/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(parsed)  // Send complete JSON as-is
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Server error: ${errorText}`);
                }

                const json = await response.json();
                const originalExtensions = json?.publicKey?.extensions;
                const createOptions = parseCreationOptionsFromJSON(json);

                const convertedExtensions = convertExtensionsForClient(originalExtensions);
                if (convertedExtensions) {
                    createOptions.publicKey = createOptions.publicKey || {};
                    createOptions.publicKey.extensions = {
                        ...(createOptions.publicKey.extensions || {}),
                        ...convertedExtensions
                    };
                }

                // Track fake credential length from form (for debugging info only)
                window.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-reg').value) || 0;
                
                showProgress('advanced', 'Connecting your authenticator device...');

                const credential = await create(createOptions);

                const credentialJson = credential.toJSON ? credential.toJSON() : JSON.parse(JSON.stringify(credential));
                const extensionResults = credential.getClientExtensionResults
                    ? credential.getClientExtensionResults()
                    : (credential.clientExtensionResults || {});
                const normalizedExtensionResults = normalizeClientExtensionResults(extensionResults);
                const existingExtensionResults = credentialJson.clientExtensionResults || {};
                if (normalizedExtensionResults && typeof normalizedExtensionResults === 'object' &&
                    Object.keys(normalizedExtensionResults).length > 0) {
                    credentialJson.clientExtensionResults = {
                        ...existingExtensionResults,
                        ...normalizedExtensionResults,
                    };
                } else if (credentialJson.clientExtensionResults === undefined) {
                    credentialJson.clientExtensionResults = existingExtensionResults;
                }

                showProgress('advanced', 'Completing registration...');

                // Send the complete JSON editor content as primary source of truth
                // The entire JSON editor content is spread as the main request object
                // Only the credential response is added as a special field
                const result = await fetch('/api/advanced/register/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        ...parsed,  // Spread the complete JSON editor content as primary data
                        __credential_response: credentialJson  // Add credential response with special key
                    }),
                });

                if (result.ok) {
                    const data = await result.json();
                    
                    // Print debug information from actual credential data
                    printRegistrationDebug(credential, createOptions, data);

                    showStatus('advanced', `Advanced registration successful! Algorithm: ${data.algo || 'Unknown'}`, 'success');

                    showRegistrationResultModal(credentialJson, data.relyingParty || null);

                    // Reload credentials from server to get the latest
                    setTimeout(loadSavedCredentials, 1000);
                } else {
                    const errorText = await result.text();
                    throw new Error(`Registration failed: ${errorText}`);
                }
            } catch (error) {
                let errorMessage = error.message;
                if (error.name === 'NotAllowedError') {
                    errorMessage = 'User cancelled or authenticator not available';
                } else if (error.name === 'InvalidStateError') {
                    errorMessage = 'Authenticator is already registered for this account';
                } else if (error.name === 'SecurityError') {
                    errorMessage = 'Security error - check your connection and try again';
                }
                
                showStatus('advanced', `Credential registration failed: ${errorMessage}`, 'error');
            } finally {
                hideProgress('advanced');
            }
        }

        async function advancedAuthenticate() {
            try {
                // Parse JSON from editor as primary source of truth
                const jsonText = document.getElementById('json-editor').value;
                const parsed = JSON.parse(jsonText);
                
                // Validate JSON structure for CredentialRequestOptions
                if (!parsed.publicKey) {
                    throw new Error('Invalid JSON structure: Missing "publicKey" property');
                }
                
                const publicKey = parsed.publicKey;
                
                // Validate required CredentialRequestOptions properties
                if (!publicKey.challenge) {
                    throw new Error('Invalid CredentialRequestOptions: Missing required "challenge" property');
                }
                
                // Send the complete parsed JSON directly to backend - NO TRANSFORMATION
                // This preserves all custom extensions and enables full extensibility
                hideStatus('advanced');
                showProgress('advanced', 'Detecting credentials...');

                const response = await fetch('/api/advanced/authenticate/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(parsed)  // Send complete JSON as-is
                });

                if (!response.ok) {
                    if (response.status === 404) {
                        throw new Error('No credentials detected. Please register a credential first.');
                    }
                    const errorText = await response.text();
                    throw new Error(`Server error: ${errorText}`);
                }

                const json = await response.json();
                const originalExtensions = json?.publicKey?.extensions;
                const assertOptions = parseRequestOptionsFromJSON(json);

                const convertedExtensions = convertExtensionsForClient(originalExtensions);
                if (convertedExtensions) {
                    assertOptions.publicKey = assertOptions.publicKey || {};
                    assertOptions.publicKey.extensions = {
                        ...(assertOptions.publicKey.extensions || {}),
                        ...convertedExtensions
                    };
                }
                
                // Track fake credential length from form (for debugging info only)
                window.lastFakeCredLength = parseInt(document.getElementById('fake-cred-length-auth').value) || 0;
                
                showProgress('advanced', 'Connecting your authenticator device...');

                const assertion = await get(assertOptions);

                const assertionJson = assertion.toJSON ? assertion.toJSON() : JSON.parse(JSON.stringify(assertion));
                const assertionExtensionResults = assertion.getClientExtensionResults
                    ? assertion.getClientExtensionResults()
                    : (assertion.clientExtensionResults || {});
                const normalizedAssertionExtensions = normalizeClientExtensionResults(assertionExtensionResults);
                const existingAssertionExtensions = assertionJson.clientExtensionResults || {};
                if (normalizedAssertionExtensions && typeof normalizedAssertionExtensions === 'object' &&
                    Object.keys(normalizedAssertionExtensions).length > 0) {
                    assertionJson.clientExtensionResults = {
                        ...existingAssertionExtensions,
                        ...normalizedAssertionExtensions,
                    };
                } else if (assertionJson.clientExtensionResults === undefined) {
                    assertionJson.clientExtensionResults = existingAssertionExtensions;
                }

                showProgress('advanced', 'Completing authentication...');

                // Send the complete JSON editor content as primary source of truth
                // The entire JSON editor content is spread as the main request object
                // Only the assertion response is added as a special field
                const result = await fetch('/api/advanced/authenticate/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        ...parsed,  // Spread the complete JSON editor content as primary data
                        __assertion_response: assertionJson  // Add assertion response with special key
                    }),
                });

                if (result.ok) {
                    const data = await result.json();
                    
                    // Print debug information from actual assertion data
                    printAuthenticationDebug(assertion, assertOptions, data);
                    
                    showStatus('advanced', 'Advanced authentication successful!', 'success');
                } else {
                    const errorText = await result.text();
                    throw new Error(`Authentication failed: ${errorText}`);
                }
            } catch (error) {
                let errorMessage = error.message;
                if (error.name === 'NotAllowedError') {
                    errorMessage = 'User cancelled or no compatible authenticator detected';
                } else if (error.name === 'InvalidStateError') {
                    errorMessage = 'Invalid authenticator state - please try again';
                } else if (error.name === 'SecurityError') {
                    errorMessage = 'Security error - check your connection and try again';
                }
                
                showStatus('advanced', `Advanced authentication failed: ${errorMessage}`, 'error');
            } finally {
                hideProgress('advanced');
            }
        }
// JSON Editor Functions
        function editCreateOptions() {
            const options = getAdvancedCreateOptions();
            currentJsonMode = 'create';
            currentJsonData = options;
            
            const sortedOptions = sortObjectKeys(options);
            document.getElementById('json-editor').value = JSON.stringify(sortedOptions, null, 2);
            document.getElementById('apply-json').style.display = 'inline-block';
            document.getElementById('cancel-json').style.display = 'inline-block';
        }

        function editAssertOptions() {
            const options = getAdvancedAssertOptions();
            currentJsonMode = 'assert';
            currentJsonData = options;

            const sortedOptions = sortObjectKeys(options);
            document.getElementById('json-editor').value = JSON.stringify(sortedOptions, null, 2);
            document.getElementById('apply-json').style.display = 'inline-block';
            document.getElementById('cancel-json').style.display = 'inline-block';
        }

        function applyJsonChanges() {
            try {
                const jsonText = document.getElementById('json-editor').value;
                const parsed = JSON.parse(jsonText);
                
                if (currentJsonMode === 'create') {
                    // Update create form fields
                    if (parsed.username) document.getElementById('user-name').value = parsed.username;
                    if (parsed.displayName) document.getElementById('user-display-name').value = parsed.displayName;
                    if (Object.prototype.hasOwnProperty.call(parsed, 'attestation')) {
                        document.getElementById('attestation').value = parsed.attestation || 'none';
                    }
                    if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                        document.getElementById('user-verification-reg').value = parsed.userVerification || 'preferred';
                    }
                    if (parsed.authenticatorAttachment !== undefined) document.getElementById('authenticator-attachment').value = parsed.authenticatorAttachment || '';
                    if (parsed.residentKey) document.getElementById('resident-key').value = parsed.residentKey;
                } else if (currentJsonMode === 'assert') {
                    // Update assert form fields
                    if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                        document.getElementById('user-verification-auth').value = parsed.userVerification || 'preferred';
                    }
                }
                
                showStatus('advanced', 'JSON changes applied successfully!', 'success');
                cancelJsonEdit();
            } catch (error) {
                showStatus('advanced', `Invalid JSON: ${error.message}`, 'error');
            }
        }

        function cancelJsonEdit() {
            document.getElementById('json-editor').value = '';
            document.getElementById('apply-json').style.display = 'none';
            document.getElementById('cancel-json').style.display = 'none';
            currentJsonMode = null;
            currentJsonData = {};
        }

        // Decoder Functions
        function decodeResponse() {
            const input = document.getElementById('decoder-input');
            if (!input) {
                return;
            }
            
            const inputValue = input.value;
            if (!inputValue.trim()) {
                showStatus('decoder', 'Decoder is empty. Please paste something to decode. ', 'error');
                return;
            }

            try {
                const parsed = JSON.parse(inputValue);
                const decoded = analyzeWebAuthnResponse(parsed);
                
                const decodedContent = document.getElementById('decoded-content');
                const decoderOutput = document.getElementById('decoder-output');
                
                if (decodedContent && decoderOutput) {
                    decodedContent.innerHTML = `<pre>${JSON.stringify(decoded, null, 2)}</pre>`;
                    decoderOutput.style.display = 'block';
                    showStatus('decoder', 'Response decoded successfully!', 'success');
                }
            } catch (error) {
                showStatus('decoder', `Decoding failed: ${error.message}`, 'error');
            }
        }

        function clearDecoder() {
            const input = document.getElementById('decoder-input');
            const output = document.getElementById('decoder-output');
            
            if (input) {
                input.value = '';
            }
            if (output) {
                output.style.display = 'none';
            }
            hideStatus('decoder');
        }

        function analyzeWebAuthnResponse(response) {
            const analysis = {
                type: 'Unknown',
                rawResponse: response,
                decodedFields: {}
            };

            // Detect if it's a registration or authentication response
            if (response.response && response.response.attestationObject) {
                analysis.type = 'Registration Response';
                analysis.decodedFields = {
                    credentialId: response.id,
                    credentialType: response.type,
                    authenticatorAttachment: response.authenticatorAttachment,
                    clientDataJSON: tryDecodeBase64Url(response.response.clientDataJSON),
                    attestationObject: 'Base64URL encoded - contains authenticator data and attestation statement'
                };
            } else if (response.response && response.response.authenticatorData) {
                analysis.type = 'Authentication Response';
                analysis.decodedFields = {
                    credentialId: response.id,
                    credentialType: response.type,
                    authenticatorAttachment: response.authenticatorAttachment,
                    clientDataJSON: tryDecodeBase64Url(response.response.clientDataJSON),
                    authenticatorData: 'Base64URL encoded - contains RP ID hash, flags, counter, etc.',
                    signature: 'Base64URL encoded signature'
                };
            }

            return analysis;
        }

        function tryDecodeBase64Url(encoded) {
            try {
                const decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
                return JSON.parse(decoded);
            } catch (error) {
                return 'Could not decode as JSON: ' + encoded;
            }
        }

        // Update JSON editor when form fields change
        document.addEventListener('DOMContentLoaded', function() {
            const formFields = [
                'user-name', 'user-display-name', 'attestation',
                'user-verification-reg', 'authenticator-attachment', 'resident-key',
                'user-verification-auth'
            ];

            formFields.forEach(fieldId => {
                const field = document.getElementById(fieldId);
                if (field) {
                    field.addEventListener('input', updateJsonFromForm);
                    field.addEventListener('change', updateJsonFromForm);
                }
            });
        });

        function updateJsonFromForm() {
            if (currentJsonMode) {
                if (currentJsonMode === 'create') {
                    const options = getAdvancedCreateOptions();
                    const sortedOptions = sortObjectKeys(options);
                    document.getElementById('json-editor').value = JSON.stringify(sortedOptions, null, 2);
                } else if (currentJsonMode === 'assert') {
                    const options = getAdvancedAssertOptions();
                    const sortedOptions = sortObjectKeys(options);
                    document.getElementById('json-editor').value = JSON.stringify(sortedOptions, null, 2);
                }
            }
        }
