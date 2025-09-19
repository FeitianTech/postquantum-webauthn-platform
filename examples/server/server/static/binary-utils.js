import { state } from './state.js';

export function isValidHex(str) {
    return /^[0-9a-fA-F]*$/.test(str) && str.length > 0;
}

export function generateRandomHex(bytes) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBase64Url(hexString) {
    if (!hexString) return '';

    if (hexString.length % 2 !== 0) {
        hexString = '0' + hexString;
    }

    const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64UrlToHex(base64url) {
    if (!base64url) return '';

    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }

    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function base64ToBase64Url(base64) {
    if (!base64) return '';
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function hexToBase64(hexString) {
    if (!hexString) return '';
    const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    return btoa(String.fromCharCode(...bytes));
}

export function hexToGuid(hexString) {
    if (!hexString || hexString.length !== 32) return '';
    return [
        hexString.substring(0, 8),
        hexString.substring(8, 12),
        hexString.substring(12, 16),
        hexString.substring(16, 20),
        hexString.substring(20, 32)
    ].join('-');
}

export function bytesToHex(bytes) {
    if (!bytes) {
        return '';
    }
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToJs(hexString) {
    if (!hexString) return '';
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return `new Uint8Array([${bytes.join(', ')}])`;
}

export function base64ToHex(base64) {
    if (!base64) return '';
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function base64UrlToHexFixed(base64url) {
    if (!base64url) return '';
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64ToHex(base64);
}

export function jsToHex(jsString) {
    if (!jsString) return '';
    const match = jsString.match(/new Uint8Array\(\[([0-9, ]+)\]\)/);
    if (!match) return '';
    const numbers = match[1].split(',').map(n => parseInt(n.trim()));
    return numbers.map(n => n.toString(16).padStart(2, '0')).join('');
}

export function convertFormat(value, fromFormat, toFormat) {
    if (!value || fromFormat === toFormat) return value;

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

export function hexToUint8Array(hex) {
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

export function base64ToUint8Array(base64) {
    if (!base64) return null;
    const normalized = base64.replace(/\s+/g, '');
    const binaryString = atob(normalized);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

export function base64UrlToUint8Array(base64url) {
    if (!base64url) return null;
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64ToUint8Array(base64);
}

export function base64UrlToUtf8String(base64url) {
    if (!base64url) return null;
    if (!state.utf8Decoder) return null;
    const bytes = base64UrlToUint8Array(base64url);
    if (!bytes) return null;
    try {
        return state.utf8Decoder.decode(bytes);
    } catch (error) {
        return null;
    }
}

export function base64UrlToJson(base64url) {
    try {
        const decoded = base64UrlToUtf8String(base64url);
        if (!decoded) return null;
        return JSON.parse(decoded);
    } catch (error) {
        return null;
    }
}

export function bufferSourceToUint8Array(value) {
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }

    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    return null;
}

export function arrayBufferToHex(buffer) {
    if (!buffer) {
        return '';
    }

    const view = bufferSourceToUint8Array(buffer);
    if (!view) {
        return '';
    }

    return Array.from(view).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function normalizeClientExtensionResults(results) {
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

export function jsonValueToUint8Array(jsonValue) {
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

export function jsonValueToArrayBuffer(jsonValue) {
    const bytes = jsonValueToUint8Array(jsonValue);
    return bytes ? bytes.buffer : null;
}

export function convertCredProtectValue(value) {
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

export function convertLargeBlobExtension(extValue) {
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
        const supportValue = jsonValueToUint8Array(extValue.support);
        if (!supportValue && typeof extValue.support.$js === 'string') {
            converted.support = extValue.support.$js;
        }
    }

    return converted;
}

export function convertPrfExtension(extValue) {
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

    Object.entries(extValue).forEach(([key, value]) => {
        if (!(key in converted)) {
            converted[key] = value;
        }
    });

    return converted;
}

export function convertExtensionsForClient(extensionsJson) {
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

export function sortObjectKeys(value) {
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

export function getCurrentBinaryFormat() {
    const element = document.getElementById('binary-format');
    return element ? element.value : 'hex';
}

export function currentFormatToJsonFormat(value) {
    if (!value) return '';
    const format = getCurrentBinaryFormat();

    switch (format) {
        case 'hex':
            return {
                '$hex': value
            };
        case 'b64':
            return {
                '$base64': value
            };
        case 'b64u':
            return {
                '$base64url': value
            };
        case 'js':
            return {
                '$js': value
            };
        default:
            return {
                '$base64url': currentFormatToBase64Url(value)
            };
    }
}

export function currentFormatToBase64Url(value) {
    if (!value) return '';
    const format = getCurrentBinaryFormat();
    const hexValue = convertFormat(value, format, 'hex');
    return hexToBase64Url(hexValue);
}

export function normalizeToHex(value) {
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
