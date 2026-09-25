import { base64UrlToBytes } from '../../../shared/utils/base64.js';

export function createSummaryItem(label, value, options = {}) {
    if (!label) {
        return null;
    }

    const resolved = Array.isArray(value) ? value.filter(Boolean) : value;
    const isArray = Array.isArray(resolved);
    const scalar = !isArray ? resolved : null;
    const text = typeof scalar === 'string' ? scalar.trim() : scalar;

    if ((!isArray && (text === undefined || text === null || text === '')) || (isArray && !resolved.length)) {
        return null;
    }

    const item = document.createElement('li');
    item.className = 'mds-certificate-summary__item';

    const labelEl = document.createElement('div');
    labelEl.className = 'mds-certificate-summary__label';
    if (typeof options.variant === 'string') {
        const variant = options.variant.toLowerCase();
        if (variant === 'primary') {
            labelEl.classList.add('mds-certificate-summary__label--primary');
        }
    }
    labelEl.textContent = label;
    item.appendChild(labelEl);

    const valueEl = document.createElement('div');
    valueEl.className = 'mds-certificate-summary__value';

    if (options.code) {
        const codeEl = document.createElement('code');
        codeEl.className = 'mds-certificate-summary__code';
        codeEl.textContent = String(value);
        valueEl.appendChild(codeEl);
    } else if (isArray) {
        resolved.forEach(entry => {
            const line = document.createElement('div');
            line.textContent = String(entry);
            valueEl.appendChild(line);
        });
    } else {
        valueEl.textContent = String(text);
    }

    item.appendChild(valueEl);
    return item;
}

export function determinePublicKeyAlgorithm(info) {
    if (!info || typeof info !== 'object') {
        return '';
    }
    const algorithm = info.algorithm;
    if (algorithm) {
        if (typeof algorithm === 'string') {
            const algorithmName = algorithm.trim();
            if (algorithmName) {
                return algorithmName;
            }
        }
        if (typeof algorithm === 'object') {
            const name = typeof algorithm.name === 'string' ? algorithm.name.trim() : '';
            if (name) {
                return name;
            }
        }
    }
    const type = typeof info.type === 'string' ? info.type.trim() : '';
    return type;
}

// Base64url text as UTF-8, decoded strictly: one spelling per byte string.
export function decodeBase64Url(value) {
    return new TextDecoder().decode(base64UrlToBytes(value));
}
