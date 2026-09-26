import { base64UrlToBytes } from '../../../shared/utils/base64.js';
import { certificateSummaryItem } from '../explorer/certificate.js';

export { determinePublicKeyAlgorithm } from '../explorer/certificate.js';

// One summary line's DOM, from explorer/certificate.js's item.
export function renderSummaryItem(item) {
    const element = document.createElement('li');
    element.className = 'mds-certificate-summary__item';

    const labelEl = document.createElement('div');
    labelEl.className = 'mds-certificate-summary__label';
    if (item.primary) {
        labelEl.classList.add('mds-certificate-summary__label--primary');
    }
    labelEl.textContent = item.label;
    element.appendChild(labelEl);

    const valueEl = document.createElement('div');
    valueEl.className = 'mds-certificate-summary__value';

    if (item.code) {
        const codeEl = document.createElement('code');
        codeEl.className = 'mds-certificate-summary__code';
        codeEl.textContent = item.value;
        valueEl.appendChild(codeEl);
    } else if (item.lines) {
        item.lines.forEach(entry => {
            const line = document.createElement('div');
            line.textContent = entry;
            valueEl.appendChild(line);
        });
    } else {
        valueEl.textContent = item.value;
    }

    element.appendChild(valueEl);
    return element;
}

export function createSummaryItem(label, value, options = {}) {
    const item = certificateSummaryItem(label, value, {
        primary: typeof options.variant === 'string' && options.variant.toLowerCase() === 'primary',
        code: Boolean(options.code),
    });
    return item ? renderSummaryItem(item) : null;
}

// Base64url text as UTF-8, decoded strictly: one spelling per byte string.
export function decodeBase64Url(value) {
    return new TextDecoder().decode(base64UrlToBytes(value));
}
