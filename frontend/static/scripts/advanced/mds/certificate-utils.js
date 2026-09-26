export { formatCertificateOutput, normaliseCertificateBase64 } from './explorer/certificate.js';

export function formatCertificateInput(value) {
    return typeof value === 'string' ? value : '';
}

export function setCertificateSummaryContent(state, content) {
    if (!state?.certificateSummary) {
        return;
    }
    const container = state.certificateSummary;
    container.replaceChildren();
    if (content instanceof Node) {
        container.appendChild(content);
    } else if (typeof content === 'string' && content.trim()) {
        const message = document.createElement('div');
        message.className = 'mds-certificate-summary__value';
        message.textContent = content;
        container.appendChild(message);
    }
}

export function setCertificateFieldContent(field, value) {
    if (!(field instanceof HTMLElement)) {
        return;
    }

    const content = typeof value === 'string' ? value : '';
    if ('value' in field) {
        field.value = content;
    } else {
        field.textContent = content;
    }
}

export function applyCertificateLoadingCursorVisibility(requestCount, loadingClassName) {
    const shouldShow = requestCount > 0;
    [document.documentElement, document.body].forEach(target => {
        if (target) {
            target.classList.toggle(loadingClassName, shouldShow);
        }
    });
}
