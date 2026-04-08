export function normaliseCertificateBase64(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.replace(/\s+/g, '').trim();
}

export function formatCertificateInput(value) {
    return typeof value === 'string' ? value : '';
}

export function formatCertificateOutput(details) {
    if (!details || typeof details !== 'object') {
        return 'No decoded certificate details available.';
    }
    if (typeof details.summary === 'string' && details.summary.trim()) {
        return details.summary.trim();
    }
    return JSON.stringify(details, null, 2);
}

export function setCertificateSummaryContent(state, content) {
    if (!state?.certificateSummary) {
        return;
    }
    const container = state.certificateSummary;
    container.innerHTML = '';
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
