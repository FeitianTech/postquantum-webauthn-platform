export function formatDetailSubtitle(entry) {
    if (!entry) {
        return '';
    }

    const parts = [];
    if (entry.aaguid) {
        parts.push(`AAGUID: ${entry.aaguid}`);
    }
    if (entry.id && entry.id !== entry.aaguid) {
        parts.push(`ID: ${entry.id}`);
    }
    if (entry.protocol) {
        parts.push(entry.protocol);
    }
    return parts.join(' • ');
}

export function renderUserVerificationDetails(details) {
    const groups = Array.isArray(details) ? details : [];
    if (!groups.length) {
        return null;
    }

    const container = document.createElement('div');
    container.className = 'mds-detail-groups';

    groups.forEach((group, index) => {
        const entries = Array.isArray(group) ? group : [group];
        const validEntries = entries.filter(item => item && typeof item === 'object');
        if (!validEntries.length) {
            return;
        }

        const card = document.createElement('div');
        card.className = 'mds-detail-card';
        const title = document.createElement('div');
        title.className = 'mds-detail-card__title';
        title.textContent = `Combination ${index + 1}`;
        card.appendChild(title);

        const content = document.createElement('div');
        content.className = 'mds-detail-card__content';

        validEntries.forEach(item => {
            const method = item.userVerificationMethod !== undefined && item.userVerificationMethod !== null
                ? String(item.userVerificationMethod)
                : '';
            if (method) {
                const methodEl = document.createElement('div');
                methodEl.textContent = method;
                content.appendChild(methodEl);
            }

            const caDesc = item.caDesc && typeof item.caDesc === 'object' ? item.caDesc : null;
            if (caDesc) {
                const parts = [];
                if (caDesc.base !== undefined) {
                    parts.push(`Base: ${caDesc.base}`);
                }
                if (caDesc.minLength !== undefined) {
                    parts.push(`Min length: ${caDesc.minLength}`);
                }
                if (caDesc.maxRetries !== undefined) {
                    parts.push(`Max retries: ${caDesc.maxRetries}`);
                }
                if (caDesc.blockSlowdown !== undefined) {
                    parts.push(`Block slowdown: ${caDesc.blockSlowdown}`);
                }
                if (parts.length) {
                    const info = document.createElement('small');
                    info.textContent = parts.join(' • ');
                    content.appendChild(info);
                }
            }
        });

        if (content.childElementCount) {
            card.appendChild(content);
            container.appendChild(card);
        }
    });

    return container.childElementCount ? container : null;
}

export function renderAttestationCertificates(certificates, onOpenCertificatePage) {
    const values = Array.isArray(certificates) ? certificates.filter(Boolean) : [];
    if (!values.length) {
        return null;
    }

    const container = document.createElement('div');
    container.className = 'mds-certificates';

    values.forEach((certificate, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'mds-certificate-button';
        button.textContent = `Certificate ${index + 1}`;
        button.addEventListener('click', () => {
            if (typeof onOpenCertificatePage === 'function') {
                onOpenCertificatePage(certificate, button);
            }
        });
        container.appendChild(button);
    });

    return container;
}
