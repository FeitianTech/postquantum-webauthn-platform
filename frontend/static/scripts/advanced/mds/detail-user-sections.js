// The detail page's user-verification combinations and certificate buttons, from
// explorer/detail.js's model.
export function renderUserVerificationDetails(combinations) {
    const container = document.createElement('div');
    container.className = 'mds-detail-groups';

    combinations.forEach(combination => {
        const card = document.createElement('div');
        card.className = 'mds-detail-card';
        const title = document.createElement('div');
        title.className = 'mds-detail-card__title';
        title.textContent = combination.title;
        card.appendChild(title);

        const content = document.createElement('div');
        content.className = 'mds-detail-card__content';

        combination.methods.forEach(item => {
            if (item.method) {
                const methodEl = document.createElement('div');
                methodEl.textContent = item.method;
                content.appendChild(methodEl);
            }
            if (item.codeAccuracy) {
                const info = document.createElement('small');
                info.textContent = item.codeAccuracy;
                content.appendChild(info);
            }
        });

        card.appendChild(content);
        container.appendChild(card);
    });

    return container;
}

export function renderAttestationCertificates(certificates, onOpenCertificatePage) {
    const container = document.createElement('div');
    container.className = 'mds-certificates';

    certificates.forEach(({ label, certificate }) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'mds-certificate-button';
        button.textContent = label;
        button.addEventListener('click', () => {
            if (typeof onOpenCertificatePage === 'function') {
                onOpenCertificatePage(certificate, button);
            }
        });
        container.appendChild(button);
    });

    return container;
}
