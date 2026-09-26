// The certificate page's summary DOM, from explorer/certificate.js's model.
import {
    certificatePublicKeySection,
    certificateSignatureSection,
    certificateSummary,
} from '../explorer/certificate.js';
import { renderSummaryItem } from './certificate-primitives.js';

function renderList(items) {
    const list = document.createElement('ul');
    list.className = 'mds-certificate-summary__list';
    items.forEach(item => list.appendChild(renderSummaryItem(item)));
    return list;
}

function renderSection(section) {
    if (!section) {
        return null;
    }
    const element = document.createElement('div');
    element.className = 'mds-certificate-summary__section';

    const title = document.createElement('div');
    title.className = 'mds-certificate-summary__heading';
    title.textContent = section.title;
    element.appendChild(title);

    element.appendChild(renderList(section.items));
    return element;
}

export function renderCertificatePublicKey(info) {
    return renderSection(certificatePublicKeySection(info));
}

export function renderCertificateSignature(signature) {
    return renderSection(certificateSignatureSection(signature));
}

export function renderCertificateSummary(details) {
    const summary = certificateSummary(details);
    if (!summary) {
        return null;
    }
    const fragment = document.createDocumentFragment();
    if (summary.items.length) {
        fragment.appendChild(renderList(summary.items));
    }
    summary.sections.forEach(section => fragment.appendChild(renderSection(section)));
    return fragment;
}
