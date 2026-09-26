import { detailSections } from './explorer/detail.js';
import {
    appendDetailGrid,
    createChipList,
    createCodeValueList,
    createDetailSection,
} from './detail-render-utils.js';
import { renderStatusReports } from './detail-status-reports.js';
import {
    renderAttestationCertificates,
    renderUserVerificationDetails,
} from './detail-user-sections.js';

function gridItems(fields) {
    return fields.map(field => (field.codes
        ? { label: field.label, node: createCodeValueList(field.codes) }
        : { label: field.label, value: field.value }));
}

// The page's sections, in explorer/detail.js's order, as the current page draws them.
export function buildDetailContent(entry, { onOpenCertificatePage } = {}) {
    const fragment = document.createDocumentFragment();

    detailSections(entry).forEach(model => {
        const section = createDetailSection(model.title);
        if (model.fields) {
            appendDetailGrid(section, gridItems(model.fields));
        }
        (model.chipLists || []).forEach(list => {
            section.appendChild(createChipList(list.label, list.values));
        });
        if (model.combinations) {
            section.appendChild(renderUserVerificationDetails(model.combinations));
        }
        if (model.certificates) {
            section.appendChild(renderAttestationCertificates(model.certificates, onOpenCertificatePage));
        }
        if (model.statusReports) {
            section.appendChild(renderStatusReports(model.columns, model.statusReports));
        }
        fragment.appendChild(section);
    });

    return fragment;
}
