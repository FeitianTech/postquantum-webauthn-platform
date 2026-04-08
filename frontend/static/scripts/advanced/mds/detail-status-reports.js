import { formatDate } from '../mds-utils.js';

export function renderStatusReports(reports) {
    const list = Array.isArray(reports) ? reports : [];
    if (!list.length) {
        return null;
    }

    const table = document.createElement('table');
    table.className = 'mds-status-table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['Status', 'Effective Date', 'Authenticator Version', 'Certificate Number', 'Descriptor'].forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    list.forEach(report => {
        if (!report || typeof report !== 'object') {
            return;
        }
        const row = document.createElement('tr');

        const statusCell = document.createElement('td');
        statusCell.textContent = report.status !== undefined && report.status !== null
            ? String(report.status)
            : '—';
        row.appendChild(statusCell);

        const dateCell = document.createElement('td');
        dateCell.textContent = report.effectiveDate !== undefined && report.effectiveDate !== null
            ? String(report.effectiveDate)
            : '—';
        row.appendChild(dateCell);

        const versionCell = document.createElement('td');
        versionCell.textContent = report.authenticatorVersion !== undefined && report.authenticatorVersion !== null
            ? String(report.authenticatorVersion)
            : '—';
        row.appendChild(versionCell);

        const certificateCell = document.createElement('td');
        certificateCell.textContent = report.certificateNumber ? String(report.certificateNumber) : '—';
        row.appendChild(certificateCell);

        const descriptorCell = document.createElement('td');
        const descriptorContainer = document.createElement('div');
        descriptorContainer.className = 'mds-status-descriptor';

        const descriptorParts = [];
        if (report.certificationDescriptor) {
            descriptorParts.push(String(report.certificationDescriptor));
        }
        if (report.url) {
            descriptorParts.push(String(report.url));
        }
        if (descriptorParts.length) {
            const descriptorLine = document.createElement('div');
            descriptorLine.textContent = descriptorParts.join(' • ');
            descriptorContainer.appendChild(descriptorLine);
        }

        const metadataLines = [];
        if (report.certificationPolicyVersion) {
            metadataLines.push(`Policy: ${report.certificationPolicyVersion}`);
        }
        if (report.certificationRequirementsVersion) {
            metadataLines.push(`Requirements: ${report.certificationRequirementsVersion}`);
        }
        if (report.timeOfLastStatusChange) {
            metadataLines.push(`Changed: ${formatDate(report.timeOfLastStatusChange)}`);
        }
        if (metadataLines.length) {
            const metaLine = document.createElement('div');
            metaLine.className = 'mds-status-meta';
            metaLine.textContent = metadataLines.join(' • ');
            descriptorContainer.appendChild(metaLine);
        }

        if (!descriptorContainer.childElementCount) {
            descriptorContainer.textContent = '—';
        }

        descriptorCell.appendChild(descriptorContainer);
        row.appendChild(descriptorCell);

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    return table;
}
