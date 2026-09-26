// The detail page's status reports table, from explorer/detail.js's rows.
import { MISSING_CELL_TEXT } from './explorer/rows.js';

function textCell(text) {
    const cell = document.createElement('td');
    cell.textContent = text;
    return cell;
}

export function renderStatusReports(columns, rows) {
    const table = document.createElement('table');
    table.className = 'mds-status-table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    columns.forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach(report => {
        const row = document.createElement('tr');
        row.appendChild(textCell(report.status));
        row.appendChild(textCell(report.effectiveDate));
        row.appendChild(textCell(report.authenticatorVersion));
        row.appendChild(textCell(report.certificateNumber));

        const descriptorCell = document.createElement('td');
        const descriptorContainer = document.createElement('div');
        descriptorContainer.className = 'mds-status-descriptor';
        if (report.descriptor) {
            const descriptorLine = document.createElement('div');
            descriptorLine.textContent = report.descriptor;
            descriptorContainer.appendChild(descriptorLine);
        }
        if (report.details) {
            const metaLine = document.createElement('div');
            metaLine.className = 'mds-status-meta';
            metaLine.textContent = report.details;
            descriptorContainer.appendChild(metaLine);
        }
        if (!descriptorContainer.childElementCount) {
            descriptorContainer.textContent = MISSING_CELL_TEXT;
        }
        descriptorCell.appendChild(descriptorContainer);
        row.appendChild(descriptorCell);

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    return table;
}
