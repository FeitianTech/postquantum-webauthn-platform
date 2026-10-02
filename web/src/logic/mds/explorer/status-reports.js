// A status report as the explorer's authenticator page lists it: the table's
// columns, and each report's cells, details and certificate. No DOM.
import { MISSING_CELL_TEXT } from './rows.js';
import { formatDetailValue } from '../formatters.js';

/** @typedef {ReturnType<typeof statusReportRow>} StatusReportRow */

export const STATUS_REPORT_COLUMNS = ['Status', 'Effective Date', 'Authenticator Version', 'Certificate Number', 'Descriptor'];

function reportCell(value) {
    return value !== undefined && value !== null ? String(value) : MISSING_CELL_TEXT;
}

// A report's other fields, in this order and under these names, in its
// Descriptor column's second line; any field a later MDS version adds follows
// them, named from its key. The row's cells and its certificate show the rest.
const REPORT_DETAILS = [
    ['certificationPolicyVersion', 'Policy'],
    ['certificationRequirementsVersion', 'Requirements'],
    ['certificationProfiles', 'Profiles'],
    ['sunsetDate', 'Sunset Date'],
    ['fipsRevision', 'FIPS Revision'],
    ['fipsPhysicalSecurityLevel', 'FIPS Physical Security Level'],
];
const REPORT_SHOWN_ELSEWHERE = new Set([
    'status',
    'effectiveDate',
    'authenticatorVersion',
    'certificateNumber',
    'certificationDescriptor',
    'url',
    'certificate',
]);

// "fipsRevision" -> "Fips Revision": a field no MDS version this page knows has.
function fieldName(key) {
    const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return words.charAt(0).toUpperCase() + words.slice(1);
}

function reportValue(value) {
    if (Array.isArray(value)) {
        return value.map(reportValue).join(', ');
    }
    if (value && typeof value === 'object') {
        return JSON.stringify(value);
    }
    return formatDetailValue(value);
}

// A status report's row: the cells, the Descriptor column's two lines,
// "descriptor • url" and every other field as "Name: value • …" ('' when a line
// has nothing; the column shows "—" when neither has), and the certificate ('' without one).
/**
 * @param {Record<string, any>} report
 */
export function statusReportRow(report) {
    const known = new Set(REPORT_DETAILS.map(([key]) => key));
    const details = [
        ...REPORT_DETAILS,
        ...Object.keys(report)
            .filter(key => !known.has(key) && !REPORT_SHOWN_ELSEWHERE.has(key))
            .map(key => [key, fieldName(key)]),
    ]
        .filter(([key]) => report[key] !== undefined && report[key] !== null && report[key] !== '')
        .map(([key, name]) => `${name}: ${reportValue(report[key])}`);
    return {
        status: reportCell(report.status),
        effectiveDate: reportCell(report.effectiveDate),
        authenticatorVersion: reportCell(report.authenticatorVersion),
        certificateNumber: report.certificateNumber ? String(report.certificateNumber) : MISSING_CELL_TEXT,
        descriptor: [report.certificationDescriptor, report.url].filter(Boolean).map(String).join(' • '),
        details: details.join(' • '),
        certificate: typeof report.certificate === 'string' ? report.certificate : '',
    };
}
