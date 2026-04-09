import {registrationDetailState} from './state.js';
import {
    normaliseCertificateEntryForModal,
    partitionCertificateEntries,
} from './certificate-core.js';
import {
    removeKeysCaseInsensitive,
    removeKeysFromObject,
    sanitizeParsedCertificateDetails,
    stripCertificateCollections,
    stripSignatureFormatting,
} from './sanitize-common.js';
import {cloneJson} from './data-utils.js';

export function sanitiseAttestationObjectForDisplay(
    attestationObject,
    attestationFormatRaw = ''
) {
    const cloned = cloneJson(attestationObject || null);
    if (!cloned || typeof cloned !== 'object') {
        const formatValue = typeof attestationFormatRaw === 'string' ? attestationFormatRaw.trim() : '';
        if (!formatValue) {
            return null;
        }
        return { fmt: formatValue };
    }

    const certificatesAll = Array.isArray(registrationDetailState.attestationCertificates)
        ? registrationDetailState.attestationCertificates
        : [];
    const { valid: certificateInfos, failures: parseFailureInfos } = partitionCertificateEntries(certificatesAll);
    const certificates = certificateInfos.length
        ? certificateInfos
        : parseFailureInfos;

    if (cloned.attStmt && typeof cloned.attStmt === 'object') {
        const attStmtClone = { ...cloned.attStmt };
        const sourceArray = Array.isArray(attStmtClone.x5c) ? attStmtClone.x5c : [];
        const maxLength = Math.max(sourceArray.length, certificates.length);

        if (maxLength > 0) {
            const sanitizedChain = [];

            for (let index = 0; index < maxLength; index += 1) {
                const info = certificates[index];
                const certificateEntry = info && typeof info === 'object' && info.entry ? info.entry : info;
                const sourceEntry = sourceArray[index];

                let parsedDetails = certificateEntry && typeof certificateEntry === 'object'
                    ? certificateEntry.parsedX5c
                    : null;

                if ((!parsedDetails || typeof parsedDetails !== 'object') && sourceEntry) {
                    const normalised = normaliseCertificateEntryForModal(sourceEntry);
                    if (normalised && typeof normalised.parsedX5c === 'object') {
                        parsedDetails = normalised.parsedX5c;
                    }
                }

                if (!parsedDetails || typeof parsedDetails !== 'object') {
                    continue;
                }

                const sanitizedDetails = sanitizeParsedCertificateDetails(parsedDetails);
                const summaryText = typeof parsedDetails.summary === 'string'
                    ? parsedDetails.summary.trim()
                    : '';
                const errorText = typeof parsedDetails.error === 'string'
                    ? parsedDetails.error.trim()
                    : '';

                const hasDetails = sanitizedDetails && Object.keys(sanitizedDetails).length > 0;
                if (!hasDetails && !summaryText && !errorText) {
                    continue;
                }

                const entry = {
                    certificateIndex: index + 1,
                };

                if (hasDetails) {
                    entry.details = sanitizedDetails;
                }

                if (summaryText) {
                    entry.summary = summaryText;
                }

                if (errorText) {
                    entry.error = errorText;
                }

                sanitizedChain.push(entry);
            }

            if (sanitizedChain.length) {
                attStmtClone.x5c = sanitizedChain;
            } else {
                delete attStmtClone.x5c;
            }
        } else {
            delete attStmtClone.x5c;
        }

        delete attStmtClone.x5cParseErrors;

        stripCertificateCollections(attStmtClone);
        removeKeysCaseInsensitive(attStmtClone, ['publicKeyHex', 'publicKeyHexLines', 'publicKeyBase64']);
        stripSignatureFormatting(attStmtClone);
        cloned.attStmt = attStmtClone;
    }

    stripCertificateCollections(cloned);
    removeKeysFromObject(cloned, ['summary', 'raw']);
    removeKeysCaseInsensitive(cloned, ['publicKeyHex', 'publicKeyHexLines', 'publicKeyBase64']);
    stripSignatureFormatting(cloned);

    let formatValue = typeof attestationFormatRaw === 'string' ? attestationFormatRaw.trim() : '';
    if (!formatValue && typeof cloned.fmt === 'string') {
        formatValue = cloned.fmt;
    }
    if (Object.prototype.hasOwnProperty.call(cloned, 'fmt')) {
        delete cloned.fmt;
    }

    const ordered = {};
    if (formatValue) {
        ordered.fmt = formatValue;
    }

    Object.keys(cloned).forEach(key => {
        ordered[key] = cloned[key];
    });

    return ordered;
}
