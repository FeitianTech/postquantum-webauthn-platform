import { formatCertificateDateDisplay, formatSignatureHashName } from './formatters.js';
import { createSummaryItem, determinePublicKeyAlgorithm } from './certificate-primitives.js';

export function renderCertificatePublicKey(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    const section = document.createElement('div');
    section.className = 'mds-certificate-summary__section';

    const title = document.createElement('div');
    title.className = 'mds-certificate-summary__heading';
    title.textContent = 'Public Key';
    section.appendChild(title);

    const list = document.createElement('ul');
    list.className = 'mds-certificate-summary__list';

    const algorithmItem = createSummaryItem('Algorithm', determinePublicKeyAlgorithm(info));
    if (algorithmItem) {
        list.appendChild(algorithmItem);
    }

    const algorithmDetails = info.algorithm && typeof info.algorithm === 'object' ? info.algorithm : null;
    const curveValue = info.curve || (algorithmDetails && algorithmDetails.namedCurve);
    if (curveValue) {
        const curveItem = createSummaryItem('Named Curve', curveValue);
        if (curveItem) {
            list.appendChild(curveItem);
        }
    }

    const modulusLength = algorithmDetails && algorithmDetails.modulusLength;
    const keySize = modulusLength || info.keySize;
    if (keySize) {
        const sizeItem = createSummaryItem('Key Size', `${keySize} bit`);
        if (sizeItem) {
            list.appendChild(sizeItem);
        }
    }

    if (info.publicExponent !== undefined && info.publicExponent !== null) {
        const exponentItem = createSummaryItem('Public Exponent', String(info.publicExponent));
        if (exponentItem) {
            list.appendChild(exponentItem);
        }
    }

    if (info.modulusHex) {
        const modulusItem = createSummaryItem('Modulus', info.modulusHex, { code: true });
        if (modulusItem) {
            list.appendChild(modulusItem);
        }
    }

    if (info.uncompressedPoint) {
        const pointItem = createSummaryItem('Uncompressed Point', info.uncompressedPoint, { code: true });
        if (pointItem) {
            list.appendChild(pointItem);
        }
    }

    if (info.subjectPublicKeyInfoBase64) {
        const valueItem = createSummaryItem('Value', info.subjectPublicKeyInfoBase64, { code: true });
        if (valueItem) {
            list.appendChild(valueItem);
        }
    }

    if (!list.childElementCount) {
        return null;
    }

    section.appendChild(list);
    return section;
}

export function renderCertificateSignature(signature) {
    if (!signature || typeof signature !== 'object') {
        return null;
    }

    const section = document.createElement('div');
    section.className = 'mds-certificate-summary__section';

    const title = document.createElement('div');
    title.className = 'mds-certificate-summary__heading';
    title.textContent = 'Signature';
    section.appendChild(title);

    const list = document.createElement('ul');
    list.className = 'mds-certificate-summary__list';

    if (signature.algorithm) {
        const algorithmItem = createSummaryItem('Algorithm', signature.algorithm);
        if (algorithmItem) {
            list.appendChild(algorithmItem);
        }
    }

    if (signature.hash) {
        const hashName = typeof signature.hash === 'object' && signature.hash !== null
            ? signature.hash.name
            : signature.hash;
        const hashValue = typeof hashName === 'string' ? formatSignatureHashName(hashName) : hashName;
        const hashItem = createSummaryItem('Hash', hashValue);
        if (hashItem) {
            list.appendChild(hashItem);
        }
    }

    if (signature.hex) {
        const valueItem = createSummaryItem('Value', signature.hex, { code: true });
        if (valueItem) {
            list.appendChild(valueItem);
        }
    }

    if (!list.childElementCount) {
        return null;
    }

    section.appendChild(list);
    return section;
}

export function renderCertificateSummary(details) {
    if (!details || typeof details !== 'object') {
        return null;
    }

    const fragment = document.createDocumentFragment();

    const infoList = document.createElement('ul');
    infoList.className = 'mds-certificate-summary__list';

    const validity = details.validity || {};
    const serialNumber = details.serialNumber || {};

    [
        createSummaryItem('Subject', details.subject, { variant: 'primary' }),
        createSummaryItem('Issuer', details.issuer, { variant: 'primary' }),
        createSummaryItem('Not Before', formatCertificateDateDisplay(validity.notBefore), { variant: 'primary' }),
        createSummaryItem('Not After', formatCertificateDateDisplay(validity.notAfter), { variant: 'primary' }),
        createSummaryItem('Serial Number', serialNumber.decimal || serialNumber.hex, { variant: 'primary' }),
        serialNumber.hex ? createSummaryItem('Serial Number (Hex)', serialNumber.hex) : null,
    ].forEach(item => {
        if (item) {
            infoList.appendChild(item);
        }
    });

    if (infoList.childElementCount) {
        fragment.appendChild(infoList);
    }

    const publicKeySection = renderCertificatePublicKey(details.publicKeyInfo);
    if (publicKeySection) {
        fragment.appendChild(publicKeySection);
    }

    const signatureSection = renderCertificateSignature(details.signature);
    if (signatureSection) {
        fragment.appendChild(signatureSection);
    }

    return fragment.childElementCount ? fragment : null;
}