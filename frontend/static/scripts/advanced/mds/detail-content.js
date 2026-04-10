import { formatUpv } from './utils.js';
import {
    appendDetailGrid,
    createChipList,
    createCodeValueList,
    createDetailSection,
    formatRawListValues,
} from './detail-render-utils.js';
import { renderAuthenticatorInfo } from './detail-authenticator-info.js';
import { renderStatusReports } from './detail-status-reports.js';
import {
    renderAttestationCertificates,
    renderUserVerificationDetails,
} from './detail-user-sections.js';

export function buildDetailContent(entry, { onOpenCertificatePage } = {}) {
    const fragment = document.createDocumentFragment();
    const metadata = entry?.metadataStatement ?? {};

    const overviewSection = createDetailSection('Overview');
    const overviewItems = [];
    overviewItems.push({ label: 'Identifier', value: entry.id || '—' });
    if (entry.aaguid) {
        overviewItems.push({ label: 'AAGUID', value: entry.aaguid });
    }
    if (entry.protocol) {
        overviewItems.push({ label: 'Protocol', value: entry.protocol });
    }
    if (entry.certification) {
        overviewItems.push({ label: 'Certification', value: entry.certification });
    }
    if (metadata.authenticatorVersion !== undefined && metadata.authenticatorVersion !== null) {
        overviewItems.push({ label: 'Authenticator Version', value: String(metadata.authenticatorVersion) });
    }
    if (entry.dateUpdated) {
        overviewItems.push({ label: 'Date Updated', value: entry.dateUpdated });
    }
    appendDetailGrid(overviewSection, overviewItems);
    fragment.appendChild(overviewSection);

    const metadataSection = createDetailSection('Metadata Statement');
    const metadataItems = [];
    if (metadata.description) {
        metadataItems.push({ label: 'Description', value: String(metadata.description) });
    }
    if (metadata.legalHeader) {
        metadataItems.push({ label: 'Legal Header', value: String(metadata.legalHeader) });
    }
    if (metadata.schema !== undefined && metadata.schema !== null) {
        metadataItems.push({ label: 'Schema', value: String(metadata.schema) });
    }
    if (metadata.cryptoStrength !== undefined && metadata.cryptoStrength !== null) {
        metadataItems.push({ label: 'Crypto Strength', value: String(metadata.cryptoStrength) });
    }
    const keyIdentifierNode = createCodeValueList(entry.attestationKeyIdentifiers);
    if (keyIdentifierNode) {
        metadataItems.push({ label: 'Attestation Certificate Key IDs', node: keyIdentifierNode });
    }
    const upvValues = formatUpv(metadata.upv);
    if (upvValues.length) {
        metadataItems.push({ label: 'UPV', value: upvValues.join(', ') });
    }
    appendDetailGrid(metadataSection, metadataItems);

    const algorithmChips = createChipList('Authentication Algorithms', formatRawListValues(metadata.authenticationAlgorithms));
    if (algorithmChips) {
        metadataSection.appendChild(algorithmChips);
    }
    const encodingChips = createChipList('Public Key Algorithms', formatRawListValues(metadata.publicKeyAlgAndEncodings));
    if (encodingChips) {
        metadataSection.appendChild(encodingChips);
    }
    const attestationChips = createChipList('Attestation Types', formatRawListValues(metadata.attestationTypes));
    if (attestationChips) {
        metadataSection.appendChild(attestationChips);
    }
    const keyProtectionChips = createChipList('Key Protection', formatRawListValues(metadata.keyProtection));
    if (keyProtectionChips) {
        metadataSection.appendChild(keyProtectionChips);
    }
    const matcherChips = createChipList('Matcher Protection', formatRawListValues(metadata.matcherProtection));
    if (matcherChips) {
        metadataSection.appendChild(matcherChips);
    }
    const attachmentChips = createChipList('Attachment Hints', formatRawListValues(metadata.attachmentHint));
    if (attachmentChips) {
        metadataSection.appendChild(attachmentChips);
    }
    const displayChips = createChipList('TC Display', formatRawListValues(metadata.tcDisplay));
    if (displayChips) {
        metadataSection.appendChild(displayChips);
    }
    fragment.appendChild(metadataSection);

    const userVerificationContent = renderUserVerificationDetails(metadata.userVerificationDetails);
    if (userVerificationContent) {
        const userSection = createDetailSection('User Verification Details');
        userSection.appendChild(userVerificationContent);
        fragment.appendChild(userSection);
    }

    const certificatesContent = renderAttestationCertificates(
        entry.attestationCertificates,
        onOpenCertificatePage,
    );
    if (certificatesContent) {
        const certificateSection = createDetailSection('Attestation Root Certificates');
        certificateSection.appendChild(certificatesContent);
        fragment.appendChild(certificateSection);
    }

    const authenticatorInfoSection = renderAuthenticatorInfo(metadata.authenticatorGetInfo);
    if (authenticatorInfoSection) {
        fragment.appendChild(authenticatorInfoSection);
    }

    const statusContent = renderStatusReports(entry.statusReports);
    if (statusContent) {
        const statusSection = createDetailSection('Status Reports');
        statusSection.appendChild(statusContent);
        fragment.appendChild(statusSection);
    }

    return fragment;
}
