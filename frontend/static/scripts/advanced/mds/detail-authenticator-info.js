import { formatDetailValue, formatGuidCandidate } from './utils.js';
import {
    appendDetailGrid,
    createChipList,
    createDetailSection,
    formatAuthenticatorInfoValues,
} from './detail-render-utils.js';

export function renderAuthenticatorInfo(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    const section = createDetailSection('Authenticator Get Info');
    const gridItems = [];

    if (info.aaguid) {
        gridItems.push({ label: 'AAGUID', value: formatGuidCandidate(info.aaguid) || String(info.aaguid) });
    }
    const numericKeys = [
        ['maxMsgSize', 'Max Message Size'],
        ['maxCredentialCountInList', 'Max Credential Count'],
        ['maxCredentialIdLength', 'Max Credential ID Length'],
        ['maxSerializedLargeBlobArray', 'Max Serialized Large Blob Array'],
        ['minPINLength', 'Min PIN Length'],
        ['firmwareVersion', 'Firmware Version'],
        ['maxCredBlobLength', 'Max Cred Blob Length'],
        ['maxRPIDsForSetMinPINLength', 'Max RP IDs for Set Min PIN Length'],
        ['remainingDiscoverableCredentials', 'Remaining Discoverable Credentials'],
    ];
    numericKeys.forEach(([key, label]) => {
        if (info[key] !== undefined && info[key] !== null) {
            gridItems.push({ label, value: String(info[key]) });
        }
    });
    appendDetailGrid(section, gridItems);

    const versionChips = createChipList('Versions', formatAuthenticatorInfoValues(info.versions));
    if (versionChips) {
        section.appendChild(versionChips);
    }
    const extensionChips = createChipList('Extensions', formatAuthenticatorInfoValues(info.extensions));
    if (extensionChips) {
        section.appendChild(extensionChips);
    }
    const transportChips = createChipList('Transports', formatAuthenticatorInfoValues(info.transports));
    if (transportChips) {
        section.appendChild(transportChips);
    }
    const algorithmChips = createChipList('Algorithms', formatAuthenticatorInfoValues(info.algorithms));
    if (algorithmChips) {
        section.appendChild(algorithmChips);
    }
    const pinProtocols = formatAuthenticatorInfoValues(info.pinUvAuthProtocols);
    if (pinProtocols.length) {
        const chip = createChipList('pinUvAuth Protocols', pinProtocols);
        if (chip) {
            section.appendChild(chip);
        }
    }

    const optionEntries = info.options && typeof info.options === 'object'
        ? Object.entries(info.options).filter(([, value]) => value !== undefined && value !== null)
        : [];
    if (optionEntries.length) {
        const optionChips = createChipList(
            'Options',
            optionEntries.map(([key, value]) => `${key}: ${formatDetailValue(value)}`),
        );
        if (optionChips) {
            section.appendChild(optionChips);
        }
    }

    return section;
}
