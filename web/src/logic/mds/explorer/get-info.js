// The Authenticator Get Info section of the explorer's authenticator page: what
// the statement's authenticatorGetInfo says. No DOM.
import { formatDetailValue } from '../formatters.js';
import { aaguidGuid } from '../../shared/aaguid.js';
import { chipList, field, nameFromKey, present, valueText } from './detail-fields.js';

const GET_INFO_FIELDS = [
    ['maxMsgSize', 'Max Message Size'],
    ['maxCredentialCountInList', 'Max Credential Count'],
    ['maxCredentialIdLength', 'Max Credential ID Length'],
    ['maxSerializedLargeBlobArray', 'Max Serialized Large Blob Array'],
    ['minPINLength', 'Min PIN Length'],
    ['firmwareVersion', 'Firmware Version'],
    ['maxCredBlobLength', 'Max Cred Blob Length'],
    ['maxRPIDsForSetMinPINLength', 'Max RP IDs for Set Min PIN Length'],
    ['remainingDiscoverableCredentials', 'Remaining Discoverable Credentials'],
    ['maxPINLength', 'Max PIN Length'],
    ['preferredPlatformUvAttempts', 'Preferred Platform UV Attempts'],
    ['uvModality', 'UV Modality'],
    ['uvCountSinceLastPinEntry', 'UV Count Since Last PIN Entry'],
    ['forcePINChange', 'Force PIN Change'],
    ['longTouchForReset', 'Long Touch for Reset'],
    ['pinComplexityPolicy', 'PIN Complexity Policy'],
    ['pinComplexityPolicyURL', 'PIN Complexity Policy URL'],
    ['encIdentifier', 'Encrypted Identifier'],
    ['encCredStoreState', 'Encrypted Credential Store State'],
];

const GET_INFO_LISTS = [
    ['versions', 'Versions'],
    ['extensions', 'Extensions'],
    ['transports', 'Transports'],
    ['algorithms', 'Algorithms'],
    ['pinUvAuthProtocols', 'pinUvAuth Protocols'],
];

const GET_INFO_LATER_LISTS = [
    ['transportsForReset', 'Transports for Reset'],
    ['attestationFormats', 'Attestation Formats'],
    ['authenticatorConfigCommands', 'Authenticator Config Commands'],
    ['vendorPrototypeConfigCommands', 'Vendor Prototype Config Commands'],
];

const GET_INFO_SHOWN = new Set([
    'aaguid',
    'options',
    'certifications',
    ...[...GET_INFO_FIELDS, ...GET_INFO_LISTS, ...GET_INFO_LATER_LISTS].map(([key]) => key),
]);

// "name: value" for each member of a map getInfo holds (its options, its
// certifications), the members without a value left out.
function memberChips(label, members) {
    const entries = members && typeof members === 'object' && !Array.isArray(members)
        ? Object.entries(members).filter(([, value]) => value !== undefined && value !== null)
        : [];
    return entries.length ? { label, values: entries.map(([key, value]) => `${key}: ${formatDetailValue(value)}`) } : null;
}

/**
 * @param {Record<string, any>} info
 */
export function authenticatorInfoSection(info) {
    const others = Object.keys(info).filter(key => !GET_INFO_SHOWN.has(key) && info[key] !== null);
    return {
        key: 'authenticatorGetInfo',
        title: 'Authenticator Get Info',
        fields: present([
            info.aaguid ? field('AAGUID', aaguidGuid(info.aaguid) || String(info.aaguid), { identifier: true }) : null,
            ...GET_INFO_FIELDS.map(([key, label]) => field(label, info[key])),
            // Any member a later CTAP version adds, named from its key.
            ...others.map(key => field(nameFromKey(key), valueText(info[key]))),
        ]),
        chipLists: present([
            ...GET_INFO_LISTS.map(([key, label]) => chipList(label, info[key])),
            memberChips('Options', info.options),
            ...GET_INFO_LATER_LISTS.map(([key, label]) => chipList(label, info[key])),
            memberChips('Certifications', info.certifications),
        ]),
    };
}
