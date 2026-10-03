// The Authenticator Get Info section of the explorer's authenticator page: what
// the statement's authenticatorGetInfo says. No DOM.
import { formatDetailValue } from '../formatters.js';
import { aaguidGuid } from '../../shared/aaguid.js';
import { chipList, field, present } from './detail-fields.js';

const GET_INFO_NUMBERS = [
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

/**
 * @param {Record<string, any>} info
 */
export function authenticatorInfoSection(info) {
    const options = info.options && typeof info.options === 'object'
        ? Object.entries(info.options).filter(([, value]) => value !== undefined && value !== null)
        : [];
    return {
        key: 'authenticatorGetInfo',
        title: 'Authenticator Get Info',
        fields: present([
            info.aaguid ? field('AAGUID', aaguidGuid(info.aaguid) || String(info.aaguid), { identifier: true }) : null,
            ...GET_INFO_NUMBERS.map(([key, label]) => field(label, info[key])),
        ]),
        chipLists: present([
            chipList('Versions', info.versions),
            chipList('Extensions', info.extensions),
            chipList('Transports', info.transports),
            chipList('Algorithms', info.algorithms),
            chipList('pinUvAuth Protocols', info.pinUvAuthProtocols),
            options.length
                ? { label: 'Options', values: options.map(([key, value]) => `${key}: ${formatDetailValue(value)}`) }
                : null,
        ]),
    };
}
