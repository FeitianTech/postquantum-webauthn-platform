// What a saved credential's details show above its registration, as data: the
// properties and the attestation checks, the user at creation with each
// identifier in every spelling, the AAGUID, the attestation format, the
// authenticator data's flags, the extension outputs and the public key. DOM-free.
// How a COSE algorithm and key type are named is passed in (`describers`: the
// callers give ../cose-labels.js's).
import {
    base64UrlToBytes,
    bytesToBase64,
    bytesToBase64Url,
} from '../../shared/base64.js';
import {hexToUint8Array} from '../../shared/bytes.js';
import {aaguidGuid, aaguidHex} from '../../shared/aaguid.js';
import {resolveCredentialAlgorithmIdentifier} from '../algorithm-tag.js';
import {extractMinPinLengthValue} from '../min-pin-length.js';
import {deriveAaguidFromCredentialData} from '../record-fields.js';
import {
    computeCredentialAaguidMatchStatus,
    normaliseAttestationResultValue,
    resolveCredentialAttestationValue,
} from '../attestation-context.js';

export function getCoseMapValue(coseMap, key) {
    if (!coseMap || typeof coseMap !== 'object') {
        return undefined;
    }
    // A number key finds its string key too: property keys are strings.
    if (Object.hasOwn(coseMap, key)) {
        return coseMap[key];
    }
    return undefined;
}

export function deriveAaguidDisplayValues(hex) {
    const normalizedAaguidHex = hex ? hex.toLowerCase() : '';
    const bytes = normalizedAaguidHex ? hexToUint8Array(normalizedAaguidHex) : null;
    return {
        aaguidHex: normalizedAaguidHex,
        aaguidB64: bytes ? bytesToBase64(bytes) : '',
        aaguidB64u: bytes ? bytesToBase64Url(bytes) : '',
    };
}

export const DETAIL_TEXT = Object.freeze({
    properties: 'Properties',
    discoverable: 'Discoverable (resident key):',
    largeBlob: 'Supports largeBlob:',
    minPinLength: 'Authenticator minPinLength:',
    // "In formal WebAuthn, any false result below causes registration to fail. ...",
    // with "false" in bold.
    checksNote: Object.freeze([
        'In formal WebAuthn, any ',
        'false',
        ' result below causes registration to fail. This platform keeps registration valid for data inspection purposes.',
    ]),
    userInfo: 'User info at creation',
    name: 'Name:',
    displayName: 'Display name:',
    userHandle: 'User handle (User ID):',
    credentialId: 'Credential ID:',
    notBase64Url: 'Not valid base64url: shown as stored.',
    aaguid: 'AAGUID',
    attestationFormat: 'Attestation Format',
    authenticatorData: 'Authenticator Data (registration)',
    signatureCounter: 'Signature Counter:',
    extensions: 'Client extension outputs (registration)',
    publicKey: 'Public Key',
    algorithm: 'Algorithm:',
    keyType: 'COSE key type:',
    parameterSet: 'ML-DSA parameter set:',
    notAvailable: 'N/A',
});

/** A check's or a property's value as the details say it: true, false, N/A when absent, or as written. */
export function describeValue(value) {
    const normalized = typeof value === 'string' ? value.trim().toLowerCase() : value;
    if (normalized === true || normalized === 'true') {
        return { kind: 'true', text: 'true' };
    }
    if (normalized === false || normalized === 'false') {
        return { kind: 'false', text: 'false' };
    }
    if (value === null || value === undefined) {
        return { kind: 'missing', text: DETAIL_TEXT.notAvailable };
    }
    return { kind: 'other', text: String(value) };
}

const ROOT_CHECKS = [
    { key: 'fido_mds', label: 'FIDO MDS' },
    { key: 'chain', label: 'Chain' },
];

// Which roots the Root Valid check tried (FIDO MDS, the certificate chain), each
// with its verdict (null when it was not tried); null when the checks name none.
function describeRootChecks(attestationChecksData) {
    const rootChecksRaw = attestationChecksData?.root_checks;
    if (!rootChecksRaw || typeof rootChecksRaw !== 'object') {
        return null;
    }

    return ROOT_CHECKS.map(descriptor => {
        const rawValue = rootChecksRaw[descriptor.key];
        return {
            label: descriptor.label,
            value: rawValue === undefined ? null : normaliseAttestationResultValue(rawValue),
        };
    });
}

/** "Properties": discoverable, large blob, minPinLength, then the four checks and their note. */
export function describeProperties({
    cred,
    attestationContext,
    fallbackCertificates,
    certificateAaguidHex,
    authDataAaguidHex,
}) {
    const { attestationChecksData } = attestationContext;

    const check = (summaryKey, propertyKey) => normaliseAttestationResultValue(
        resolveCredentialAttestationValue(cred, summaryKey, propertyKey, attestationContext),
    );

    return {
        title: DETAIL_TEXT.properties,
        discoverable: cred.residentKey ?? false,
        largeBlob: cred.largeBlob ?? false,
        minPinLength: extractMinPinLengthValue(cred),
        checks: [
            { label: 'Signature Valid', value: check('signatureValid', 'attestationSignatureValid'), rootChecks: null },
            {
                label: 'Root Valid',
                value: check('rootValid', 'attestationRootValid'),
                rootChecks: describeRootChecks(attestationChecksData),
            },
            { label: 'RPID Hash Valid', value: check('rpIdHashValid', 'attestationRpIdHashValid'), rootChecks: null },
            {
                label: 'AAGUID Match',
                value: computeCredentialAaguidMatchStatus(cred, {
                    certificateEntries: fallbackCertificates,
                    certificateAaguidHex,
                    authDataAaguidHex,
                    attestationContext,
                }),
                rootChecks: null,
            },
        ],
    };
}

// An identifier the record keeps as base64url, in each spelling of its bytes; or
// the value as stored, with why, when it is not base64url.
function describeIdentifier(title, value) {
    let bytes;
    try {
        bytes = base64UrlToBytes(value);
    } catch (error) {
        return { title, stored: value, note: DETAIL_TEXT.notBase64Url };
    }
    return {
        title,
        spellings: [
            { label: 'b64', value: bytesToBase64(bytes) },
            { label: 'b64u', value: bytesToBase64Url(bytes) },
            { label: 'hex', value: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('') },
        ],
    };
}

/** "User info at creation": the name and display name, then the user handle and the credential id when there are. */
export function describeUserInfo(cred) {
    const identifiers = [];
    if (cred.userHandle) {
        identifiers.push(describeIdentifier(DETAIL_TEXT.userHandle, cred.userHandle));
    }
    if (cred.credentialId) {
        identifiers.push(describeIdentifier(DETAIL_TEXT.credentialId, cred.credentialId));
    }
    return {
        title: DETAIL_TEXT.userInfo,
        name: cred.userName || cred.email || DETAIL_TEXT.notAvailable,
        displayName: cred.displayName || cred.userName || cred.email || DETAIL_TEXT.notAvailable,
        identifiers,
    };
}

// The record's own spellings that say what they are come first (hex, GUID),
// then `aaguid`, which the server writes in base64url.
function resolveAaguidHex(cred, attestationContext) {
    const { propertiesData, attestationChecksData } = attestationContext;

    let hex = '';
    for (const explicit of [cred.aaguidHex, cred.aaguidGuid, propertiesData?.aaguidHex, propertiesData?.aaguidGuid]) {
        hex = aaguidHex(explicit);
        if (hex) {
            break;
        }
    }
    if (!hex) {
        hex = aaguidHex(cred.aaguid);
    }

    const fallbackAaguidCandidates = [
        propertiesData?.aaguid,
        attestationChecksData?.metadata?.aaguid,
    ];

    const relyingPartyAaguid = cred?.relyingParty?.aaguid;
    if (relyingPartyAaguid && typeof relyingPartyAaguid === 'object') {
        fallbackAaguidCandidates.push(relyingPartyAaguid.raw, relyingPartyAaguid.guid);
    } else if (relyingPartyAaguid) {
        fallbackAaguidCandidates.push(relyingPartyAaguid);
    }

    if (!hex) {
        for (const candidate of fallbackAaguidCandidates) {
            const normalised = aaguidHex(candidate);
            if (normalised) {
                hex = normalised;
                break;
            }
        }
    }

    if (!hex) {
        hex = deriveAaguidFromCredentialData(cred);
    }

    return hex;
}

/** The AAGUID in each spelling (b64, b64u, hex, guid), each "N/A" when unknown. */
export function describeAaguid(cred, attestationContext) {
    const {
        aaguidHex: normalizedAaguidHex,
        aaguidB64,
        aaguidB64u,
    } = deriveAaguidDisplayValues(resolveAaguidHex(cred, attestationContext));

    const guid = normalizedAaguidHex && normalizedAaguidHex.length === 32 ? aaguidGuid(normalizedAaguidHex) : '';

    const hasAaguid = Boolean(normalizedAaguidHex);
    const or = value => value || DETAIL_TEXT.notAvailable;
    return {
        title: DETAIL_TEXT.aaguid,
        values: [
            { label: 'b64', value: or(hasAaguid && aaguidB64) },
            { label: 'b64u', value: or(hasAaguid && aaguidB64u) },
            { label: 'hex', value: or(hasAaguid && normalizedAaguidHex) },
            { label: 'guid', value: or(guid) },
        ],
    };
}

/** "Attestation Format": the format as given. */
export function describeAttestationFormat(format) {
    return { title: DETAIL_TEXT.attestationFormat, value: format };
}

const FLAG_NAMES = ['at', 'be', 'bs', 'ed', 'up', 'uv'];

/** "Authenticator Data (registration)": each flag and the signature counter; null without flags. */
export function describeAuthenticatorDataFlags(cred) {
    if (!cred.flags) {
        return null;
    }
    return {
        title: DETAIL_TEXT.authenticatorData,
        flags: FLAG_NAMES.map(flag => ({ name: flag.toUpperCase(), value: String(cred.flags[flag]) })),
        counter: String(cred.signCount || 0),
    };
}

/** "Client extension outputs (registration)" as indented JSON; null when there are none. */
export function describeExtensions(cred) {
    if (!cred.clientExtensionOutputs || Object.keys(cred.clientExtensionOutputs).length === 0) {
        return null;
    }
    return { title: DETAIL_TEXT.extensions, text: JSON.stringify(cred.clientExtensionOutputs, null, 2) };
}

/** "Public Key": the algorithm, the COSE key type, an ML-DSA key's parameter set; null without either. */
export function describePublicKey(cred, { describeCoseAlgorithm, describeCoseKeyType, describeMldsaParameterSet }) {
    const hasPublicKeyData = cred.publicKeyAlgorithm !== undefined
        || cred.algorithm !== undefined
        || (cred.publicKeyCose && Object.keys(cred.publicKeyCose).length > 0);

    if (!hasPublicKeyData) {
        return null;
    }

    const coseMap = cred.publicKeyCose || {};
    const resolvedAlgorithm = resolveCredentialAlgorithmIdentifier(cred);
    const algorithm = resolvedAlgorithm !== null
        ? resolvedAlgorithm
        : getCoseMapValue(coseMap, 3);

    const keyType = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);
    const parameterSet = describeMldsaParameterSet(algorithm);

    const lines = [{ label: DETAIL_TEXT.algorithm, value: describeCoseAlgorithm(algorithm) }];
    if (keyType !== undefined && keyType !== null) {
        lines.push({ label: DETAIL_TEXT.keyType, value: describeCoseKeyType(keyType) });
    }
    if (parameterSet) {
        lines.push({ label: DETAIL_TEXT.parameterSet, value: parameterSet });
    }
    return { title: DETAIL_TEXT.publicKey, lines };
}
