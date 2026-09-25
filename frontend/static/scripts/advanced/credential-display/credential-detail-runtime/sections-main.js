import {
    base64UrlToBytes,
    bytesToBase64,
    bytesToBase64Url,
} from '../../../shared/utils/base64.js';
import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
} from '../../ui/display-utils.js';
import {el} from '../../../shared/ui/dom.js';
import {labelledLine} from '../detail-nodes.js';
import {
    getCoseMapValue,
} from '../../credentials/utils.js';
import {
    resolveCredentialAlgorithmIdentifier,
} from '../algorithm.js';

const SECTION_STYLE = 'margin-bottom: 1.5rem;';
const HEADING_STYLE = 'color: #0072CE; margin-bottom: 0.5rem;';

function section(title, ...children) {
    return el('div', { style: SECTION_STYLE },
        el('h4', { style: HEADING_STYLE, text: title }),
        ...children,
    );
}

function codeBlock(text) {
    return el('div', { className: 'credential-code-block', text });
}

function identifierRows(value) {
    let bytes;
    try {
        bytes = base64UrlToBytes(value);
    } catch (error) {
        return [
            codeBlock(value),
            el('div', { style: 'font-style: italic; color: #6c757d;', text: 'Not valid base64url: shown as stored.' }),
        ];
    }
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return [
        el('div', {}, el('strong', { text: 'b64' })),
        codeBlock(bytesToBase64(bytes)),
        el('div', {}, el('strong', { text: 'b64u' })),
        codeBlock(bytesToBase64Url(bytes)),
        el('div', {}, el('strong', { text: 'hex' })),
        codeBlock(hex),
    ];
}

// An identifier the record keeps as base64url, shown in each spelling of its bytes.
function buildEncodedIdentifierSection({
    title,
    value,
}) {
    return el('div', { style: 'margin-top: 0.5rem;' },
        el('div', {}, el('strong', { text: title })),
        el('div', {
            style: "font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;",
        }, identifierRows(value)),
    );
}

export function buildUserInfoSection(cred, aaguidSection) {
    return section('User info at creation',
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            labelledLine('Name:', cred.userName || cred.email || 'N/A'),
            labelledLine('Display name:', cred.displayName || cred.userName || cred.email || 'N/A', {
                style: 'margin-bottom: 0.5rem;',
            }),
        ),
        cred.userHandle
            ? buildEncodedIdentifierSection({ title: 'User handle (User ID):', value: cred.userHandle })
            : null,
        cred.credentialId
            ? buildEncodedIdentifierSection({ title: 'Credential ID:', value: cred.credentialId })
            : null,
        aaguidSection,
    );
}

export function buildAttestationFormatSection(attestationFormatDisplay) {
    return section('Attestation Format',
        el('div', { style: 'font-size: 0.9rem;', text: attestationFormatDisplay }),
    );
}

const FLAG_NAMES = ['at', 'be', 'bs', 'ed', 'up', 'uv'];

export function buildAuthenticatorDataSection(cred) {
    if (!cred.flags) {
        return null;
    }

    const flagLine = el('div', {}, FLAG_NAMES.map((flag, index) => [
        index ? ', ' : null,
        el('strong', { text: `${flag.toUpperCase()}:` }),
        ` ${String(cred.flags[flag])}`,
    ]));

    return section('Authenticator Data (registration)',
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            flagLine,
            labelledLine('Signature Counter:', String(cred.signCount || 0)),
        ),
    );
}

export function buildExtensionsSection(cred) {
    if (!cred.clientExtensionOutputs || Object.keys(cred.clientExtensionOutputs).length === 0) {
        return null;
    }

    return section('Client extension outputs (registration)',
        el('div', {
            className: 'credential-code-block',
            style: 'font-size: 0.9rem; border-radius: 16px;',
            text: JSON.stringify(cred.clientExtensionOutputs, null, 2),
        }),
    );
}

export function buildPublicKeySection(cred) {
    const hasPublicKeyData = cred.publicKeyAlgorithm !== undefined
        || cred.algorithm !== undefined
        || (cred.publicKeyCose && Object.keys(cred.publicKeyCose).length > 0);

    if (!hasPublicKeyData) {
        return null;
    }

    const coseMap = cred.publicKeyCose || {};
    const resolvedAlgorithm = resolveCredentialAlgorithmIdentifier(cred);
    const fallbackAlgorithm = resolvedAlgorithm !== null
        ? resolvedAlgorithm
        : getCoseMapValue(coseMap, 3);

    const coseKeyTypeValue = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);
    const parameterSet = describeMldsaParameterSet(fallbackAlgorithm);

    return section('Public Key',
        el('div', { style: 'font-size: 0.9rem;' },
            labelledLine('Algorithm:', describeCoseAlgorithm(fallbackAlgorithm)),
            coseKeyTypeValue !== undefined && coseKeyTypeValue !== null
                ? labelledLine('COSE key type:', describeCoseKeyType(coseKeyTypeValue))
                : null,
            parameterSet ? labelledLine('ML-DSA parameter set:', parameterSet) : null,
        ),
    );
}

// The registration detail (registration-compose-runtime.js) goes in this
// container, or a note that there is none.
export function buildRegistrationDetailSection(registrationView) {
    return el('div', { className: 'credential-registration-copy' },
        registrationView || el('div', {
            style: 'font-style: italic; color: #6c757d;',
            text: 'Registration detail data is not available for this credential.',
        }),
    );
}
