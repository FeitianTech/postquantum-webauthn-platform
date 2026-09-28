import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
} from '../../ui/display-utils.js';
import {el} from '../../../shared/ui/dom.js';
import {labelledLine} from '../detail-nodes.js';
import {
    DETAIL_TEXT,
    describeAttestationFormat,
    describeAuthenticatorDataFlags,
    describeExtensions,
    describePublicKey,
    describeUserInfo,
} from './detail-sections.js';

// The current UI's sections of a credential's details, each built from
// ./detail-sections.js's data (render...), or from the record (build...).

const SECTION_STYLE = 'margin-bottom: 1.5rem;';
const HEADING_STYLE = 'color: #0072CE; margin-bottom: 0.5rem;';

export const COSE_DESCRIBERS = Object.freeze({
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
});

function section(title, ...children) {
    return el('div', { style: SECTION_STYLE },
        el('h4', { style: HEADING_STYLE, text: title }),
        ...children,
    );
}

function codeBlock(text) {
    return el('div', { className: 'credential-code-block', text });
}

function identifierRows(identifier) {
    if (!identifier.spellings) {
        return [
            codeBlock(identifier.stored),
            el('div', { style: 'font-style: italic; color: #6c757d;', text: identifier.note }),
        ];
    }
    return identifier.spellings.flatMap(spelling => [
        el('div', {}, el('strong', { text: spelling.label })),
        codeBlock(spelling.value),
    ]);
}

// An identifier the record keeps as base64url, shown in each spelling of its bytes.
function buildEncodedIdentifierSection(identifier) {
    return el('div', { style: 'margin-top: 0.5rem;' },
        el('div', {}, el('strong', { text: identifier.title })),
        el('div', {
            style: "font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;",
        }, identifierRows(identifier)),
    );
}

export function renderUserInfoSection(userInfo, aaguidSection) {
    return section(userInfo.title,
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            labelledLine(DETAIL_TEXT.name, userInfo.name),
            labelledLine(DETAIL_TEXT.displayName, userInfo.displayName, {
                style: 'margin-bottom: 0.5rem;',
            }),
        ),
        ...userInfo.identifiers.map(buildEncodedIdentifierSection),
        aaguidSection,
    );
}

export function buildUserInfoSection(cred, aaguidSection) {
    return renderUserInfoSection(describeUserInfo(cred), aaguidSection);
}

export function renderAttestationFormatSection(format) {
    return section(format.title,
        el('div', { style: 'font-size: 0.9rem;', text: format.value }),
    );
}

export function buildAttestationFormatSection(attestationFormatDisplay) {
    return renderAttestationFormatSection(describeAttestationFormat(attestationFormatDisplay));
}

export function renderAuthenticatorDataSection(authenticatorData) {
    if (!authenticatorData) {
        return null;
    }

    const flagLine = el('div', {}, authenticatorData.flags.map((flag, index) => [
        index ? ', ' : null,
        el('strong', { text: `${flag.name}:` }),
        ` ${flag.value}`,
    ]));

    return section(authenticatorData.title,
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            flagLine,
            labelledLine(DETAIL_TEXT.signatureCounter, authenticatorData.counter),
        ),
    );
}

export function buildAuthenticatorDataSection(cred) {
    return renderAuthenticatorDataSection(describeAuthenticatorDataFlags(cred));
}

export function renderExtensionsSection(extensions) {
    if (!extensions) {
        return null;
    }

    return section(extensions.title,
        el('div', {
            className: 'credential-code-block',
            style: 'font-size: 0.9rem; border-radius: 16px;',
            text: extensions.text,
        }),
    );
}

export function buildExtensionsSection(cred) {
    return renderExtensionsSection(describeExtensions(cred));
}

export function renderPublicKeySection(publicKey) {
    if (!publicKey) {
        return null;
    }

    return section(publicKey.title,
        el('div', { style: 'font-size: 0.9rem;' },
            publicKey.lines.map(line => labelledLine(line.label, line.value)),
        ),
    );
}

export function buildPublicKeySection(cred) {
    return renderPublicKeySection(describePublicKey(cred, COSE_DESCRIBERS));
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
