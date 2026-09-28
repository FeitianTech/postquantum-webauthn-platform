// The current UI's registration view: DOM built from ./registration-view.js's
// data over its one state (./state.js), the certificates and the authenticator
// data opened in a second modal.
import {closeModal, openModal} from '../../shared/ui/core.js';
import {el, fragment} from '../../shared/ui/dom.js';
import {autoResizeCertificateTextareas} from './formatting.js';
import {decodePayloadThroughApi} from './decode-payload.js';
import {
    composeRegistration,
    describeAttestationCertificate,
    describeAttestationSection,
    describeAuthenticatorData,
    REGISTRATION_TEXT,
} from './registration-view.js';
import {
    registrationDetailState,
} from './state.js';

const SECTION_STYLE = 'margin-bottom: 1.5rem;';
const SECTION_HEADING_STYLE = 'color: #0072CE; margin-bottom: 0.75rem;';
const PLACEHOLDER_STYLE = 'font-style: italic; color: #6c757d;';
const ERROR_STYLE = 'color: #dc3545; font-size: 0.9rem;';

function placeholder(text, extraStyle = '') {
    return el('div', { style: `${PLACEHOLDER_STYLE}${extraStyle}`, text });
}

function preformatted(text) {
    return el('pre', { className: 'modal-pre', text });
}

function certificateButton(label, displayIndex) {
    const button = el('button', {
        className: 'btn btn-small registration-attestation-cert-button',
        attrs: { type: 'button' },
        dataset: { certIndex: displayIndex },
        text: label,
    });
    button.addEventListener('click', event => {
        event.preventDefault();
        openAttestationCertificateDetail(displayIndex);
    });
    return button;
}

function authenticatorDataButton() {
    const button = el('button', {
        className: 'btn btn-small btn-secondary registration-authenticator-data-button',
        attrs: { type: 'button' },
        text: REGISTRATION_TEXT.authenticatorData,
    });
    button.addEventListener('click', event => {
        event.preventDefault();
        openAuthenticatorDataDetail();
    });
    return button;
}

function attestationBody(body) {
    if (body.kind === 'json') {
        return certificateTextarea(body.text);
    }
    if (body.kind === 'error') {
        return el('div', { style: ERROR_STYLE, text: body.text });
    }
    return placeholder(body.text);
}

function renderAttestationSection(section) {
    if (!section) {
        return null;
    }

    const buttons = section.certificates.map(certificate => certificateButton(certificate.title, certificate.index));
    if (section.hasAuthenticatorData) {
        buttons.push(authenticatorDataButton());
    }

    return el('section', { style: SECTION_STYLE },
        el('h3', { style: SECTION_HEADING_STYLE, text: REGISTRATION_TEXT.attestationTitle }),
        el('div', { style: 'margin-bottom: 0.75rem;' },
            el('h4', {
                style: 'font-weight: 600; color: #0f2740; margin-bottom: 0.5rem;',
                text: REGISTRATION_TEXT.attestationObject,
            }),
            attestationBody(section.body),
        ),
        buttons.length ? el('div', { className: 'registration-detail-button-row' }, buttons) : null,
        section.certificateMessage ? placeholder(section.certificateMessage, ' margin-top: 0.75rem;') : null,
        section.authenticatorError
            ? el('div', { style: `${ERROR_STYLE} margin-top: 0.75rem;`, text: section.authenticatorError })
            : null,
    );
}

export function buildAttestationSection(options = {}) {
    return renderAttestationSection(describeAttestationSection(registrationDetailState, options));
}

function buildResponseSections(response) {
    return [
        el('section', { style: SECTION_STYLE },
            el('h3', { style: SECTION_HEADING_STYLE, text: REGISTRATION_TEXT.responseTitle }),
            el('ol', { style: 'padding-left: 1.25rem; margin: 0;' },
                el('li', { style: 'margin-bottom: 1rem;' },
                    el('div', {
                        style: 'font-weight: 600; margin-bottom: 0.5rem;',
                        text: REGISTRATION_TEXT.createResponse,
                    }),
                    response.credential
                        ? preformatted(response.credential)
                        : placeholder(REGISTRATION_TEXT.noCredentialResponse),
                ),
                el('li', {},
                    el('div', { style: 'font-weight: 600; margin-bottom: 0.5rem;', text: REGISTRATION_TEXT.parsedClientData }),
                    response.clientData
                        ? preformatted(response.clientData)
                        : placeholder(REGISTRATION_TEXT.noClientData),
                ),
            ),
        ),
        el('section', { style: SECTION_STYLE },
            el('h3', { style: SECTION_HEADING_STYLE, text: REGISTRATION_TEXT.serverDataTitle }),
            response.relyingParty
                ? preformatted(response.relyingParty)
                : placeholder(REGISTRATION_TEXT.noRelyingParty),
        ),
    ];
}

/**
 * The registration's detail view, built from data: the browser's response, the
 * client data, the relying party's view and the attestation. Returns the view as
 * a fragment of fresh nodes, with the state the snapshot keeps and the relying
 * party view it showed.
 */
export async function composeRegistrationDetail(options = {}) {
    const composed = await composeRegistration(options, {
        state: registrationDetailState,
        decode: decodePayloadThroughApi,
    });
    return {
        view: fragment(buildResponseSections(composed.response), renderAttestationSection(composed.attestation)),
        stateSnapshot: composed.stateSnapshot,
        relyingPartyCopy: composed.relyingPartyCopy,
    };
}

export function certificateTextarea(text) {
    return el('textarea', {
        className: 'certificate-textarea',
        attrs: { readonly: true, spellcheck: 'false', wrap: 'soft' },
        text,
    });
}

function openRegistrationDetailModal(title, body) {
    const modal = document.getElementById('registrationDetailModal');
    const titleEl = document.getElementById('registrationDetailModalTitle');
    const bodyEl = document.getElementById('registrationDetailModalBody');
    if (!modal || !titleEl || !bodyEl) {
        return;
    }

    titleEl.textContent = title;
    bodyEl.replaceChildren(body);
    openModal('registrationDetailModal');

    const resize = () => autoResizeCertificateTextareas(bodyEl);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(resize);
    } else {
        setTimeout(resize, 0);
    }
}

export function openAttestationCertificateDetail(index) {
    const view = describeAttestationCertificate(registrationDetailState, index);
    if (!view) {
        return;
    }

    let body;
    if (view.text) {
        body = certificateTextarea(view.text);
    } else if (view.error) {
        body = el('div', { style: 'color: #dc3545; font-size: 0.9rem;', text: view.error });
    } else {
        body = el('div', {
            style: 'font-style: italic; color: #6c757d;',
            text: view.placeholder,
        });
    }

    openRegistrationDetailModal(view.title, body);
}

export function openAuthenticatorDataDetail() {
    const view = describeAuthenticatorData(registrationDetailState);
    if (!view) {
        return;
    }

    openRegistrationDetailModal(view.title, certificateTextarea(view.text));
}

export function closeRegistrationDetailModalRuntime() {
    closeModal('registrationDetailModal');
}
