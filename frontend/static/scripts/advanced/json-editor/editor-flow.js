import { state } from '../../shared/state.js';
import { sortObjectKeys } from '../../shared/utils/binary.js';
import { showStatus } from '../../shared/ui/status.js';
import {
    getAdvancedAssertOptions,
    getAdvancedCreateOptions,
} from './advanced-options.js';
import { dispatchChangeEvent } from './dom-helpers.js';
import {
    updateAuthenticationFormFromJson,
    updateRegistrationFormFromJson,
} from './form-sync.js';
import {
    mergePublicKey,
    pruneUnsupportedProperties,
} from './merge-prune.js';
import {
    getCredentialCreationOptions,
} from './creation-options.js';
import { getCredentialRequestOptions } from './request-options.js';
import { isPlainObject } from './schema.js';
import { followForm } from './request-patch.js';
import {
    validateAuthenticationPublicKey,
} from './validation-authentication.js';
import { validateRegistrationPublicKey } from './validation-registration.js';
import {
    EDITOR_TEXT,
    editorTitle,
    parseEditorRequest,
    requestText,
    resetFailedText,
    validationFailedText,
} from './editor-model.js';

function buildOptionsForCurrentScope(scope) {
    if (scope === 'authentication') {
        return getCredentialRequestOptions();
    }
    return getCredentialCreationOptions();
}

function mergeParsedJsonWithForm(parsedRoot, scope, latestOptions) {
    const latestPublicKey = latestOptions?.publicKey || {};

    if (!isPlainObject(parsedRoot)) {
        return latestOptions;
    }

    const merged = { ...parsedRoot };

    Object.keys(latestOptions).forEach(key => {
        if (key === 'publicKey') {
            merged.publicKey = mergePublicKey(parsedRoot.publicKey, latestPublicKey, scope);
            pruneUnsupportedProperties(merged.publicKey, scope);
        } else {
            merged[key] = latestOptions[key];
        }
    });

    return merged;
}

function setJsonEditorContent(content) {
    const jsonEditor = document.getElementById('json-editor');
    if (!jsonEditor) {
        return;
    }

    jsonEditor.value = content;
    jsonEditor.scrollTop = 0;
    jsonEditor.scrollLeft = 0;
}

// The form's request the editor's text last followed, and for which sub-tab.
let formRequest = null;

// Rewrites in the editor what the form's request changed since the text last
// followed it (./request-patch.js), keeping the rest as typed; on another
// sub-tab, or with nothing followed yet, the form's request.
export function updateJsonEditor() {
    let options = {};
    const scope = state.currentSubTab;

    if (scope === 'registration') {
        options = getCredentialCreationOptions();
    } else if (scope === 'authentication') {
        options = getCredentialRequestOptions();
    }

    const editor = document.getElementById('json-editor');
    const followed = formRequest && formRequest.scope === scope && editor
        ? followForm(editor.value, formRequest.request, options)
        : requestText(options);
    formRequest = { scope, request: options };
    setJsonEditorContent(followed);

    const titleElement = document.querySelector('.json-editor-column h3');
    if (titleElement) {
        titleElement.textContent = editorTitle(state.currentSubTab);
    }
}

/** The editor's text rebuilt from the form, whatever it held (a reset, a switch). */
export function rebuildJsonEditor() {
    formRequest = null;
    updateJsonEditor();
}

export function saveJsonEditor() {
    try {
        const editor = document.getElementById('json-editor');
        const parsed = parseEditorRequest(editor ? editor.value : '');

        const scope = state.currentSubTab === 'authentication' ? 'authentication' : 'registration';

        if (scope === 'registration') {
            validateRegistrationPublicKey(parsed.publicKey);
            updateRegistrationFormFromJson(parsed.publicKey);
        } else {
            validateAuthenticationPublicKey(parsed.publicKey);
            updateAuthenticationFormFromJson(parsed.publicKey);
        }

        const latestOptions = buildOptionsForCurrentScope(scope);
        const followed = { scope, request: JSON.parse(JSON.stringify(latestOptions)) };
        setJsonEditorContent(requestText(mergeParsedJsonWithForm(parsed, scope, latestOptions)));
        formRequest = followed;

        showStatus('advanced', EDITOR_TEXT.saved, 'success');
    } catch (error) {
        showStatus('advanced', validationFailedText(error.message), 'error');
    }
}

export function resetJsonEditor() {
    const scope = state.currentSubTab === 'authentication' ? 'authentication' : 'registration';
    const editor = document.getElementById('json-editor');
    let parsed = null;

    if (editor && editor.value) {
        try {
            parsed = JSON.parse(editor.value);
        } catch (error) {
            parsed = null;
        }
    }

    try {
        const latestOptions = buildOptionsForCurrentScope(scope);
        const followed = { scope, request: JSON.parse(JSON.stringify(latestOptions)) };
        setJsonEditorContent(requestText(mergeParsedJsonWithForm(parsed, scope, latestOptions)));
        formRequest = followed;
        showStatus('advanced', EDITOR_TEXT.reset, 'info');
    } catch (error) {
        showStatus('advanced', resetFailedText(error.message), 'error');
    }
}

export function editCreateOptions() {
    const options = getAdvancedCreateOptions();
    state.currentJsonMode = 'create';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function editAssertOptions() {
    const options = getAdvancedAssertOptions();
    state.currentJsonMode = 'assert';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function applyJsonChanges() {
    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (state.currentJsonMode === 'create') {
            if (parsed.username) {
                document.getElementById('user-name').value = parsed.username;
            }
            if (parsed.displayName) {
                document.getElementById('user-display-name').value = parsed.displayName;
            }
            if (Object.prototype.hasOwnProperty.call(parsed, 'attestation')) {
                document.getElementById('attestation').value = parsed.attestation || 'direct';
            }
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-reg').value = parsed.userVerification || 'preferred';
            }
            if (parsed.residentKey) {
                document.getElementById('resident-key').value = parsed.residentKey;
            }
            if (Object.prototype.hasOwnProperty.call(parsed, 'authenticatorAttachment')) {
                const attachmentSelect = document.getElementById('authenticator-attachment');
                if (attachmentSelect) {
                    const rawValue = parsed.authenticatorAttachment;
                    const normalized = rawValue === 'platform' || rawValue === 'cross-platform' || rawValue === 'unspecified'
                        ? rawValue
                        : 'cross-platform';
                    attachmentSelect.value = normalized;
                    dispatchChangeEvent(attachmentSelect);
                }
            }
        } else if (state.currentJsonMode === 'assert') {
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-auth').value = parsed.userVerification || 'preferred';
            }
        }

        showStatus('advanced', 'JSON changes applied successfully!', 'success');
        cancelJsonEdit();
    } catch (error) {
        showStatus('advanced', `Invalid JSON: ${error.message}`, 'error');
    }
}

export function cancelJsonEdit() {
    setJsonEditorContent('');
    document.getElementById('apply-json').style.display = 'none';
    document.getElementById('cancel-json').style.display = 'none';
    state.currentJsonMode = null;
    state.currentJsonData = {};
}

export function updateJsonFromForm() {
    if (state.currentJsonMode) {
        if (state.currentJsonMode === 'create') {
            const options = getAdvancedCreateOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        } else if (state.currentJsonMode === 'assert') {
            const options = getAdvancedAssertOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        }
    }
}
