import { state } from '../../shared/state.js';
import { sortObjectKeys } from '../../shared/binary-utils.js';
import { showStatus } from '../../shared/status.js';
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
import {
    validateAuthenticationPublicKey,
} from './validation-authentication.js';
import { validateRegistrationPublicKey } from './validation-registration.js';

function buildOptionsForCurrentScope(scope) {
    if (scope === 'authentication') {
        return getCredentialRequestOptions();
    }
    return getCredentialCreationOptions();
}

function mergeParsedJsonWithForm(parsedRoot, scope) {
    const latestOptions = buildOptionsForCurrentScope(scope);
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

export function updateJsonEditor() {
    let options = {};
    let title = 'JSON Editor';

    if (state.currentSubTab === 'registration') {
        options = getCredentialCreationOptions();
        title = 'JSON Editor (CredentialCreationOptions)';
    } else if (state.currentSubTab === 'authentication') {
        options = getCredentialRequestOptions();
        title = 'JSON Editor (CredentialRequestOptions)';
    }

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));

    const titleElement = document.querySelector('.json-editor-column h3');
    if (titleElement) {
        titleElement.textContent = title;
    }
}

export function saveJsonEditor() {
    try {
        const editor = document.getElementById('json-editor');
        const jsonText = editor ? editor.value : '';
        const parsed = JSON.parse(jsonText || '{}');

        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('Invalid JSON structure.');
        }

        if (!parsed.publicKey || typeof parsed.publicKey !== 'object') {
            throw new Error('Invalid JSON structure: Missing "publicKey" object.');
        }

        const scope = state.currentSubTab === 'authentication' ? 'authentication' : 'registration';

        if (scope === 'registration') {
            validateRegistrationPublicKey(parsed.publicKey);
            updateRegistrationFormFromJson(parsed.publicKey);
        } else {
            validateAuthenticationPublicKey(parsed.publicKey);
            updateAuthenticationFormFromJson(parsed.publicKey);
        }

        const merged = mergeParsedJsonWithForm(parsed, scope);
        const sorted = sortObjectKeys(merged);
        setJsonEditorContent(JSON.stringify(sorted, null, 2));

        showStatus('advanced', 'JSON changes saved successfully!', 'success');
    } catch (error) {
        showStatus('advanced', `JSON validation failed: ${error.message}`, 'error');
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
        const merged = mergeParsedJsonWithForm(parsed, scope);
        const sorted = sortObjectKeys(merged);
        setJsonEditorContent(JSON.stringify(sorted, null, 2));
        showStatus('advanced', 'JSON editor reset to current settings.', 'info');
    } catch (error) {
        showStatus('advanced', `Unable to reset JSON editor: ${error.message}`, 'error');
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
