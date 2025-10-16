import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from './shared/webauthn-json.browser-ponyfill.js';
import {
    initializeLoader,
    loaderIsActive,
    loaderSetPhase,
    loaderSetProgress
} from './shared/loader.js';
import {
    switchTab,
    switchSubTab,
    toggleSection
} from './shared/navigation.js';
import {
    showInfoPopup,
    hideInfoPopup,
    toggleLanguage,
    toggleJsonEditorExpansion,
    updateGlobalScrollLock,
    closeModal
} from './shared/ui.js';
import {
    updateFieldLabels,
    randomizeChallenge,
    randomizePrfEval,
    randomizeLargeBlobWrite,
    validatePrfInputs,
    validateUserIdInput,
    validateChallengeInputs,
    validatePrfEvalInputs,
    validateLargeBlobWriteInput,
    checkLargeBlobCapability,
    updateAuthenticationExtensionAvailability
} from './advanced/forms.js';
import {
    resetRegistrationForm,
    resetAuthenticationForm
} from './advanced/resets.js';
import { initializeSimpleUsername, randomizeUserIdentity, randomizeSimpleUsername } from './shared/username.js';
import {
    simpleRegister,
    simpleAuthenticate
} from './simple/auth-simple.js';
import {
    advancedRegister,
    advancedAuthenticate
} from './advanced/auth-advanced.js';
import {
    processCodec,
    clearCodec,
    toggleRawCodec,
    switchCodecMode
} from './decoder/codec.js';
import {
    saveJsonEditor,
    resetJsonEditor,
    updateJsonEditor,
    updateJsonFromForm,
    editCreateOptions,
    editAssertOptions,
    applyJsonChanges,
    cancelJsonEdit
} from './advanced/json-editor.js';
import {
    loadSavedCredentials,
    showCredentialDetails,
    navigateToMdsAuthenticator,
    closeCredentialModal,
    closeRegistrationResultModal,
    closeRegistrationDetailModal,
    deleteCredential,
    clearAllCredentials,
    updateAllowCredentialsDropdown
} from './advanced/credential-display.js';
import { registerHintsChangeCallback } from './advanced/hints.js';
import { handleJsonEditorKeydown } from './advanced/json-editor-utils.js';
import {
    createFakeExcludeCredential,
    removeFakeExcludeCredential,
    renderFakeExcludeCredentialList,
    createFakeAllowCredential,
    removeFakeAllowCredential,
    renderFakeAllowCredentialList
} from './advanced/exclude-credentials.js';

registerHintsChangeCallback(() => updateAllowCredentialsDropdown());

window.create = create;
window.get = get;
window.parseCreationOptionsFromJSON = parseCreationOptionsFromJSON;
window.parseRequestOptionsFromJSON = parseRequestOptionsFromJSON;

window.switchTab = switchTab;
window.updateGlobalScrollLock = updateGlobalScrollLock;
window.switchSubTab = switchSubTab;
window.toggleSection = toggleSection;
window.showInfoPopup = showInfoPopup;
window.hideInfoPopup = hideInfoPopup;
window.toggleLanguage = toggleLanguage;
window.randomizeChallenge = randomizeChallenge;
window.randomizePrfEval = randomizePrfEval;
window.randomizeLargeBlobWrite = randomizeLargeBlobWrite;
window.resetRegistrationForm = resetRegistrationForm;
window.resetAuthenticationForm = resetAuthenticationForm;
window.randomizeUserIdentity = randomizeUserIdentity;
window.randomizeSimpleUsername = randomizeSimpleUsername;
window.simpleRegister = simpleRegister;
window.simpleAuthenticate = simpleAuthenticate;
window.advancedRegister = advancedRegister;
window.advancedAuthenticate = advancedAuthenticate;
window.processCodec = processCodec;
window.clearCodec = clearCodec;
window.toggleRawCodec = toggleRawCodec;
window.clearDecoder = clearCodec;
window.toggleRawDecoder = toggleRawCodec;
window.closeModal = closeModal;
window.switchCodecMode = switchCodecMode;
window.saveJsonEditor = saveJsonEditor;
window.resetJsonEditor = resetJsonEditor;
window.showCredentialDetails = showCredentialDetails;
window.navigateToMdsAuthenticator = navigateToMdsAuthenticator;
window.closeCredentialModal = closeCredentialModal;
window.closeRegistrationResultModal = closeRegistrationResultModal;
window.closeRegistrationDetailModal = closeRegistrationDetailModal;
window.deleteCredential = deleteCredential;
window.clearAllCredentials = clearAllCredentials;
window.editCreateOptions = editCreateOptions;
window.editAssertOptions = editAssertOptions;
window.applyJsonChanges = applyJsonChanges;
window.cancelJsonEdit = cancelJsonEdit;

document.addEventListener('DOMContentLoaded', () => {
    initializeLoader();
    loaderSetPhase('Preparing application…', { progress: 8 });

    updateFieldLabels();

    const jsonEditorElement = document.getElementById('json-editor');
    if (jsonEditorElement) {
        jsonEditorElement.setAttribute('spellcheck', 'false');
        jsonEditorElement.setAttribute('autocorrect', 'off');
        jsonEditorElement.setAttribute('autocapitalize', 'off');
        jsonEditorElement.setAttribute('autocomplete', 'off');
        jsonEditorElement.setAttribute('data-gramm', 'false');
        jsonEditorElement.setAttribute('data-gramm_editor', 'false');
        jsonEditorElement.setAttribute('data-enable-grammarly', 'false');
    }

    setTimeout(() => {
        randomizeUserIdentity();
        randomizeChallenge('reg');
        randomizeChallenge('auth');
        randomizeLargeBlobWrite();
        initializeSimpleUsername();
        const prfRegFirst = document.getElementById('prf-eval-first-reg');
        const prfRegSecond = document.getElementById('prf-eval-second-reg');
        const prfAuthFirst = document.getElementById('prf-eval-first-auth');
        const prfAuthSecond = document.getElementById('prf-eval-second-auth');
        if (prfRegFirst) prfRegFirst.value = '';
        if (prfRegSecond) {
            prfRegSecond.value = '';
            prfRegSecond.disabled = true;
        }
        if (prfAuthFirst) prfAuthFirst.value = '';
        if (prfAuthSecond) {
            prfAuthSecond.value = '';
            prfAuthSecond.disabled = true;
        }

        loadSavedCredentials();
        updateJsonEditor();
        renderFakeExcludeCredentialList();
        renderFakeAllowCredentialList();
        updateAuthenticationExtensionAvailability();

        if (loaderIsActive()) {
            loaderSetProgress(18);
        }
    }, 100);

    setTimeout(() => {
        const allInputs = document.querySelectorAll('#advanced-tab input, #advanced-tab select, #advanced-tab input[type="checkbox"]');
        allInputs.forEach(input => {
            input.addEventListener('input', updateJsonEditor);
            input.addEventListener('change', updateJsonEditor);
        });

        const attachmentSelect = document.getElementById('authenticator-attachment');
        if (attachmentSelect) {
            attachmentSelect.addEventListener('change', () => {
                updateAllowCredentialsDropdown();
            });
        }

        const registrationHintCheckboxes = ['hint-client-device', 'hint-hybrid', 'hint-security-key'];
        registrationHintCheckboxes.forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.addEventListener('change', () => {
                    updateAllowCredentialsDropdown();
                });
            }
        });

        const usernameInput = document.getElementById('user-name');
        const displayNameInput = document.getElementById('user-display-name');
        if (usernameInput && displayNameInput) {
            usernameInput.addEventListener('input', () => {
                displayNameInput.value = usernameInput.value;
                updateJsonEditor();
            });
        }

        const largeBlobSelect = document.getElementById('large-blob-auth');
        if (largeBlobSelect) {
            largeBlobSelect.addEventListener('change', () => {
                updateAuthenticationExtensionAvailability();
                updateJsonEditor();
            });
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            const handleCredProtectToggle = () => {
                if (credProtectSelect.value) {
                    enforceCredProtectCheckbox.disabled = false;
                } else {
                    enforceCredProtectCheckbox.checked = true;
                    enforceCredProtectCheckbox.disabled = true;
                }
            };
            credProtectSelect.addEventListener('change', handleCredProtectToggle);
            handleCredProtectToggle();
        }

        const allowCredentialsSelect = document.getElementById('allow-credentials');
        if (allowCredentialsSelect) {
            allowCredentialsSelect.addEventListener('change', () => {
                updateAuthenticationExtensionAvailability();
                updateJsonEditor();
            });
        }

        const residentKeySelect = document.getElementById('resident-key');
        const largeBlobRegSelect = document.getElementById('large-blob-reg');
        if (residentKeySelect && largeBlobRegSelect) {
            residentKeySelect.addEventListener('change', () => {
                const residentKey = residentKeySelect.value;
                if (residentKey !== 'required') {
                    const largeBlobValue = largeBlobRegSelect.value;
                    if (largeBlobValue === 'preferred' || largeBlobValue === 'required') {
                        largeBlobRegSelect.value = '';
                    }
                }
                updateJsonEditor();
            });
        }

        const fakeCredentialButton = document.getElementById('fake-cred-generate');
        if (fakeCredentialButton) {
            fakeCredentialButton.addEventListener('click', () => {
                const lengthInput = document.getElementById('fake-cred-length-reg');
                const lengthValue = lengthInput ? lengthInput.value : '';
                const created = createFakeExcludeCredential(lengthValue);
                if (created) {
                    updateJsonEditor();
                }
            });
        }

        const fakeCredentialList = document.getElementById('fake-cred-generated-list');
        if (fakeCredentialList) {
            fakeCredentialList.addEventListener('click', event => {
                const button = event.target instanceof HTMLElement
                    ? event.target.closest('button[data-fake-credential-index]')
                    : null;
                if (!button) {
                    return;
                }
                event.preventDefault();
                const removed = removeFakeExcludeCredential(button.dataset.fakeCredentialIndex);
                if (removed) {
                    updateJsonEditor();
                }
            });
        }

        const fakeAllowButton = document.getElementById('fake-cred-generate-auth');
        if (fakeAllowButton) {
            fakeAllowButton.addEventListener('click', () => {
                const lengthInput = document.getElementById('fake-cred-length-auth');
                const lengthValue = lengthInput ? lengthInput.value : '';
                const created = createFakeAllowCredential(lengthValue);
                if (created) {
                    updateJsonEditor();
                }
            });
        }

        const fakeAllowList = document.getElementById('fake-cred-auth-generated-list');
        if (fakeAllowList) {
            fakeAllowList.addEventListener('click', event => {
                const button = event.target instanceof HTMLElement
                    ? event.target.closest('button[data-fake-credential-index]')
                    : null;
                if (!button) {
                    return;
                }
                event.preventDefault();
                const removed = removeFakeAllowCredential(button.dataset.fakeCredentialIndex);
                if (removed) {
                    updateJsonEditor();
                }
            });
        }

        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    closeModal(modal.id);
                }
            });
        });

        const prfFirstInputs = ['prf-eval-first-reg', 'prf-eval-first-auth'];
        prfFirstInputs.forEach(inputId => {
            const input = document.getElementById(inputId);
            if (input) {
                input.addEventListener('input', () => {
                    const formType = inputId.includes('reg') ? 'reg' : 'auth';
                    validatePrfInputs(formType);
                    validatePrfEvalInputs();
                });
                input.addEventListener('change', () => {
                    const formType = inputId.includes('reg') ? 'reg' : 'auth';
                    validatePrfInputs(formType);
                    validatePrfEvalInputs();
                });
            }
        });

        const hexInputs = [
            'user-id', 'challenge-reg', 'challenge-auth',
            'prf-eval-first-reg', 'prf-eval-second-reg',
            'prf-eval-first-auth', 'prf-eval-second-auth',
            'large-blob-write'
        ];
        hexInputs.forEach(inputId => {
            const input = document.getElementById(inputId);
            if (input) {
                input.addEventListener('input', () => {
                    if (inputId === 'user-id') validateUserIdInput();
                    else if (inputId.includes('challenge')) validateChallengeInputs();
                    else if (inputId.includes('prf-eval')) validatePrfEvalInputs();
                    else if (inputId === 'large-blob-write') validateLargeBlobWriteInput();
                });
                input.addEventListener('blur', () => {
                    if (inputId === 'user-id') validateUserIdInput();
                    else if (inputId.includes('challenge')) validateChallengeInputs();
                    else if (inputId.includes('prf-eval')) validatePrfEvalInputs();
                    else if (inputId === 'large-blob-write') validateLargeBlobWriteInput();
                });
            }
        });

        if (jsonEditorElement) {
            jsonEditorElement.addEventListener('click', () => {
                const container = document.getElementById('json-editor-container');
                if (container && !container.classList.contains('expanded')) {
                    toggleJsonEditorExpansion();
                }
            });
            jsonEditorElement.addEventListener('focus', () => {
                const container = document.getElementById('json-editor-container');
                if (container && !container.classList.contains('expanded')) {
                    toggleJsonEditorExpansion();
                }
            });
            jsonEditorElement.addEventListener('keydown', handleJsonEditorKeydown);
        }

        const jsonEditorCloseButton = document.getElementById('json-editor-close');
        if (jsonEditorCloseButton) {
            jsonEditorCloseButton.addEventListener('click', () => toggleJsonEditorExpansion(true));
        }

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                const container = document.getElementById('json-editor-container');
                if (container?.classList.contains('expanded')) {
                    toggleJsonEditorExpansion(true);
                }
            }
        });

        if (loaderIsActive()) {
            loaderSetProgress(26);
        }
    }, 100);

    setTimeout(() => {
        updateJsonEditor();
        if (loaderIsActive()) {
            loaderSetProgress(32);
        }
    }, 200);
    setTimeout(() => {
        loadSavedCredentials();
        if (loaderIsActive()) {
            loaderSetProgress(38);
        }
    }, 300);
    setTimeout(() => {
        checkLargeBlobCapability();
        if (loaderIsActive()) {
            loaderSetProgress(44);
        }
    }, 500);

    const formFields = [
        'user-name', 'user-display-name', 'attestation',
        'user-verification-reg', 'resident-key',
        'user-verification-auth'
    ];

    formFields.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field) {
            field.addEventListener('input', updateJsonFromForm);
            field.addEventListener('change', updateJsonFromForm);
        }
    });
});
