import {
    create,
    get,
    parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON
} from './webauthn-json.browser-ponyfill.js';
import {
    switchTab,
    switchSubTab,
    toggleSection
} from './navigation.js';
import {
    showInfoPopup,
    hideInfoPopup,
    toggleLanguage,
    toggleJsonEditorExpansion,
    updateGlobalScrollLock,
    closeModal
} from './ui.js';
import {
    changeBinaryFormat,
    updateFieldLabels,
    randomizeUserId,
    randomizeChallenge,
    randomizePrfEval,
    randomizeLargeBlobWrite,
    validatePrfInputs,
    validateUserIdInput,
    validateChallengeInputs,
    validatePrfEvalInputs,
    validateLargeBlobWriteInput,
    checkLargeBlobCapability
} from './forms.js';
import {
    resetRegistrationForm,
    resetAuthenticationForm
} from './resets.js';
import {
    randomizeUsername,
    generateRandom10DigitUsername
} from './username.js';
import {
    simpleRegister,
    simpleAuthenticate
} from '../simple-auth/auth-simple.js';
import {
    advancedRegister,
    advancedAuthenticate
} from './auth-advanced.js';
import {
    decodeResponse,
    clearDecoder
} from '../decoder/decoder.js';
import {
    saveJsonEditor,
    resetJsonEditor,
    updateJsonEditor,
    updateJsonFromForm,
    editCreateOptions,
    editAssertOptions,
    applyJsonChanges,
    cancelJsonEdit
} from './json-editor.js';
import {
    loadSavedCredentials,
    showCredentialDetails,
    navigateToMdsAuthenticator,
    closeCredentialModal,
    closeRegistrationResultModal,
    deleteCredential
} from './credential-display.js';
import { handleJsonEditorKeydown } from './json-editor-utils.js';

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
window.randomizeUserId = randomizeUserId;
window.randomizeChallenge = randomizeChallenge;
window.randomizePrfEval = randomizePrfEval;
window.randomizeLargeBlobWrite = randomizeLargeBlobWrite;
window.resetRegistrationForm = resetRegistrationForm;
window.resetAuthenticationForm = resetAuthenticationForm;
window.randomizeUsername = randomizeUsername;
window.simpleRegister = simpleRegister;
window.simpleAuthenticate = simpleAuthenticate;
window.advancedRegister = advancedRegister;
window.advancedAuthenticate = advancedAuthenticate;
window.decodeResponse = decodeResponse;
window.clearDecoder = clearDecoder;
window.changeBinaryFormat = changeBinaryFormat;
window.saveJsonEditor = saveJsonEditor;
window.resetJsonEditor = resetJsonEditor;
window.showCredentialDetails = showCredentialDetails;
window.navigateToMdsAuthenticator = navigateToMdsAuthenticator;
window.closeCredentialModal = closeCredentialModal;
window.closeRegistrationResultModal = closeRegistrationResultModal;
window.deleteCredential = deleteCredential;
window.editCreateOptions = editCreateOptions;
window.editAssertOptions = editAssertOptions;
window.applyJsonChanges = applyJsonChanges;
window.cancelJsonEdit = cancelJsonEdit;

document.addEventListener('DOMContentLoaded', () => {
    window.currentBinaryFormat = 'hex';
    updateFieldLabels('hex');

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
        randomizeUserId();
        const randomUsername = generateRandom10DigitUsername();
        const userName = document.getElementById('user-name');
        const displayName = document.getElementById('user-display-name');
        if (userName) userName.value = randomUsername;
        if (displayName) displayName.value = randomUsername;
        randomizeChallenge('reg');
        randomizeChallenge('auth');
        randomizeLargeBlobWrite();
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
    }, 100);

    setTimeout(() => {
        const allInputs = document.querySelectorAll('#advanced-tab input, #advanced-tab select, #advanced-tab input[type="checkbox"]');
        allInputs.forEach(input => {
            input.addEventListener('input', updateJsonEditor);
            input.addEventListener('change', updateJsonEditor);
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
                checkLargeBlobCapability();
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

        const jsonEditorExpandButton = document.getElementById('json-editor-expand');
        if (jsonEditorExpandButton) {
            jsonEditorExpandButton.addEventListener('click', () => toggleJsonEditorExpansion());
        }

        const jsonEditorOverlay = document.getElementById('json-editor-overlay');
        if (jsonEditorOverlay) {
            jsonEditorOverlay.addEventListener('click', () => toggleJsonEditorExpansion(true));
        }

        if (jsonEditorElement) {
            jsonEditorElement.addEventListener('keydown', handleJsonEditorKeydown);
        }

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                const container = document.getElementById('json-editor-container');
                if (container?.classList.contains('expanded')) {
                    toggleJsonEditorExpansion(true);
                }
            }
        });
    }, 100);

    setTimeout(updateJsonEditor, 200);
    setTimeout(loadSavedCredentials, 300);
    setTimeout(() => {
        checkLargeBlobCapability();
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
