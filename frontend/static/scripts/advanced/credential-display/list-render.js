import {el} from '../../shared/ui/dom.js';
import {
    ALLOW_CREDENTIALS_TEXT,
    allowCredentialChoices,
    keptChoice,
    registrationAttachmentFilter,
} from '../auth/allow-credentials.js';
import {
    SAVED_LIST_TEXT,
    describeCredentialCard,
    listSavedCredentials,
} from '../credentials/saved-list.js';

// The Allow Credentials select, drawn from ../auth/allow-credentials.js: the
// saved credentials the registration form's hints (or its attachment) allow,
// the choice kept, else All, announced as changed.
export function updateAllowCredentialsDropdownRuntime(deps) {
    const {
        state,
        collectSelectedHints,
        deriveAllowedAttachmentsFromHints,
        getStoredCredentialAttachment,
        describeCredentialAlgorithm,
        getCredentialIdHex,
    } = deps;

    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (!allowCredentialsSelect) return;

    const currentValue = allowCredentialsSelect.value;

    const selectedHints = collectSelectedHints ? collectSelectedHints('registration') : [];
    const attachmentSelect = document.getElementById('authenticator-attachment');
    const attachments = registrationAttachmentFilter(
        deriveAllowedAttachmentsFromHints(selectedHints),
        attachmentSelect ? attachmentSelect.value : '',
    );
    const choices = allowCredentialChoices(state.storedCredentials, {
        attachments,
        getCredentialIdHex,
        getStoredCredentialAttachment,
        describeAlgorithm: describeCredentialAlgorithm,
    });

    allowCredentialsSelect.replaceChildren(
        el('option', { attrs: { value: 'all' }, text: ALLOW_CREDENTIALS_TEXT.all }),
        el('option', { attrs: { value: 'empty' }, text: ALLOW_CREDENTIALS_TEXT.empty }),
        ...choices.map(choice => el('option', {
            attrs: { value: choice.value },
            dataset: { attachment: choice.attachment },
            text: choice.label,
        })),
    );

    const desiredValue = keptChoice(choices, currentValue);
    if (allowCredentialsSelect.value !== desiredValue) {
        allowCredentialsSelect.value = desiredValue;
        try {
            allowCredentialsSelect.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (error) {
            const changeEvent = document.createEvent('Event');
            changeEvent.initEvent('change', true, true);
            allowCredentialsSelect.dispatchEvent(changeEvent);
        }
    }
}

export async function loadSavedCredentialsRuntime(deps) {
    const {
        getAllStoredCredentialsInOrder,
        normaliseAaguidValue,
        getCredentialIdHex,
        getCredentialUserHandleHex,
        state,
        updateCredentialsDisplay,
        updateJsonEditor,
        scheduleCredentialBackgroundWarmup,
    } = deps;

    state.storedCredentials = listSavedCredentials(getAllStoredCredentialsInOrder(), {
        normaliseAaguidValue,
        getCredentialIdHex,
        getCredentialUserHandleHex,
    });
    updateCredentialsDisplay();
    updateJsonEditor();
    void scheduleCredentialBackgroundWarmup();
}

function readCredentialIndex(element) {
    const rawIndex = element?.dataset?.credentialIndex;
    if (typeof rawIndex !== 'string' || rawIndex.trim() === '') {
        return null;
    }
    const parsed = Number.parseInt(rawIndex, 10);
    return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function resolveCredentialAction(candidate) {
    return typeof candidate === 'function' ? candidate : null;
}

function statusColour(value) {
    if (value === true) {
        return '#11b66d';
    }
    if (value === false) {
        return '#dc3545';
    }
    return '#6c757d';
}

function buildCredentialCard(card, index, {
    deletionInProgress,
    handleCredentialMdsClick,
    removeCredential,
    openCredentialDetails,
}) {
    const statusLine = el('div', { style: 'font-size: 0.75rem; font-weight: 600; margin-bottom: 0.25rem;' },
        card.checks.map((check, position) => el('span', {
            style: `${position ? 'margin-left: 0.75rem; ' : ''}color: ${statusColour(check.value)};`,
            text: check.label,
        })),
    );

    const featureTags = card.tags.length > 0
        ? el('div', { className: 'credential-feature-tags' },
            card.tags.map(label => el('span', { className: 'credential-feature-tag', text: label })))
        : null;

    let mdsButton = null;
    if (card.mdsAaguid) {
        mdsButton = el('button', {
            className: 'btn btn-small btn-secondary credential-mds-button',
            attrs: { type: 'button', title: SAVED_LIST_TEXT.openMetadata },
            dataset: { aaguid: card.mdsAaguid },
            text: 'FIDO MDS',
        });
        mdsButton.addEventListener('click', handleCredentialMdsClick);
    }

    const deleteButton = el('button', {
        className: 'btn btn-small btn-danger credential-delete-button',
        attrs: {
            disabled: deletionInProgress,
            'aria-disabled': deletionInProgress ? 'true' : null,
        },
        dataset: { credentialIndex: index },
        text: 'Delete',
    });
    deleteButton.addEventListener('click', event => {
        event.stopPropagation();
        const deleteIndex = readCredentialIndex(deleteButton);
        if (deleteIndex === null || !removeCredential) {
            return;
        }
        removeCredential(deleteIndex);
    });

    const item = el('div', {
        className: 'credential-item',
        attrs: { role: 'button', tabindex: '0' },
        dataset: {
            credentialId: card.credentialIdHex,
            credentialIndex: index,
        },
    },
    el('div', { style: 'flex: 1; min-width: 0;' },
        el('div', {
            style: 'font-weight: 600; color: #0f2740; font-size: 0.95rem; margin-bottom: 0.25rem;',
            text: card.name,
        }),
        statusLine,
        featureTags,
    ),
    el('div', { className: 'credential-item-actions' }, mdsButton, deleteButton),
    );

    if (openCredentialDetails) {
        item.addEventListener('click', () => {
            openCredentialDetails(index);
        });
        item.addEventListener('keydown', event => {
            if (event.key !== 'Enter' && event.key !== ' ') {
                return;
            }
            event.preventDefault();
            openCredentialDetails(index);
        });
    }

    return item;
}

export function updateCredentialsDisplayRuntime(deps) {
    const {
        state,
        getCredentialIdHex,
        readPendingCredentialFlash,
        isCredentialDeletionInProgress,
        checkLargeBlobCapability,
        updateAllowCredentialsDropdown,
        updateAuthenticationExtensionAvailability,
        clearCredentialFlashQueue,
        describeCredentialAlgorithmTag,
        deriveCredentialStatusIndicators,
        handleCredentialMdsClick,
        triggerCredentialFlash,
        showCredentialDetails,
        deleteCredential,
    } = deps;

    const openCredentialDetails = resolveCredentialAction(showCredentialDetails);
    const removeCredential = resolveCredentialAction(deleteCredential);

    const hasCredentials = state.storedCredentials.length > 0;
    const flashRequest = readPendingCredentialFlash();
    const deletionInProgress = isCredentialDeletionInProgress();
    const runPostUpdate = () => {
        checkLargeBlobCapability();
        updateAllowCredentialsDropdown();
        updateAuthenticationExtensionAvailability();
    };

    const clearButtons = document.querySelectorAll('[data-credentials-clear]');
    clearButtons.forEach(button => {
        if (button instanceof HTMLButtonElement) {
            button.disabled = !hasCredentials || deletionInProgress;
        }
    });

    const lists = document.querySelectorAll('[data-credentials-list]');
    if (!lists.length) {
        return;
    }

    if (!hasCredentials) {
        lists.forEach(list => {
            list.replaceChildren(el('p', { className: 'credential-list-empty', text: SAVED_LIST_TEXT.empty }));
        });
        clearCredentialFlashQueue();
        runPostUpdate();
        return;
    }

    const cards = state.storedCredentials.map(cred => {
        const algorithmTag = describeCredentialAlgorithmTag(cred);
        return describeCredentialCard(cred, {
            algorithmTag,
            credentialIdHex: getCredentialIdHex(cred),
            indicators: deriveCredentialStatusIndicators(cred),
        });
    });

    // Each list gets its own nodes: the same card cannot sit in two lists.
    lists.forEach(list => {
        list.replaceChildren(...cards.map((card, index) => buildCredentialCard(card, index, {
            deletionInProgress,
            handleCredentialMdsClick,
            removeCredential,
            openCredentialDetails,
        })));
    });

    clearCredentialFlashQueue();
    if (flashRequest) {
        requestAnimationFrame(() => {
            triggerCredentialFlash(flashRequest);
        });
    }
    runPostUpdate();
}
