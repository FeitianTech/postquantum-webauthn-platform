import {el} from '../../shared/ui/dom.js';

export function updateAllowCredentialsDropdownRuntime(deps) {
    const {
        state,
        collectSelectedHints,
        deriveAllowedAttachmentsFromHints,
        getStoredCredentialAttachment,
        ATTACHMENT_LABELS,
        describeCredentialAlgorithm,
        getCredentialIdHex,
    } = deps;

    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (!allowCredentialsSelect) return;

    const currentValue = allowCredentialsSelect.value;

    allowCredentialsSelect.innerHTML = `
        <option value="all">All credentials</option>
        <option value="empty">Empty (resident key only)</option>
    `;

    const selectedHints = collectSelectedHints ? collectSelectedHints('registration') : [];
    let attachmentFilters = deriveAllowedAttachmentsFromHints(selectedHints);
    if (!attachmentFilters.length) {
        const attachmentSelect = document.getElementById('authenticator-attachment');
        const attachmentPreference = attachmentSelect ? attachmentSelect.value : '';
        if (attachmentPreference === 'platform' || attachmentPreference === 'cross-platform') {
            attachmentFilters = [attachmentPreference];
        }
    }

    const matchesAttachmentPreference = attachmentValue => {
        if (!attachmentFilters.length) {
            return true;
        }
        if (typeof attachmentValue !== 'string' || !attachmentValue.trim()) {
            return false;
        }
        return attachmentFilters.includes(attachmentValue.trim().toLowerCase());
    };

    if (state.storedCredentials && state.storedCredentials.length > 0) {
        state.storedCredentials.forEach((cred, index) => {
            const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
            if (!credentialIdHex) {
                return;
            }

            const attachmentValue = getStoredCredentialAttachment(cred);
            if (!matchesAttachmentPreference(attachmentValue)) {
                return;
            }

            const credName = cred.userName || cred.username || cred.email || `Credential ${index + 1}`;
            const algorithmLabel = describeCredentialAlgorithm(cred);
            const attachmentLabel = attachmentValue
                ? (ATTACHMENT_LABELS[attachmentValue] || attachmentValue)
                : '';
            const labelSuffix = attachmentLabel ? ` • ${attachmentLabel}` : '';

            const option = document.createElement('option');
            option.value = credentialIdHex;
            option.textContent = `${credName} (${algorithmLabel})${labelSuffix}`;
            option.dataset.attachment = attachmentValue || '';
            allowCredentialsSelect.appendChild(option);
        });
    }

    const availableValues = new Set(Array.from(allowCredentialsSelect.options).map(opt => opt.value));
    const desiredValue = availableValues.has(currentValue) ? currentValue : 'all';
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

    const orderedRecords = getAllStoredCredentialsInOrder();

    const mappedCredentials = orderedRecords.map(record => {
        if ((record.type || 'simple') === 'advanced') {
            const relyingPartyInfo = record && typeof record === 'object' ? record.relyingParty : null;
            const relyingPartyAaguid = relyingPartyInfo && typeof relyingPartyInfo === 'object'
                ? relyingPartyInfo.aaguid
                : null;
            const normalizedAaguidHex = normaliseAaguidValue(
                record.aaguidHex || record.aaguid || relyingPartyAaguid,
            );

            return {
                ...record,
                type: record.type || 'advanced',
                storageId: record.storageId || record.localStorageId || null,
                localStorageId: record.storageId || record.localStorageId || null,
                aaguidHex: normalizedAaguidHex || record.aaguidHex || null,
                credentialIdHex: getCredentialIdHex(record),
                userHandleHex: getCredentialUserHandleHex(record),
            };
        }

        return {
            ...record,
            type: 'simple',
            credentialIdHex: getCredentialIdHex(record),
            userHandleHex: getCredentialUserHandleHex(record),
        };
    });

    state.storedCredentials = mappedCredentials;
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

function resolveCredentialAction(candidate, globalName) {
    if (typeof candidate === 'function') {
        return candidate;
    }
    const globalCandidate = typeof window !== 'undefined' ? window[globalName] : undefined;
    return typeof globalCandidate === 'function' ? globalCandidate : null;
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

function buildCredentialCard(cred, index, {
    credentialIdHex,
    featureLabels,
    indicators,
    deletionInProgress,
    handleCredentialMdsClick,
    removeCredential,
    openCredentialDetails,
}) {
    const {
        signatureStatus,
        rootStatus,
        rpidStatus,
        aaguidStatus,
        metadataAvailable,
        aaguidGuid,
    } = indicators;

    const statusLine = el('div', { style: 'font-size: 0.75rem; font-weight: 600; margin-bottom: 0.25rem;' },
        el('span', { style: `color: ${statusColour(signatureStatus)};`, text: 'Signature' }),
        el('span', { style: `margin-left: 0.75rem; color: ${statusColour(rootStatus)};`, text: 'Root' }),
        el('span', { style: `margin-left: 0.75rem; color: ${statusColour(rpidStatus)};`, text: 'RPID' }),
        el('span', { style: `margin-left: 0.75rem; color: ${statusColour(aaguidStatus)};`, text: 'AAGUID' }),
    );

    const featureTags = featureLabels.length > 0
        ? el('div', { className: 'credential-feature-tags' },
            featureLabels.map(label => el('span', { className: 'credential-feature-tag', text: label })))
        : null;

    let mdsButton = null;
    if (aaguidGuid && (rootStatus === true || metadataAvailable)) {
        mdsButton = el('button', {
            className: 'btn btn-small btn-secondary credential-mds-button',
            attrs: { type: 'button', title: 'Open authenticator metadata' },
            dataset: { aaguid: aaguidGuid.toLowerCase() },
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
            credentialId: (credentialIdHex || '').toLowerCase(),
            credentialIndex: index,
        },
    },
    el('div', { style: 'flex: 1; min-width: 0;' },
        el('div', {
            style: 'font-weight: 600; color: #0f2740; font-size: 0.95rem; margin-bottom: 0.25rem;',
            text: cred.userName || cred.username || cred.email || 'Unknown User',
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

    const openCredentialDetails = resolveCredentialAction(showCredentialDetails, 'showCredentialDetails');
    const removeCredential = resolveCredentialAction(deleteCredential, 'deleteCredential');

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
            list.replaceChildren(el('p', { className: 'credential-list-empty', text: 'No credentials registered yet.' }));
        });
        clearCredentialFlashQueue();
        runPostUpdate();
        return;
    }

    const cardInputs = state.storedCredentials.map(cred => {
        const featureLabels = [];
        const algorithmTag = describeCredentialAlgorithmTag(cred);
        if (algorithmTag) {
            featureLabels.push(algorithmTag);
        }
        if (cred.residentKey === true || cred.discoverable === true) {
            featureLabels.push('Discoverable');
        }
        if (cred.largeBlob === true || cred.largeBlobSupported === true) {
            featureLabels.push('Large blob');
        }
        return {
            credentialIdHex: getCredentialIdHex(cred),
            featureLabels,
            indicators: deriveCredentialStatusIndicators(cred),
        };
    });

    // Each list gets its own nodes: the same card cannot sit in two lists.
    lists.forEach(list => {
        list.replaceChildren(...state.storedCredentials.map((cred, index) => buildCredentialCard(cred, index, {
            ...cardInputs[index],
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
