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
        escapeHtml,
        handleCredentialMdsClick,
        triggerCredentialFlash,
    } = deps;

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

    const emptyStateHtml = '<p style="color: #6c757d;">No credentials registered yet.</p>';

    if (!hasCredentials) {
        lists.forEach(list => {
            list.innerHTML = emptyStateHtml;
        });
        clearCredentialFlashQueue();
        runPostUpdate();
        return;
    }

    const itemsHtml = state.storedCredentials.map((cred, index) => {
        const credentialIdHex = getCredentialIdHex(cred);
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

        const featureTagsHtml = featureLabels.length > 0
            ? `<div class="credential-feature-tags">${featureLabels.map(label => `<span class="credential-feature-tag">${escapeHtml(label)}</span>`).join('')}</div>`
            : '';

        const {
            signatureStatus,
            rootStatus,
            rpidStatus,
            aaguidStatus,
            metadataAvailable,
            aaguidGuid,
        } = deriveCredentialStatusIndicators(cred);

        const pickStatusColor = value => {
            if (value === true) {
                return '#11b66d';
            }
            if (value === false) {
                return '#dc3545';
            }
            return '#6c757d';
        };
        const signatureColor = pickStatusColor(signatureStatus);
        const rootColor = pickStatusColor(rootStatus);
        const rpidColor = pickStatusColor(rpidStatus);
        const aaguidColor = pickStatusColor(aaguidStatus);

        const mdsButtonHtml = (aaguidGuid && (rootStatus === true || metadataAvailable))
            ? `<button type="button" class="btn btn-small btn-secondary credential-mds-button" data-aaguid="${escapeHtml(aaguidGuid.toLowerCase())}" title="Open authenticator metadata">FIDO MDS</button>`
            : '';
        const deleteButtonDisabledAttributes = deletionInProgress
            ? ' disabled aria-disabled="true"'
            : '';
        const deleteButtonHtml = `<button class="btn btn-small btn-danger credential-delete-button"${deleteButtonDisabledAttributes} onclick="event.stopPropagation();deleteCredential(${index})">Delete</button>`;
        const actionsHtml = `<div class="credential-item-actions">${mdsButtonHtml}${deleteButtonHtml}</div>`;

        return `
        <div class="credential-item" data-credential-id="${escapeHtml((credentialIdHex || '').toLowerCase())}" role="button" tabindex="0" onclick="showCredentialDetails(${index})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();showCredentialDetails(${index});}">
            <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 600; color: #0f2740; font-size: 0.95rem; margin-bottom: 0.25rem;">${cred.userName || cred.username || cred.email || 'Unknown User'}</div>
                <div style="font-size: 0.75rem; font-weight: 600; margin-bottom: 0.25rem;">
                    <span style="color: ${signatureColor};">Signature</span>
                    <span style="margin-left: 0.75rem; color: ${rootColor};">Root</span>
                    <span style="margin-left: 0.75rem; color: ${rpidColor};">RPID</span>
                    <span style="margin-left: 0.75rem; color: ${aaguidColor};">AAGUID</span>
                </div>
                ${featureTagsHtml}
            </div>
            ${actionsHtml}
        </div>
        `;
    }).join('');

    lists.forEach(list => {
        list.innerHTML = itemsHtml;
        list.querySelectorAll('.credential-mds-button').forEach(button => {
            button.addEventListener('click', handleCredentialMdsClick);
        });
    });

    clearCredentialFlashQueue();
    if (flashRequest) {
        requestAnimationFrame(() => {
            triggerCredentialFlash(flashRequest);
        });
    }
    runPostUpdate();
}
