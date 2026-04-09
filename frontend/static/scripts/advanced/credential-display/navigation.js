function setAaguidStatus(statusEl, message, { showSpinner = false } = {}) {
    if (!(statusEl instanceof HTMLElement)) {
        return;
    }

    statusEl.dataset.active = 'true';
    const spinner = statusEl.querySelector('.credential-aaguid-spinner');
    const textEl = statusEl.querySelector('.credential-aaguid-status-text');

    if (spinner instanceof HTMLElement) {
        if (showSpinner) {
            spinner.hidden = false;
            spinner.setAttribute('aria-hidden', 'true');
        } else {
            spinner.hidden = true;
            spinner.setAttribute('aria-hidden', 'true');
        }
    }

    if (textEl instanceof HTMLElement) {
        textEl.textContent = typeof message === 'string' ? message : '';
    }
}

export function clearAaguidStatus(statusEl) {
    if (!(statusEl instanceof HTMLElement)) {
        return;
    }
    delete statusEl.dataset.active;
    const spinner = statusEl.querySelector('.credential-aaguid-spinner');
    const textEl = statusEl.querySelector('.credential-aaguid-status-text');
    if (spinner instanceof HTMLElement) {
        spinner.hidden = true;
        spinner.setAttribute('aria-hidden', 'true');
    }
    if (textEl instanceof HTMLElement) {
        textEl.textContent = '';
    }
}

export function navigateToMdsAuthenticatorRuntime(aaguid, deps = {}) {
    const {
        closeCredentialModal,
    } = deps;

    if (!aaguid) {
        return;
    }

    const switchToMdsTab = typeof window.switchTab === 'function'
        ? window.switchTab
        : null;

    const highlightRow = typeof window.highlightMdsAuthenticatorRow === 'function'
        ? window.highlightMdsAuthenticatorRow
        : null;

    if (!highlightRow) {
        console.warn('Unable to highlight authenticator row: integration unavailable.');
        return;
    }

    const modalBody = document.getElementById('modalBody');
    const statusEl = modalBody ? modalBody.querySelector('.credential-aaguid-status') : null;
    const resolveEntryByAaguidGlobal = typeof window.resolveMdsEntryByAaguid === 'function'
        ? window.resolveMdsEntryByAaguid
        : null;

    let clearTimer = null;
    const scheduleClear = () => {
        if (typeof window !== 'undefined' && clearTimer) {
            window.clearTimeout(clearTimer);
        }
        if (typeof window !== 'undefined') {
            clearTimer = window.setTimeout(() => {
                clearAaguidStatus(statusEl);
                clearTimer = null;
            }, 4000);
        }
    };

    const showSpinnerStatus = message => {
        if (!statusEl) {
            return;
        }
        if (typeof window !== 'undefined' && clearTimer) {
            window.clearTimeout(clearTimer);
            clearTimer = null;
        }
        setAaguidStatus(statusEl, message, { showSpinner: true });
    };

    const waitForNextFrame = async (count = 1) => {
        if (count <= 0) {
            return;
        }
        const waitOnce = () => new Promise(resolve => {
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(() => resolve());
            } else {
                setTimeout(resolve, 16);
            }
        });
        for (let i = 0; i < count; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            await waitOnce();
        }
    };

    const run = async () => {
        try {
            if (statusEl) {
                showSpinnerStatus('Locating metadata entry...');
            }

            if (switchToMdsTab) {
                switchToMdsTab('mds', { preserveMessages: true });
            }

            let resolvedEntry = null;
            if (resolveEntryByAaguidGlobal) {
                try {
                    resolvedEntry = await resolveEntryByAaguidGlobal(aaguid);
                } catch (error) {
                    console.warn('Failed to pre-resolve authenticator metadata entry:', error);
                }
            }

            if (!resolvedEntry) {
                if (statusEl) {
                    setAaguidStatus(statusEl, 'Authenticator metadata not found.', { showSpinner: false });
                    scheduleClear();
                }
                return { highlighted: false, entry: null };
            }

            const normaliseHighlightResult = result => {
                if (result && typeof result === 'object' && 'highlighted' in result) {
                    return {
                        highlighted: Boolean(result.highlighted),
                        entry: result.entry || null,
                    };
                }
                return {
                    highlighted: Boolean(result),
                    entry: null,
                };
            };

            const invokeHighlight = async (options = {}) => {
                try {
                    const result = await Promise.resolve(highlightRow(aaguid, {
                        scrollBehavior: 'smooth',
                        preResolvedEntry: resolvedEntry,
                        ...options,
                    }));
                    return normaliseHighlightResult(result);
                } catch (error) {
                    console.warn('Failed to highlight authenticator row:', error);
                    return { highlighted: false, entry: null };
                }
            };

            if (statusEl) {
                showSpinnerStatus('Locating metadata entry...');
            }

            const preparation = await invokeHighlight({
                deferScroll: true,
                waitForVisibility: false,
                focusRow: false,
            });

            if (!resolvedEntry && preparation.entry) {
                resolvedEntry = preparation.entry;
            }

            if (!preparation.highlighted) {
                if (statusEl) {
                    const message = resolvedEntry
                        ? 'Unable to locate metadata entry.'
                        : 'Authenticator metadata not found.';
                    setAaguidStatus(statusEl, message, { showSpinner: false });
                    scheduleClear();
                }
                return { highlighted: false, entry: resolvedEntry };
            }

            if (statusEl) {
                showSpinnerStatus('Opening authenticator metadata...');
            }

            await waitForNextFrame(2);

            let finalised = false;
            const finaliseHighlight = typeof window.finaliseMdsAuthenticatorHighlight === 'function'
                ? window.finaliseMdsAuthenticatorHighlight
                : null;

            if (finaliseHighlight) {
                try {
                    finalised = Boolean(finaliseHighlight({ behavior: 'smooth', focus: true }));
                } catch (error) {
                    console.warn('Failed to finalise authenticator highlight:', error);
                    finalised = false;
                }
            }

            if (!finalised) {
                const completion = await invokeHighlight({ waitForVisibility: true });
                if (!resolvedEntry && completion.entry) {
                    resolvedEntry = completion.entry;
                }
                finalised = completion.highlighted;
            }

            if (finalised) {
                clearAaguidStatus(statusEl);
                if (typeof closeCredentialModal === 'function') {
                    closeCredentialModal();
                }
                return { highlighted: true, entry: resolvedEntry };
            }

            if (statusEl) {
                const message = resolvedEntry
                    ? 'Unable to locate metadata entry.'
                    : 'Authenticator metadata not found.';
                setAaguidStatus(statusEl, message, { showSpinner: false });
                scheduleClear();
            }

            return { highlighted: false, entry: resolvedEntry };
        } catch (error) {
            console.error('Failed to highlight authenticator row.', error);
            if (statusEl) {
                setAaguidStatus(statusEl, 'Unable to open authenticator metadata.', { showSpinner: false });
                scheduleClear();
            }
            return { highlighted: false, entry: null, error };
        }
    };

    return run();
}

export function handleCredentialMdsClickRuntime(event, deps = {}) {
    const {
        dismissAllTransientMessages,
        showSharedCredentialProgress,
        hideSharedCredentialProgress,
        showSharedCredentialStatus,
        navigateToMdsAuthenticator,
    } = deps;

    event.preventDefault();
    event.stopPropagation();

    const button = event.currentTarget;
    const aaguid = button?.getAttribute('data-aaguid');
    if (!aaguid) {
        return;
    }

    dismissAllTransientMessages();
    showSharedCredentialProgress('Locating metadata entry...');

    const finish = () => {
        hideSharedCredentialProgress();
    };

    let navigationResult;
    try {
        navigationResult = navigateToMdsAuthenticator(aaguid);
    } catch (error) {
        console.error('Failed to navigate to authenticator metadata.', error);
        showSharedCredentialStatus('Unable to open authenticator metadata.', 'error');
        finish();
        return;
    }

    if (navigationResult === undefined) {
        showSharedCredentialStatus('Authenticator metadata entry unavailable.', 'warning');
        finish();
        return;
    }

    Promise.resolve(navigationResult)
        .then(result => {
            if (!result) {
                showSharedCredentialStatus('Authenticator metadata entry unavailable.', 'warning');
                return;
            }
            if (result.error) {
                showSharedCredentialStatus('Unable to open authenticator metadata.', 'error');
                return;
            }
            if (result.highlighted !== true) {
                showSharedCredentialStatus('Authenticator metadata not found.', 'warning');
            }
        })
        .catch(error => {
            console.error('Failed to navigate to authenticator metadata.', error);
            showSharedCredentialStatus('Unable to open authenticator metadata.', 'error');
        })
        .finally(finish);
}
