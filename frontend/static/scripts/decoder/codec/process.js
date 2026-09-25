import {
    hideProgress,
    hideStatus,
    showProgress,
    showStatus,
} from '../../shared/ui/status.js';
import { closeModal } from '../../shared/ui/core.js';
import {
    resetScrollPosition,
    updateDecoderEmptyState,
} from './dom-state.js';
import {
    getSelectedDecoderMode,
    resolveCodecConfig,
} from './mode.js';
import { renderDecodedResult } from './render-sections.js';
import {
    buildCodecRequest,
    codecFailureText,
    codecProgressText,
    codecRawJson,
    codecSuccessText,
    requestCodec,
    validateCodecInput,
} from './request.js';

function updateDecodeEmptyState(mode) {
    if (mode === 'decode') {
        updateDecoderEmptyState();
    }
}

export async function processCodec(mode = getSelectedDecoderMode()) {
    const config = resolveCodecConfig(mode);
    if (!config) {
        return;
    }

    const input = document.getElementById(config.inputId);
    if (!input) {
        return;
    }

    const inputValue = input.value;
    let targetFormat = null;
    if (mode === 'encode') {
        const formatSelect = config.formatSelectId
            ? document.getElementById(config.formatSelectId)
            : null;
        targetFormat = formatSelect ? formatSelect.value : '';
    }

    const invalid = validateCodecInput(mode, inputValue, targetFormat);
    if (invalid) {
        showStatus(config.statusKey, invalid, 'error');
        updateDecodeEmptyState(mode);
        return;
    }

    const outputPanel = document.getElementById(config.outputId);
    const summaryContainer = document.getElementById(config.summaryId);
    const rawContent = document.getElementById(config.rawContentId);
    const toggleButton = document.getElementById(config.toggleRawId);
    const rawModal = config.rawModalId ? document.getElementById(config.rawModalId) : null;
    const progressText = document.getElementById(config.progressTextId);

    if (summaryContainer) {
        summaryContainer.replaceChildren();
    }
    if (rawContent) {
        rawContent.textContent = '';
    }
    if (toggleButton) {
        toggleButton.disabled = true;
    }
    if (outputPanel) {
        outputPanel.classList.remove('is-visible');
    }
    if (rawModal && rawModal.classList.contains('open')) {
        closeModal(config.rawModalId);
    }
    hideStatus(config.statusKey);

    updateDecodeEmptyState(mode);

    const actionText = codecProgressText(mode);
    showProgress(config.statusKey, actionText);
    if (progressText) {
        progressText.textContent = actionText;
    }

    try {
        const lenient = mode !== 'encode' && Boolean(document.getElementById('decoder-lenient')?.checked);
        const payload = await requestCodec(
            buildCodecRequest(mode, inputValue, { format: targetFormat, lenient }),
        );

        if (summaryContainer) {
            renderDecodedResult(summaryContainer, payload, mode);
        }
        if (rawContent) {
            rawContent.textContent = codecRawJson(payload);
            resetScrollPosition(rawContent);
        }
        if (outputPanel) {
            outputPanel.classList.add('is-visible');
        }
        if (toggleButton) {
            toggleButton.disabled = !rawContent || rawContent.textContent.trim().length === 0;
        }

        showStatus(config.statusKey, codecSuccessText(mode), 'success');

        updateDecodeEmptyState(mode);
    } catch (error) {
        if (outputPanel) {
            outputPanel.classList.remove('is-visible');
        }
        if (toggleButton) {
            toggleButton.disabled = true;
        }
        if (rawModal && rawModal.classList.contains('open')) {
            closeModal(config.rawModalId);
        }

        showStatus(config.statusKey, codecFailureText(mode, error), 'error');

        updateDecodeEmptyState(mode);
    } finally {
        hideProgress(config.statusKey);
        updateDecodeEmptyState(mode);
    }
}
