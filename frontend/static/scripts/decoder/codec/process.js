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
import { canEncodeToFormat } from './encoding.js';
import {
    getSelectedDecoderMode,
    resolveCodecConfig,
} from './mode.js';
import { renderDecodedResult } from './render-sections.js';

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
    if (!inputValue.trim()) {
        const message = mode === 'encode'
            ? 'Encoder input is empty. Provide JSON to encode.'
            : 'Codec input is empty. Please paste something to process.';
        showStatus(config.statusKey, message, 'error');
        updateDecodeEmptyState(mode);
        return;
    }

    let targetFormat = null;
    if (mode === 'encode') {
        const formatSelect = config.formatSelectId
            ? document.getElementById(config.formatSelectId)
            : null;
        targetFormat = formatSelect ? formatSelect.value : '';
        if (!targetFormat || !targetFormat.trim()) {
            showStatus(config.statusKey, 'Select an encoding format before encoding.', 'error');
            return;
        }

        let parsedValue;
        try {
            parsedValue = JSON.parse(inputValue);
        } catch (parseError) {
            showStatus(config.statusKey, 'Encoder expects valid JSON input.', 'error');
            return;
        }

        if (!canEncodeToFormat(parsedValue, targetFormat)) {
            showStatus(
                config.statusKey,
                `Input cannot be converted into ${targetFormat}.`,
                'error',
            );
            return;
        }
    }

    const outputPanel = document.getElementById(config.outputId);
    const summaryContainer = document.getElementById(config.summaryId);
    const rawContent = document.getElementById(config.rawContentId);
    const toggleButton = document.getElementById(config.toggleRawId);
    const rawModal = config.rawModalId ? document.getElementById(config.rawModalId) : null;
    const progressText = document.getElementById(config.progressTextId);

    if (summaryContainer) {
        summaryContainer.innerHTML = '';
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

    const actionText = mode === 'encode' ? 'Encoding…' : 'Decoding…';
    showProgress(config.statusKey, actionText);
    if (progressText) {
        progressText.textContent = actionText;
    }

    try {
        const body = { payload: inputValue, mode };
        if (mode === 'encode') {
            body.format = targetFormat;
        }

        const response = await fetch('/api/codec', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (parseError) {
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            throw new Error('Failed to parse decoder response.');
        }

        if (!response.ok) {
            const message = payload && payload.error
                ? payload.error
                : `Server responded with status ${response.status}`;
            throw new Error(message);
        }

        if (summaryContainer) {
            renderDecodedResult(summaryContainer, payload, mode);
        }
        if (rawContent) {
            rawContent.textContent = JSON.stringify(payload, null, 2);
            resetScrollPosition(rawContent);
        }
        if (outputPanel) {
            outputPanel.classList.add('is-visible');
        }
        if (toggleButton) {
            toggleButton.disabled = !rawContent || rawContent.textContent.trim().length === 0;
        }

        const successMessage = mode === 'encode'
            ? 'Payload encoded successfully!'
            : 'Response decoded successfully!';
        showStatus(config.statusKey, successMessage, 'success');

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

        const message = error instanceof Error ? error.message : String(error);
        const failurePrefix = mode === 'encode' ? 'Encoding failed' : 'Decoding failed';
        showStatus(config.statusKey, `${failurePrefix}: ${message}`, 'error');

        updateDecodeEmptyState(mode);
    } finally {
        hideProgress(config.statusKey);
        updateDecodeEmptyState(mode);
    }
}
