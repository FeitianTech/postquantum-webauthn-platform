import {
    hideProgress,
    hideStatus,
} from '../../shared/ui/status.js';
import { closeModal, openModal } from '../../shared/ui/core.js';
import {
    resetScrollPosition,
    updateDecoderEmptyState,
} from './dom-state.js';
import {
    getSelectedDecoderMode,
    resolveCodecConfig,
    updateDecoderModeUI,
} from './mode.js';

export function clearCodec(mode = getSelectedDecoderMode()) {
    const config = resolveCodecConfig(mode);
    if (!config) {
        return;
    }

    const input = document.getElementById(config.inputId);
    const output = document.getElementById(config.outputId);
    const summary = document.getElementById(config.summaryId);
    const rawContent = document.getElementById(config.rawContentId);
    const toggleButton = document.getElementById(config.toggleRawId);
    const rawModal = config.rawModalId ? document.getElementById(config.rawModalId) : null;

    if (input) {
        input.value = '';
        resetScrollPosition(input);
    }
    if (summary) {
        summary.innerHTML = '';
    }
    if (rawContent) {
        rawContent.textContent = '';
        resetScrollPosition(rawContent);
    }
    if (toggleButton) {
        toggleButton.disabled = true;
    }
    if (output) {
        output.classList.remove('is-visible');
    }
    if (rawModal && rawModal.classList.contains('open')) {
        closeModal(config.rawModalId);
    }

    hideStatus(config.statusKey);
    hideProgress(config.statusKey);

    if (mode === 'decode') {
        updateDecoderEmptyState();
    }
    updateDecoderModeUI();
}

export function toggleRawCodec(mode = getSelectedDecoderMode()) {
    const config = resolveCodecConfig(mode);
    if (!config || !config.rawModalId) {
        return;
    }

    const toggleButton = document.getElementById(config.toggleRawId);
    const rawContent = document.getElementById(config.rawContentId);
    const modal = document.getElementById(config.rawModalId);

    if (!toggleButton || !rawContent || !modal) {
        return;
    }

    if (toggleButton.disabled) {
        return;
    }

    const hasContent = rawContent.textContent && rawContent.textContent.trim().length > 0;
    if (!hasContent) {
        return;
    }

    if (modal.classList.contains('open')) {
        closeModal(config.rawModalId);
    } else {
        openModal(config.rawModalId);
    }
}
