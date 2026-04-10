import { updateDecoderModeUI } from './mode.js';

export function resetScrollPosition(element) {
    if (element && typeof element.scrollTop === 'number') {
        element.scrollTop = 0;
    }
    if (element && typeof element.scrollLeft === 'number') {
        element.scrollLeft = 0;
    }
}

export function autoSizeRawTextarea(textarea) {
    if (!(textarea instanceof HTMLTextAreaElement)) {
        return;
    }

    textarea.style.overflowY = 'hidden';
    textarea.style.height = 'auto';
    const scrollHeight = textarea.scrollHeight;
    textarea.style.height = scrollHeight ? `${scrollHeight}px` : '';
}

export function updateDecoderEmptyState() {
    const output = document.getElementById('decoder-output');
    const description = document.getElementById('decoder-description');

    if (!description) {
        return;
    }

    const summary = output ? output.querySelector('#decoded-content') : null;
    const hasVisibleOutput = Boolean(
        output &&
            output.classList.contains('is-visible') &&
            summary &&
            summary.childElementCount > 0
    );

    description.style.display = hasVisibleOutput ? 'none' : 'block';
}

export function initDecoderEmptyState() {
    updateDecoderEmptyState();
    updateDecoderModeUI();
}
