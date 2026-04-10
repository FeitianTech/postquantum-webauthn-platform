import { hideStatus } from '../../shared/status.js';
import { MODE_CONFIG } from './constants.js';

let currentCodecMode = 'decode';

export function getSelectedDecoderMode() {
    return currentCodecMode;
}

export function resolveCodecConfig(mode) {
    return MODE_CONFIG[mode] || MODE_CONFIG[currentCodecMode];
}

export function updateDecoderModeUI() {
    const mode = getSelectedDecoderMode();
    const decodeTab = document.getElementById('codec-mode-decode');
    const encodeTab = document.getElementById('codec-mode-encode');
    const decodePanel = document.getElementById(MODE_CONFIG.decode.panelId);
    const encodePanel = document.getElementById(MODE_CONFIG.encode.panelId);

    if (decodeTab) {
        decodeTab.classList.toggle('active', mode === 'decode');
        decodeTab.setAttribute('aria-selected', mode === 'decode' ? 'true' : 'false');
    }
    if (encodeTab) {
        encodeTab.classList.toggle('active', mode === 'encode');
        encodeTab.setAttribute('aria-selected', mode === 'encode' ? 'true' : 'false');
    }
    if (decodePanel) {
        decodePanel.classList.toggle('is-active', mode === 'decode');
        decodePanel.hidden = mode !== 'decode';
    }
    if (encodePanel) {
        encodePanel.classList.toggle('is-active', mode === 'encode');
        encodePanel.hidden = mode !== 'encode';
    }
}

export function switchCodecMode(mode) {
    if (mode !== 'decode' && mode !== 'encode') {
        return;
    }
    if (mode === currentCodecMode) {
        return;
    }

    currentCodecMode = mode;
    hideStatus('decoder');
    hideStatus('encoder');
    updateDecoderModeUI();

    const content = document.getElementById('codec-mode-content');
    if (content) {
        content.classList.remove('codec-mode-animating');
        void content.offsetWidth;
        content.classList.add('codec-mode-animating');
        content.addEventListener('animationend', () => {
            content.classList.remove('codec-mode-animating');
        }, { once: true });
    }
}
