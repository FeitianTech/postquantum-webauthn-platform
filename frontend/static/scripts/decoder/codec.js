import {
    clearCodec,
    toggleRawCodec,
} from './codec/panel-actions.js';
import { initDecoderEmptyState } from './codec/dom-state.js';
import { switchCodecMode } from './codec/mode.js';
import { processCodec } from './codec/process.js';

export {
    clearCodec,
    processCodec,
    switchCodecMode,
    toggleRawCodec,
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDecoderEmptyState);
} else {
    initDecoderEmptyState();
}
