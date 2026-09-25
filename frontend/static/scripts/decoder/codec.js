import {
    clearCodec,
    toggleRawCodec,
} from './codec/panel-actions.js';
import { initDecoderEmptyState } from './codec/dom-state.js';
import { switchCodecMode } from './codec/mode.js';
import { processCodec } from './codec/process.js';
import { bindActions, callWith } from '../shared/ui/actions.js';

export {
    clearCodec,
    processCodec,
    switchCodecMode,
    toggleRawCodec,
};

// Each control names its panel with data-mode="decode" or "encode".
export const codecActions = {
    'switch-codec-mode': callWith(switchCodecMode, 'mode'),
    'process-codec': callWith(processCodec, 'mode'),
    'clear-codec': callWith(clearCodec, 'mode'),
    'toggle-raw-codec': callWith(toggleRawCodec, 'mode'),
};

export function bindCodecActions() {
    return bindActions(document.getElementById('codec-tab'), codecActions);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDecoderEmptyState);
} else {
    initDecoderEmptyState();
}
