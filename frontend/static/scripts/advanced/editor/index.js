import { registerHintsChangeCallback } from '../auth/hints.js';
import { resetJsonEditor, saveJsonEditor, updateJsonEditor } from '../json-editor/editor-flow.js';
import { bindActions, callWith } from '../../shared/ui/actions.js';

registerHintsChangeCallback(() => updateJsonEditor());

export {
    getAdvancedAssertOptions,
    getAdvancedCreateOptions,
} from '../json-editor/advanced-options.js';

export {
    applyJsonChanges,
    cancelJsonEdit,
    editAssertOptions,
    editCreateOptions,
    resetJsonEditor,
    saveJsonEditor,
    updateJsonEditor,
    updateJsonFromForm,
} from '../json-editor/editor-flow.js';

export {
    updateAuthenticationFormFromJson,
    updateRegistrationFormFromJson,
} from '../json-editor/form-sync.js';

export { getCredentialCreationOptions } from '../json-editor/creation-options.js';

export { getCredentialRequestOptions } from '../json-editor/request-options.js';

export const editorActions = {
    'save-json-editor': callWith(saveJsonEditor),
    'reset-json-editor': callWith(resetJsonEditor),
};

export function bindEditorActions() {
    return bindActions(document.getElementById('advanced-tab'), editorActions);
}
