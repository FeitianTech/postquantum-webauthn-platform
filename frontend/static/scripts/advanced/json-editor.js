import { registerHintsChangeCallback } from './hints.js';
import { updateJsonEditor } from './json-editor/editor-flow.js';

registerHintsChangeCallback(() => updateJsonEditor());

export {
    getAdvancedAssertOptions,
    getAdvancedCreateOptions,
} from './json-editor/advanced-options.js';

export {
    applyJsonChanges,
    cancelJsonEdit,
    editAssertOptions,
    editCreateOptions,
    resetJsonEditor,
    saveJsonEditor,
    updateJsonEditor,
    updateJsonFromForm,
} from './json-editor/editor-flow.js';

export {
    updateAuthenticationFormFromJson,
    updateRegistrationFormFromJson,
} from './json-editor/form-sync.js';

export { getCredentialCreationOptions } from './json-editor/creation-options.js';

export { getCredentialRequestOptions } from './json-editor/request-options.js';
