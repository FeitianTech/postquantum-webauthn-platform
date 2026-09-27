// The current UI's delete and Clear All: advanced/credentials/delete-flow.js,
// asking with the browser's confirm.
import { clearSavedCredentials, deleteSavedCredential } from '../credentials/delete-flow.js';

function confirmInBrowser(question) {
    return confirm(question);
}

export async function deleteCredentialRuntime(index, deps) {
    await deleteSavedCredential(deps.state.storedCredentials[index], { ...deps, confirm: confirmInBrowser });
}

export async function clearAllCredentialsRuntime(deps) {
    await clearSavedCredentials({ ...deps, confirm: confirmInBrowser });
}
