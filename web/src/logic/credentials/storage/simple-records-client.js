// The Simple tab's records on the server (routes/simple/deletion.py): deleting the
// one a saved Simple credential has when the person deletes the credential. DOM-free.
import { requestDeletion } from './deletion-request.js';
import { ensureBase64Url } from './local/id-utils.js';

const SIMPLE_CREDENTIALS_PATH = '/api/simple/credentials';

/**
 * Deletes the server's record of a Simple credential, from its username's list.
 * The username goes as the credential was saved with it: the server reads it as
 * its store names the list, which keeps a name saved before today's rules.
 * @param {string} credentialId
 * @param {unknown} username
 * @returns {Promise<import('./deletion-request.js').DeletionAnswer>}
 */
export function deleteSimpleCredentialRecord(credentialId, username) {
    const id = encodeURIComponent(ensureBase64Url(credentialId));
    return requestDeletion(`${SIMPLE_CREDENTIALS_PATH}/${id}?email=${encodeURIComponent(String(username))}`);
}
