// The saved credentials an authenticator's MDS entry lists: those whose AAGUID
// reads as the entry's. A row's AAGUID is the dashed one its status indicators
// read from whichever spelling the record keeps (its hex, its base64url, the
// relying party's, its authenticator data or certificate); both sides are read
// with aaguidHex, so a dashed GUID in capitals, its hex and its base64url are one
// AAGUID. An entry or a row without sixteen readable bytes matches none.
// DOM-free: the entry's page lists these.
import { aaguidHex } from '../shared/aaguid.js';

/** @import { CredentialRowView } from './saved-list.js' */

/**
 * @param {CredentialRowView[]} rows The saved list's rows, in its order.
 * @param {unknown} aaguid The entry's AAGUID, as the entry spells it.
 * @returns {CredentialRowView[]}
 */
export function credentialsWithAaguid(rows, aaguid) {
    const wanted = aaguidHex(aaguid);
    if (wanted.length !== 32) {
        return [];
    }
    return rows.filter(row => aaguidHex(row.aaguid) === wanted);
}
