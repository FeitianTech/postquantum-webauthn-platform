// What a registration's result keeps once it is composed: the registration as
// data, saved as the record's snapshot (schemaVersion 2) in the browser and on
// the server, so its details build from it without asking again. DOM-free.
import { updateAdvancedCredentialRegistrationSnapshot } from '../storage/local/advanced-snapshot-update.js';
import { decodePayloadThroughApi } from './decode-payload.js';
import { createRegistrationState } from './state.js';
import { composeRegistration, registrationResultInput, registrationSnapshotPayload } from './view.js';

/**
 * Composes the registration the browser's credential and the relying party's
 * answer describe, into a state of its own, through the server's decoder; then,
 * for a record the browser saved (`storageId`), saves the snapshot, captured now,
 * into it. Gives the composition and whether the snapshot changed anything.
 * @param {{ credentialJson: Record<string, any>, relyingPartyInfo: Record<string, any> | null, storageId?: string | null }} result
 */
export async function keepRegistrationSnapshot({ credentialJson, relyingPartyInfo, storageId = null }) {
    const composed = await composeRegistration({
        credentialJson,
        relyingPartyInfo,
        ...registrationResultInput(credentialJson, relyingPartyInfo),
    }, { state: createRegistrationState(), decode: decodePayloadThroughApi });

    if (!storageId || !composed) {
        return { composed, saved: false };
    }
    // The registration is kept as data -- the response and the relying party's
    // view of it, with the decoded attestation in `state` -- and the details
    // build their view from that. No markup is stored.
    const payload = registrationSnapshotPayload({
        stateSnapshot: composed.stateSnapshot,
        credentialJson,
        relyingPartyCopy: composed.relyingPartyCopy,
    }, new Date().toISOString());
    return { composed, saved: Boolean(await updateAdvancedCredentialRegistrationSnapshot(storageId, payload)) };
}
