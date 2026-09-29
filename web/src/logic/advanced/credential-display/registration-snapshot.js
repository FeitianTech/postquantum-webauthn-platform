// What a registration's result keeps once it is composed: the registration as
// data, saved as the record's snapshot (schemaVersion 2) in the browser and on
// the server, so its details build from it without asking again. DOM-free.
import { registrationResultInput, registrationSnapshotPayload } from './registration-view.js';

/**
 * Composes the registration the browser's credential and the relying party's
 * answer describe (`compose(input)`, into the state its caller keeps), then, for
 * a record the browser saved (`storageId`), saves the snapshot
 * (`saveSnapshot(storageId, payload)`, true when anything changed). Gives the
 * composition and whether the snapshot changed anything.
 */
export async function keepRegistrationSnapshot(
    { credentialJson, relyingPartyInfo, storageId = null },
    { compose, saveSnapshot, now = () => new Date().toISOString() },
) {
    const composed = await compose({
        credentialJson,
        relyingPartyInfo,
        ...registrationResultInput(credentialJson, relyingPartyInfo),
    });

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
    }, now());
    return { composed, saved: Boolean(await saveSnapshot(storageId, payload)) };
}
