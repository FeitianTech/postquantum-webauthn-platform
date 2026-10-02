// The saved credentials, as both tabs read and write them: one localStorage
// array of simple and advanced records (local/constants.js), read once and then
// kept in step with every save (local/storage-core.js). It reads no page. Each
// kind's reads and writes are in local/simple-credentials.js and
// local/advanced-credentials.js, the server sync in local/advanced-sync.js.
import {
    cloneAdvancedStoredRecord,
} from './local/advanced-storage-shaping.js';
import { readUnifiedCredentialRecords } from './local/storage-core.js';

// Every record, simple and advanced, in the order stored. The unified read gives
// only objects typed "simple" or "advanced" (local/storage-core.js); each is a
// copy, so a caller cannot change the stored records by changing it.
export function getAllStoredCredentialsInOrder() {
    return readUnifiedCredentialRecords().map(record => (
        record.type === 'advanced' ? cloneAdvancedStoredRecord(record) : { ...record }
    ));
}
