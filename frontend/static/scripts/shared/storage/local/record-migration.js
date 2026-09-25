// Records saved by earlier versions, brought to today's format when they are read.
//
// Registration detail used to be stored as composed HTML: in the snapshot and
// under raw registrationDetailHtml-style keys. The detail view is now built from
// data and never reads markup, so the markup is dropped; the snapshot's
// structured state stays.

const RECORD_MARKUP_KEYS = [
    'registrationDetailHtml',
    'registration_detail_html',
    'registrationDetailCombinedHtml',
    'registration_detail_combined_html',
];

const SNAPSHOT_KEYS = [
    'registrationDetailSnapshot',
    'registration_detail_snapshot',
    'registrationDetailCopy',
    'registration_detail_copy',
];

const SNAPSHOT_MARKUP_KEYS = ['html', 'attestationSectionHtml', 'combinedHtml'];

function hasOwn(target, key) {
    return Object.prototype.hasOwnProperty.call(target, key);
}

/** The record in today's format, and whether anything had to change. */
export function migrateStoredRecord(record) {
    if (!record || typeof record !== 'object') {
        return { record, changed: false };
    }

    let migrated = record;
    const edit = () => {
        if (migrated === record) {
            migrated = { ...record };
        }
        return migrated;
    };

    RECORD_MARKUP_KEYS.forEach(key => {
        if (hasOwn(migrated, key)) {
            delete edit()[key];
        }
    });

    SNAPSHOT_KEYS.forEach(key => {
        const snapshot = migrated[key];
        if (!snapshot || typeof snapshot !== 'object' || !SNAPSHOT_MARKUP_KEYS.some(name => hasOwn(snapshot, name))) {
            return;
        }
        const cleaned = { ...snapshot };
        SNAPSHOT_MARKUP_KEYS.forEach(name => {
            delete cleaned[name];
        });
        // A snapshot that held only markup holds nothing now; without it the
        // record is completed from its server artifact again.
        if (cleaned.state || cleaned.stateSnapshot || cleaned.response) {
            edit()[key] = cleaned;
        } else {
            delete edit()[key];
        }
    });

    return { record: migrated, changed: migrated !== record };
}
