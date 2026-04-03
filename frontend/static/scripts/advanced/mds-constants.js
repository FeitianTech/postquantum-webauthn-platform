export const MDS_EXPLORER_PATH = 'api/mds/metadata/explorer';
export const MDS_RESOLVE_PATH = 'api/mds/metadata/resolve';
export const MDS_VERIFIED_META_PATH = 'fido-mds3.verified.json.meta.json';
export const CUSTOM_METADATA_LIST_PATH = 'api/mds/metadata/custom';
export const CUSTOM_METADATA_UPLOAD_PATH = 'api/mds/metadata/upload';
export const CUSTOM_METADATA_DELETE_PATH = 'api/mds/metadata/custom';
export const COLUMN_COUNT = 13;
export const MISSING_METADATA_MESSAGE =
    'Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present.';

export const UPDATE_BUTTON_STATES = {
    update: { label: 'Refresh Metadata', busyLabel: 'Refreshing…' },
    download: { label: 'Refresh Metadata', busyLabel: 'Refreshing…' },
};

export const CERTIFICATION_OPTIONS = [
    'FIDO_CERTIFIED',
    'FIDO_CERTIFIED_L1',
    'FIDO_CERTIFIED_L2',
    'NOT_FIDO_CERTIFIED',
    'REVOKED',
];

export const FILTER_CONFIG = [
    { key: 'name', inputId: 'mds-filter-name' },
    { key: 'protocol', inputId: 'mds-filter-protocol', optionsKey: 'protocol' },
    {
        key: 'certification',
        inputId: 'mds-filter-certification',
        optionsKey: 'certification',
        staticOptions: CERTIFICATION_OPTIONS,
    },
    { key: 'id', inputId: 'mds-filter-id' },
    {
        key: 'userVerification',
        inputId: 'mds-filter-user-verification',
        optionsKey: 'userVerification',
        expandDropdown: true,
    },
    { key: 'attachment', inputId: 'mds-filter-attachment', optionsKey: 'attachment' },
    { key: 'transports', inputId: 'mds-filter-transports', optionsKey: 'transports' },
    { key: 'keyProtection', inputId: 'mds-filter-key-protection', optionsKey: 'keyProtection' },
    {
        key: 'algorithms',
        inputId: 'mds-filter-algorithms',
        optionsKey: 'algorithms',
        expandDropdown: true,
    },
    { key: 'algorithmInfo', inputId: 'mds-filter-algorithm-info' },
    { key: 'commonName', inputId: 'mds-filter-common-name' },
];

export const FILTER_LOOKUP = FILTER_CONFIG.reduce((map, config) => {
    map[config.key] = config;
    return map;
}, {});
