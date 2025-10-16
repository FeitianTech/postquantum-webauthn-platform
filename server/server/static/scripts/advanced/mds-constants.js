export const MDS_HTML_PATH = 'templates/advanced/mds-content.html';
export const MDS_METADATA_PATH = 'fido-mds3.verified.json';
export const CUSTOM_METADATA_LIST_PATH = 'api/mds/metadata/custom';
export const CUSTOM_METADATA_UPLOAD_PATH = 'api/mds/metadata/upload';
export const CUSTOM_METADATA_DELETE_PATH = 'api/mds/metadata/custom';
export const COLUMN_COUNT = 13;
export const MISSING_METADATA_MESSAGE =
    'Metadata has not been downloaded yet. Ensure the automatic metadata updater is running.';

export const UPDATE_BUTTON_STATES = {
    update: { label: 'Update Metadata', busyLabel: 'Updating…' },
    download: { label: 'Download Metadata', busyLabel: 'Downloading…' },
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
