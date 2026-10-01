export const MDS_EXPLORER_FULL_PATH = '/api/mds/metadata/explorer/full';
export const MDS_INFO_PATH = '/api/mds/metadata/info';
export const MDS_RESOLVE_PATH = '/api/mds/metadata/resolve';
export const CUSTOM_METADATA_LIST_PATH = '/api/mds/metadata/custom';
export const CUSTOM_METADATA_UPLOAD_PATH = '/api/mds/metadata/upload';
export const CUSTOM_METADATA_DELETE_PATH = '/api/mds/metadata/custom';
export const MISSING_METADATA_MESSAGE =
    'Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present.';

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
