export const COSE_ALGORITHM_LABELS = {
    '-50': 'ML-DSA-87 (PQC) (-50)',
    '-49': 'ML-DSA-65 (PQC) (-49)',
    '-48': 'ML-DSA-44 (PQC) (-48)',
    '-8': 'EdDSA (-8)',
    '-7': 'ES256 (-7)',
    '-37': 'PS256 (-37)',
    '-35': 'ES384 (-35)',
    '-36': 'ES512 (-36)',
    '-47': 'ES256K (-47)',
    '-257': 'RS256 (-257)',
    '-258': 'RS384 (-258)',
    '-259': 'RS512 (-259)',
    '-65535': 'RS1 (-65535)'
};

export const COSE_KEY_TYPE_LABELS = {
    '1': 'OKP (1)',
    '2': 'EC2 (2)',
    '3': 'RSA (3)',
    '4': 'Symmetric (4)',
    '7': 'ML-DSA (7)'
};

export const HINT_ATTACHMENT_MAP = {
    'security-key': 'cross-platform',
    'hybrid': 'cross-platform',
    'client-device': 'platform',
};

export const ATTACHMENT_LABELS = {
    'cross-platform': 'Cross-platform (Security key / Hybrid)',
    'platform': 'Platform (Client device)',
};

export const JSON_EDITOR_INDENT_UNIT = '  ';
