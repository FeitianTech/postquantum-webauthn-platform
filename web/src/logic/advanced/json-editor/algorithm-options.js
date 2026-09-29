// The signature algorithms the registration form offers, in the order the
// request lists them (the most preferred first): the three ML-DSA parameter
// sets, then the classical ones. DOM-free: the current form's checkboxes
// (./algorithms.js) and the new UI's chips are both built from it.
export const ALGORITHM_OPTIONS = [
    { key: 'mldsa44', alg: -48, label: 'ML-DSA-44', pqc: true },
    { key: 'mldsa65', alg: -49, label: 'ML-DSA-65', pqc: true },
    { key: 'mldsa87', alg: -50, label: 'ML-DSA-87', pqc: true },
    { key: 'eddsa', alg: -8, label: 'EdDSA', pqc: false },
    { key: 'es256', alg: -7, label: 'ES256', pqc: false },
    { key: 'rs256', alg: -257, label: 'RS256', pqc: false },
    { key: 'es384', alg: -35, label: 'ES384', pqc: false },
    { key: 'es512', alg: -36, label: 'ES512', pqc: false },
    { key: 'rs384', alg: -258, label: 'RS384', pqc: false },
    { key: 'rs512', alg: -259, label: 'RS512', pqc: false },
    { key: 'rs1', alg: -65535, label: 'RS1', pqc: false },
    { key: 'ed25519', alg: -19, label: 'Ed25519', pqc: false },
    { key: 'es256k', alg: -47, label: 'ES256K', pqc: false },
    { key: 'esp256', alg: -9, label: 'ESP256', pqc: false },
    { key: 'esp384', alg: -51, label: 'ESP384', pqc: false },
    { key: 'esp512', alg: -52, label: 'ESP512', pqc: false },
    { key: 'ps256', alg: -37, label: 'PS256', pqc: false },
    { key: 'ps384', alg: -38, label: 'PS384', pqc: false },
    { key: 'ps512', alg: -39, label: 'PS512', pqc: false },
    { key: 'ed448', alg: -53, label: 'Ed448', pqc: false },
];
