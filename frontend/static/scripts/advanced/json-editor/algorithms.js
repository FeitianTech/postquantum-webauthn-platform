const ALGORITHM_CHECKBOX_CONFIG = [
    { id: 'param-mldsa44', alg: -48, label: 'ML-DSA-44', requiredForFormSync: false },
    { id: 'param-mldsa65', alg: -49, label: 'ML-DSA-65', requiredForFormSync: false },
    { id: 'param-mldsa87', alg: -50, label: 'ML-DSA-87', requiredForFormSync: false },
    { id: 'param-eddsa', alg: -8, label: 'EdDSA', requiredForFormSync: true },
    { id: 'param-es256', alg: -7, label: 'ES256', requiredForFormSync: true },
    { id: 'param-rs256', alg: -257, label: 'RS256', requiredForFormSync: true },
    { id: 'param-es384', alg: -35, label: 'ES384', requiredForFormSync: true },
    { id: 'param-es512', alg: -36, label: 'ES512', requiredForFormSync: true },
    { id: 'param-rs384', alg: -258, label: 'RS384', requiredForFormSync: true },
    { id: 'param-rs512', alg: -259, label: 'RS512', requiredForFormSync: true },
    { id: 'param-rs1', alg: -65535, label: 'RS1', requiredForFormSync: true },
    { id: 'param-ed25519', alg: -19, label: 'Ed25519', requiredForFormSync: true },
    { id: 'param-es256k', alg: -47, label: 'ES256K', requiredForFormSync: true },
    { id: 'param-esp256', alg: -9, label: 'ESP256', requiredForFormSync: true },
    { id: 'param-esp384', alg: -51, label: 'ESP384', requiredForFormSync: true },
    { id: 'param-esp512', alg: -52, label: 'ESP512', requiredForFormSync: true },
    { id: 'param-ps256', alg: -37, label: 'PS256', requiredForFormSync: true },
    { id: 'param-ps384', alg: -38, label: 'PS384', requiredForFormSync: true },
    { id: 'param-ps512', alg: -39, label: 'PS512', requiredForFormSync: true },
    { id: 'param-ed448', alg: -53, label: 'Ed448', requiredForFormSync: true },
];

const ALGORITHM_BY_ID = new Map(ALGORITHM_CHECKBOX_CONFIG.map(entry => [entry.alg, entry]));

function setCheckboxValue(id, checked, requiredForFormSync) {
    const checkbox = document.getElementById(id);
    if (requiredForFormSync) {
        checkbox.checked = checked;
        return;
    }
    if (checkbox) {
        checkbox.checked = checked;
    }
}

export function appendSelectedAlgorithmParams(pubKeyCredParams) {
    ALGORITHM_CHECKBOX_CONFIG.forEach(entry => {
        if (document.getElementById(entry.id)?.checked) {
            pubKeyCredParams.push({
                type: 'public-key',
                alg: entry.alg,
            });
        }
    });
}

export function appendSelectedAlgorithmLabels(target) {
    ALGORITHM_CHECKBOX_CONFIG.forEach(entry => {
        if (document.getElementById(entry.id)?.checked) {
            target.push(entry.label);
        }
    });
}

export function clearRegistrationAlgorithmCheckboxesForFormSync() {
    ALGORITHM_CHECKBOX_CONFIG.forEach(entry => {
        setCheckboxValue(entry.id, false, entry.requiredForFormSync);
    });
}

export function applyRegistrationAlgorithmSelection(rawAlg) {
    const algValue = typeof rawAlg === 'string' ? Number.parseInt(rawAlg, 10) : rawAlg;
    if (Number.isNaN(algValue)) {
        return;
    }

    const config = ALGORITHM_BY_ID.get(algValue);
    if (!config) {
        return;
    }

    setCheckboxValue(config.id, true, config.requiredForFormSync);
}
