import { ALGORITHM_OPTIONS } from './algorithm-options.js';

// The form's checkboxes, param-<key>: the ML-DSA ones may be absent from a page.
const ALGORITHM_CHECKBOX_CONFIG = ALGORITHM_OPTIONS.map(({ key, alg, label, pqc }) => ({
    id: `param-${key}`,
    alg,
    label,
    requiredForFormSync: !pqc,
}));

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
