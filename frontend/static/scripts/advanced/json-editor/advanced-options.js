import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
} from '../../shared/utils/binary.js';
import { collectSelectedHints } from '../hints.js';
import { appendSelectedAlgorithmLabels } from './algorithms.js';

export function getAdvancedCreateOptions() {
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        username: document.getElementById('user-name').value,
        displayName: document.getElementById('user-display-name').value || document.getElementById('user-name').value,
        userId: convertFormat(document.getElementById('user-id').value, currentFormat, 'hex'),

        attestation: document.getElementById('attestation').value,
        userVerification: document.getElementById('user-verification-reg').value,
        residentKey: document.getElementById('resident-key').value,
        authenticatorAttachment: document.getElementById('authenticator-attachment').value || 'cross-platform',

        excludeCredentials: document.getElementById('exclude-credentials').checked,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-reg').value) || 0,

        challenge: convertFormat(document.getElementById('challenge-reg').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-reg').value) || 90000,

        pubKeyCredParams: [],
        hints: [],
        extensions: {},
    };

    appendSelectedAlgorithmLabels(options.pubKeyCredParams);

    options.hints = collectSelectedHints('registration');
    if (document.getElementById('cred-props')?.checked) {
        options.extensions.credProps = true;
    }

    if (document.getElementById('min-pin-length')?.checked) {
        options.extensions.minPinLength = true;
    }

    const credProtect = document.getElementById('cred-protect')?.value;
    if (credProtect && credProtect !== '') {
        options.extensions.credentialProtectionPolicy = credProtect;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            options.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlob = document.getElementById('large-blob-reg')?.value;
    if (largeBlob && largeBlob !== '') {
        options.extensions.largeBlob = { support: largeBlob };
    }

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            options.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst),
                },
            };
            if (prfSecond) {
                options.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    return options;
}

export function getAdvancedAssertOptions() {
    const allowCreds = document.getElementById('allow-credentials').value;
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        userVerification: document.getElementById('user-verification-auth').value,
        allowCredentials: allowCreds,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-auth').value) || 0,
        challenge: convertFormat(document.getElementById('challenge-auth').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-auth').value) || 90000,
        extensions: {},
    };

    if (allowCreds !== 'all' && allowCreds !== 'empty') {
        options.specificCredentialId = allowCreds;
    }

    const largeBlob = document.getElementById('large-blob-auth')?.value;
    if (largeBlob === 'read') {
        options.extensions.largeBlob = { read: true };
    } else if (largeBlob === 'write') {
        const largeBlobWrite = document.getElementById('large-blob-write')?.value;
        if (largeBlobWrite) {
            options.extensions.largeBlob = {
                write: currentFormatToJsonFormat(largeBlobWrite),
            };
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
    if (prfFirst || prfSecond) {
        const prfEval = {};
        if (prfFirst) {
            prfEval.first = currentFormatToJsonFormat(prfFirst);
        }
        if (prfSecond) {
            prfEval.second = currentFormatToJsonFormat(prfSecond);
        }
        if (Object.keys(prfEval).length > 0) {
            options.extensions.prf = { eval: prfEval };
        }
    }

    options.hints = collectSelectedHints('authentication');
    return options;
}
