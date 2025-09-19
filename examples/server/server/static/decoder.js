import { showStatus, hideStatus } from './status.js';

export function decodeResponse() {
    const input = document.getElementById('decoder-input');
    if (!input) {
        return;
    }

    const inputValue = input.value;
    if (!inputValue.trim()) {
        showStatus('decoder', 'Decoder is empty. Please paste something to decode. ', 'error');
        return;
    }

    try {
        const parsed = JSON.parse(inputValue);
        const decoded = analyzeWebAuthnResponse(parsed);

        const decodedContent = document.getElementById('decoded-content');
        const decoderOutput = document.getElementById('decoder-output');

        if (decodedContent && decoderOutput) {
            decodedContent.innerHTML = `<pre>${JSON.stringify(decoded, null, 2)}</pre>`;
            decoderOutput.style.display = 'block';
            showStatus('decoder', 'Response decoded successfully!', 'success');
        }
    } catch (error) {
        showStatus('decoder', `Decoding failed: ${error.message}`, 'error');
    }
}

export function clearDecoder() {
    const input = document.getElementById('decoder-input');
    const output = document.getElementById('decoder-output');

    if (input) {
        input.value = '';
    }
    if (output) {
        output.style.display = 'none';
    }
    hideStatus('decoder');
}

export function analyzeWebAuthnResponse(response) {
    const analysis = {
        type: 'Unknown',
        rawResponse: response,
        decodedFields: {}
    };

    if (response.response && response.response.attestationObject) {
        analysis.type = 'Registration Response';
        analysis.decodedFields = {
            credentialId: response.id,
            credentialType: response.type,
            authenticatorAttachment: response.authenticatorAttachment,
            clientDataJSON: tryDecodeBase64Url(response.response.clientDataJSON),
            attestationObject: 'Base64URL encoded - contains authenticator data and attestation statement'
        };
    } else if (response.response && response.response.authenticatorData) {
        analysis.type = 'Authentication Response';
        analysis.decodedFields = {
            credentialId: response.id,
            credentialType: response.type,
            authenticatorAttachment: response.authenticatorAttachment,
            clientDataJSON: tryDecodeBase64Url(response.response.clientDataJSON),
            authenticatorData: 'Base64URL encoded - contains RP ID hash, flags, counter, etc.',
            signature: 'Base64URL encoded signature'
        };
    }

    return analysis;
}

function tryDecodeBase64Url(encoded) {
    try {
        const decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(decoded);
    } catch (error) {
        return 'Could not decode as JSON: ' + encoded;
    }
}
