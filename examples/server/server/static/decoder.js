// WebAuthn FIDO2 Test Application - Decoder Functions

// Decoder Functions
function decodeResponse() {
    const input = document.getElementById('decoder-input');
    if (!input) {
        if (window.console && console.error) {
            console.error('Decoder input element not found');
        }
        return;
    }
    
    const inputValue = input.value;
    if (!inputValue.trim()) {
        showStatus('decoder', 'Please paste a WebAuthn response to decode', 'error');
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
        } else {
            if (window.console && console.error) {
                console.error('Decoder output elements not found');
            }
        }
    } catch (error) {
        showStatus('decoder', `Decoding failed: ${error.message}`, 'error');
    }
}

function clearDecoder() {
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

function analyzeWebAuthnResponse(response) {
    const analysis = {
        type: 'Unknown',
        rawResponse: response,
        decodedFields: {}
    };

    // Detect if it's a registration or authentication response
    if (response.response && response.response.attestationObject) {
        analysis.type = 'Registration Response';
        analysis.decodedFields = {
            credentialId: response.id,
            credentialType: response.type,
            authenticatorAttachment: response.authenticatorAttachment,
            clientDataJSON: tryDecodeBase64Url(response.response.clientDataJSON),
            attestationObject: 'Base64URL encoded - contains authenticator data and attestation statement'
        };
        
        // Try to decode more fields if possible
        if (response.response.clientDataJSON) {
            try {
                const clientData = JSON.parse(atob(response.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')));
                analysis.decodedFields.clientDataDecoded = clientData;
            } catch (e) {
                // Ignore decode errors
            }
        }
        
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
        
        // Try to decode client data
        if (response.response.clientDataJSON) {
            try {
                const clientData = JSON.parse(atob(response.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')));
                analysis.decodedFields.clientDataDecoded = clientData;
            } catch (e) {
                // Ignore decode errors
            }
        }
    }

    // Check for extension outputs
    if (response.clientExtensionResults) {
        analysis.decodedFields.clientExtensionResults = response.clientExtensionResults;
    }

    return analysis;
}

function tryDecodeBase64Url(encoded) {
    if (!encoded) return 'No data';
    
    try {
        // Convert base64url to base64
        let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
        
        // Add padding if needed
        while (base64.length % 4) {
            base64 += '=';
        }
        
        const decoded = atob(base64);
        
        // Try to parse as JSON first
        try {
            return JSON.parse(decoded);
        } catch (jsonError) {
            // If not JSON, return as string
            return decoded;
        }
    } catch (error) {
        return `Could not decode: ${encoded}`;
    }
}

// Make functions globally available
window.decodeResponse = decodeResponse;
window.clearDecoder = clearDecoder;
window.analyzeWebAuthnResponse = analyzeWebAuthnResponse;
window.tryDecodeBase64Url = tryDecodeBase64Url;