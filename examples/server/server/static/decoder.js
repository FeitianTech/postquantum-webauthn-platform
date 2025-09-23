import { showStatus, hideStatus } from './status.js';

export async function decodeResponse() {
    const input = document.getElementById('decoder-input');
    if (!input) {
        return;
    }

    const inputValue = input.value;
    if (!inputValue.trim()) {
        showStatus('decoder', 'Decoder is empty. Please paste something to decode.', 'error');
        return;
    }

    const decoderOutput = document.getElementById('decoder-output');
    const decodedContent = document.getElementById('decoded-content');

    if (decodedContent) {
        decodedContent.value = '';
    }
    if (decoderOutput) {
        decoderOutput.style.display = 'none';
    }
    hideStatus('decoder');

    try {
        const response = await fetch('/api/decode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ payload: inputValue }),
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (parseError) {
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            throw new Error('Failed to parse decoder response.');
        }

        if (!response.ok) {
            const message = payload && payload.error
                ? payload.error
                : `Server responded with status ${response.status}`;
            throw new Error(message);
        }

        if (decodedContent) {
            decodedContent.value = JSON.stringify(payload, null, 2);
        }
        if (decoderOutput) {
            decoderOutput.style.display = 'block';
        }
        showStatus('decoder', 'Response decoded successfully!', 'success');
    } catch (error) {
        if (decoderOutput) {
            decoderOutput.style.display = 'none';
        }
        const message = error instanceof Error ? error.message : String(error);
        showStatus('decoder', `Decoding failed: ${message}`, 'error');
    }
}

export function clearDecoder() {
    const input = document.getElementById('decoder-input');
    const output = document.getElementById('decoder-output');
    const decodedContent = document.getElementById('decoded-content');

    if (input) {
        input.value = '';
    }
    if (decodedContent) {
        decodedContent.value = '';
    }
    if (output) {
        output.style.display = 'none';
    }
    hideStatus('decoder');
}
