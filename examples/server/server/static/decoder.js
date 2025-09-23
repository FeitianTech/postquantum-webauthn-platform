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
    const rawContainer = document.getElementById('decoder-raw-container');
    const rawContent = document.getElementById('decoder-raw-content');
    const toggleButton = document.getElementById('decoder-toggle-raw');

    if (decodedContent) {
        decodedContent.value = '';
    }
    if (rawContent) {
        rawContent.value = '';
    }
    if (rawContainer) {
        rawContainer.style.display = 'none';
    }
    if (toggleButton) {
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
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
            decodedContent.value = payload && typeof payload.summary === 'string'
                ? payload.summary
                : '';
        }
        if (rawContent) {
            if (payload && payload.raw !== undefined) {
                rawContent.value = JSON.stringify(payload.raw, null, 2);
            } else {
                rawContent.value = '';
            }
        }
        if (decoderOutput) {
            decoderOutput.style.display = 'block';
        }
        if (toggleButton) {
            toggleButton.textContent = 'Show raw';
            toggleButton.dataset.expanded = 'false';
        }
        if (rawContainer) {
            rawContainer.style.display = 'none';
        }
        showStatus('decoder', 'Response decoded successfully!', 'success');
    } catch (error) {
        if (decoderOutput) {
            decoderOutput.style.display = 'none';
        }
        if (rawContainer) {
            rawContainer.style.display = 'none';
        }
        if (toggleButton) {
            toggleButton.textContent = 'Show raw';
            toggleButton.dataset.expanded = 'false';
        }
        const message = error instanceof Error ? error.message : String(error);
        showStatus('decoder', `Decoding failed: ${message}`, 'error');
    }
}

export function clearDecoder() {
    const input = document.getElementById('decoder-input');
    const output = document.getElementById('decoder-output');
    const decodedContent = document.getElementById('decoded-content');
    const rawContainer = document.getElementById('decoder-raw-container');
    const rawContent = document.getElementById('decoder-raw-content');
    const toggleButton = document.getElementById('decoder-toggle-raw');

    if (input) {
        input.value = '';
    }
    if (decodedContent) {
        decodedContent.value = '';
    }
    if (rawContent) {
        rawContent.value = '';
    }
    if (rawContainer) {
        rawContainer.style.display = 'none';
    }
    if (toggleButton) {
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
    }
    if (output) {
        output.style.display = 'none';
    }
    hideStatus('decoder');
}

export function toggleRawDecoder() {
    const rawContainer = document.getElementById('decoder-raw-container');
    const toggleButton = document.getElementById('decoder-toggle-raw');
    if (!rawContainer || !toggleButton) {
        return;
    }

    const expanded = toggleButton.dataset.expanded === 'true';
    if (expanded) {
        rawContainer.style.display = 'none';
        toggleButton.textContent = 'Show raw';
        toggleButton.dataset.expanded = 'false';
    } else {
        rawContainer.style.display = 'block';
        toggleButton.textContent = 'Hide raw';
        toggleButton.dataset.expanded = 'true';
    }
}
