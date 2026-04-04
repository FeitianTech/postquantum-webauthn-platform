import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/status.js', () => ({
  hideProgress: vi.fn(),
  hideStatus: vi.fn(),
  showProgress: vi.fn(),
  showStatus: vi.fn(),
}));

vi.mock('../../static/scripts/shared/ui.js', () => ({
  closeModal: vi.fn(),
  openModal: vi.fn(),
}));

import { hideProgress, hideStatus, showStatus } from '../../static/scripts/shared/status.js';
import { closeModal, openModal } from '../../static/scripts/shared/ui.js';
import { clearCodec, processCodec, switchCodecMode, toggleRawCodec } from '../../static/scripts/decoder/codec.js';

function buildCodecDom() {
  document.body.innerHTML = `
    <button id="codec-mode-decode" class="active"></button>
    <button id="codec-mode-encode"></button>
    <div id="codec-mode-content"></div>

    <section id="codec-decode-panel" class="is-active"></section>
    <textarea id="decoder-input"></textarea>
    <p id="decoder-description">Decoder help text</p>
    <div id="decoder-output">
      <div id="decoded-content"></div>
    </div>
    <button id="decoder-toggle-raw" disabled></button>
    <textarea id="decoder-raw-content"></textarea>
    <div id="decoder-raw-modal" class="modal"></div>
    <div id="decoder-progress"></div>
    <div id="decoder-progress-text"></div>

    <section id="codec-encode-panel" hidden></section>
    <textarea id="encoder-input"></textarea>
    <div id="encoder-output">
      <div id="encoded-content"></div>
    </div>
    <button id="encoder-toggle-raw" disabled></button>
    <textarea id="encoder-raw-content"></textarea>
    <div id="encoder-raw-modal" class="modal"></div>
    <div id="encoder-progress"></div>
    <div id="encoder-progress-text"></div>
    <select id="encoder-format">
      <option value=""></option>
      <option value="json">json</option>
      <option value="pem">pem</option>
    </select>
  `;
}

describe('codec UI', () => {
  beforeEach(() => {
    buildCodecDom();
    vi.clearAllMocks();
    switchCodecMode('decode');
  });

  it('switches between decode and encode modes', () => {
    switchCodecMode('encode');
    expect(document.getElementById('codec-mode-encode').classList.contains('active')).toBe(true);
    expect(document.getElementById('codec-encode-panel').hidden).toBe(false);
    expect(hideStatus).toHaveBeenCalledWith('decoder');
    expect(hideStatus).toHaveBeenCalledWith('encoder');

    const content = document.getElementById('codec-mode-content');
    expect(content.classList.contains('codec-mode-animating')).toBe(true);
    content.dispatchEvent(new Event('animationend'));
    expect(content.classList.contains('codec-mode-animating')).toBe(false);
  });

  it('clears codec fields and modal state', () => {
    document.getElementById('decoder-input').value = 'payload';
    document.getElementById('decoded-content').innerHTML = '<p>value</p>';
    document.getElementById('decoder-raw-content').textContent = '{"ok":true}';
    document.getElementById('decoder-output').classList.add('is-visible');
    document.getElementById('decoder-raw-modal').classList.add('open');

    clearCodec('decode');

    expect(document.getElementById('decoder-input').value).toBe('');
    expect(document.getElementById('decoded-content').innerHTML).toBe('');
    expect(document.getElementById('decoder-output').classList.contains('is-visible')).toBe(false);
    expect(closeModal).toHaveBeenCalledWith('decoder-raw-modal');
    expect(hideProgress).toHaveBeenCalledWith('decoder');
  });

  it('toggles raw modal visibility only when content exists', () => {
    const rawButton = document.getElementById('decoder-toggle-raw');
    const rawContent = document.getElementById('decoder-raw-content');
    rawButton.disabled = false;
    rawContent.textContent = '{"ok":true}';

    toggleRawCodec('decode');
    expect(openModal).toHaveBeenCalledWith('decoder-raw-modal');

    document.getElementById('decoder-raw-modal').classList.add('open');
    toggleRawCodec('decode');
    expect(closeModal).toHaveBeenCalledWith('decoder-raw-modal');
  });

  it('reports validation errors for missing codec input', async () => {
    await processCodec('decode');
    expect(showStatus).toHaveBeenCalledWith('decoder', 'Codec input is empty. Please paste something to process.', 'error');
  });

  it('encodes JSON input and renders the response', async () => {
    switchCodecMode('encode');
    document.getElementById('encoder-input').value = '{"hello":"world"}';
    document.getElementById('encoder-format').value = 'json';
    fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        type: 'JSON',
        encodedValue: 'eyJoZWxsbyI6IndvcmxkIn0=',
        structure: { hello: 'world' },
      }),
    });

    await processCodec('encode');

    expect(fetch).toHaveBeenCalledWith('/api/codec', expect.objectContaining({
      method: 'POST',
    }));
    expect(document.getElementById('encoder-output').classList.contains('is-visible')).toBe(true);
    expect(document.getElementById('encoder-raw-content').textContent).toContain('"success": true');
    expect(document.getElementById('encoder-toggle-raw').disabled).toBe(false);
  });

  it('rejects encode requests without a format, with invalid json, or unsupported binary conversion', async () => {
    switchCodecMode('encode');

    document.getElementById('encoder-input').value = '{"hello":"world"}';
    document.getElementById('encoder-format').value = '';
    await processCodec('encode');
    expect(showStatus).toHaveBeenLastCalledWith('encoder', 'Select an encoding format before encoding.', 'error');

    document.getElementById('encoder-format').value = 'json';
    document.getElementById('encoder-input').value = '{invalid';
    await processCodec('encode');
    expect(showStatus).toHaveBeenLastCalledWith('encoder', 'Encoder expects valid JSON input.', 'error');

    document.getElementById('encoder-format').value = 'pem';
    document.getElementById('encoder-input').value = '{"hello":"not@@binary"}';
    await processCodec('encode');
    expect(showStatus).toHaveBeenLastCalledWith('encoder', 'Input cannot be converted into pem.', 'error');
  });

  it('handles decode server failures and parse errors with clear status feedback', async () => {
    document.getElementById('decoder-input').value = 'AQID';

    fetch.mockResolvedValueOnce({
      ok: false,
      status: 422,
      json: vi.fn().mockResolvedValue({ error: 'bad payload' }),
    });
    await processCodec('decode');
    expect(showStatus).toHaveBeenLastCalledWith('decoder', 'Decoding failed: bad payload', 'error');

    fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockRejectedValue(new Error('invalid json')),
    });
    await processCodec('decode');
    expect(showStatus).toHaveBeenLastCalledWith('decoder', 'Decoding failed: Failed to parse decoder response.', 'error');

    fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: vi.fn().mockRejectedValue(new Error('bad json')),
    });
    await processCodec('decode');
    expect(showStatus).toHaveBeenLastCalledWith('decoder', 'Decoding failed: Server responded with status 500', 'error');
  });

  it('renders rich decode structures and hides the empty-state description', async () => {
    document.getElementById('decoder-input').value = 'AQID';

    fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        type: 'PublicKeyCredential',
        malformed: ['padding-byte'],
        data: {
          expandedJson: {
            topLevel: true,
          },
          credential: {
            id: 'cred-id',
            type: 'public-key',
          },
          attestationObject: {
            expandedJson: {
              nested: {
                count: 2,
              },
            },
            authenticatorData: {
              counter: 3,
            },
          },
          clientDataJSON: 'line-1\nline-2',
          clientExtensionResults: {
            credProps: { rk: true },
          },
          responseDetails: [
            { label: 'first' },
            2,
            true,
          ],
        },
      }),
    });

    await processCodec('decode');

    expect(document.getElementById('decoder-output').classList.contains('is-visible')).toBe(true);
    expect(document.getElementById('decoded-content').textContent).toContain('Malformed segments: padding-byte');
    expect(document.querySelector('.decoder-expanded-json')).not.toBeNull();
    expect(document.getElementById('decoder-description').style.display).toBe('none');
    expect(document.getElementById('decoder-toggle-raw').disabled).toBe(false);
  });

  it('handles encode server failure and nested encoded summary rendering', async () => {
    switchCodecMode('encode');

    document.getElementById('encoder-format').value = 'json';
    document.getElementById('encoder-input').value = '{"payload":"ok"}';

    fetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: vi.fn().mockResolvedValue({ error: 'cannot encode payload' }),
    });

    await processCodec('encode');
    expect(showStatus).toHaveBeenLastCalledWith('encoder', 'Encoding failed: cannot encode payload', 'error');

    fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        type: 'CBOR',
        data: {
          binary: {
            hex: 'aabbccdd',
            base64: 'qrvM3Q==',
            base64url: 'qrvM3Q',
            byteLength: 4,
            encoding: 'cbor',
          },
        },
      }),
    });

    await processCodec('encode');
    expect(document.getElementById('encoded-content').textContent).toContain('Encoded output');
    expect(document.getElementById('encoded-content').textContent).toContain('Byte length: 4');
    expect(document.getElementById('encoder-toggle-raw').disabled).toBe(false);
  });

  it('accepts integer-byte arrays and nested array/object payloads for binary encode formats', async () => {
    switchCodecMode('encode');
    document.getElementById('encoder-format').value = 'pem';

    document.getElementById('encoder-input').value = '{"bytes":[1,2,3,4]}';
    fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({ success: true, type: 'PEM', encodedValue: 'LS0tLUJFR0lO' }),
    });
    await processCodec('encode');
    expect(fetch).toHaveBeenCalledTimes(1);

    document.getElementById('encoder-input').value = '{"bytes":[{"value":"QUJD"}]}';
    fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({ success: true, type: 'PEM', encodedValue: 'LS0tLUVORA==' }),
    });
    await processCodec('encode');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('clears encode mode state and respects raw toggle guard rails', () => {
    switchCodecMode('encode');
    document.getElementById('encoder-input').value = '{"test":1}';
    document.getElementById('encoder-output').classList.add('is-visible');
    document.getElementById('encoder-raw-content').textContent = '{"raw":true}';
    document.getElementById('encoder-toggle-raw').disabled = true;

    toggleRawCodec('encode');
    expect(openModal).not.toHaveBeenCalledWith('encoder-raw-modal');

    document.getElementById('encoder-toggle-raw').disabled = false;
    document.getElementById('encoder-raw-content').textContent = '';
    toggleRawCodec('encode');
    expect(openModal).not.toHaveBeenCalledWith('encoder-raw-modal');

    document.getElementById('encoder-raw-content').textContent = '{"raw":true}';
    toggleRawCodec('encode');
    expect(openModal).toHaveBeenCalledWith('encoder-raw-modal');

    clearCodec('encode');
    expect(document.getElementById('encoder-input').value).toBe('');
    expect(document.getElementById('encoder-output').classList.contains('is-visible')).toBe(false);
    expect(document.getElementById('encoder-raw-content').textContent).toBe('');
  });
});
