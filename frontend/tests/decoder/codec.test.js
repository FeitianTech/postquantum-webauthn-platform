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
    <div id="decoder-output"></div>
    <div id="decoded-content"></div>
    <button id="decoder-toggle-raw" disabled></button>
    <textarea id="decoder-raw-content"></textarea>
    <div id="decoder-raw-modal" class="modal"></div>
    <div id="decoder-progress"></div>
    <div id="decoder-progress-text"></div>

    <section id="codec-encode-panel" hidden></section>
    <textarea id="encoder-input"></textarea>
    <div id="encoder-output"></div>
    <div id="encoded-content"></div>
    <button id="encoder-toggle-raw" disabled></button>
    <textarea id="encoder-raw-content"></textarea>
    <div id="encoder-raw-modal" class="modal"></div>
    <div id="encoder-progress"></div>
    <div id="encoder-progress-text"></div>
    <select id="encoder-format">
      <option value=""></option>
      <option value="json">json</option>
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
});
