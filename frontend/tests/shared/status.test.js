import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  dismissAllTransientMessages,
  hideAllProgress,
  hideAllStatuses,
  hideProgress,
  hideStatus,
  showProgress,
  showStatus,
} from '../../static/scripts/shared/status.js';

function buildDom() {
  document.body.innerHTML = `
    <div id="simple-status" class="status"></div>
    <div id="simple-progress" class="progress">
      <span id="simple-progress-text"></span>
    </div>
    <div id="advanced-status" class="status"></div>
    <div id="advanced-progress" class="progress show" style="height: 20px;">
      <span id="advanced-progress-text"></span>
    </div>
  `;
  vi.spyOn(document.getElementById('advanced-progress'), 'getBoundingClientRect').mockReturnValue({ height: 24 });
}

describe('status helpers', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    buildDom();
  });

  it('shows and automatically hides status messages', () => {
    showStatus('advanced', 'Saved', 'success');

    const status = document.getElementById('advanced-status');
    expect(status.classList.contains('success')).toBe(true);
    expect(status.textContent).toBe('Saved');
    expect(status.style.bottom).toContain('36px');

    vi.advanceTimersByTime(5000);
    expect(status.className).toBe('status');
    expect(status.textContent).toBe('');
  });

  it('shows and hides progress blocks', () => {
    showProgress('simple', 'Working');
    expect(document.getElementById('simple-progress').classList.contains('show')).toBe(true);
    expect(document.getElementById('simple-progress-text').textContent).toBe('Working');

    hideProgress('simple');
    expect(document.getElementById('simple-progress').classList.contains('show')).toBe(false);
  });

  it('clears status and progress collections', () => {
    showStatus('simple', 'One', 'info');
    showProgress('simple', 'Loading');

    hideStatus('simple');
    expect(document.getElementById('simple-status').className).toBe('status');

    showStatus('simple', 'One', 'info');
    showStatus('advanced', 'Two', 'error');
    showProgress('simple', 'Loading');
    showProgress('advanced', 'Busy');

    hideAllStatuses();
    hideAllProgress();

    expect(document.querySelectorAll('.status.status--visible')).toHaveLength(0);
    expect(document.querySelectorAll('.progress.show')).toHaveLength(0);
  });

  it('dismisses all transient messages together', () => {
    showStatus('simple', 'Hello', 'success');
    showProgress('simple', 'Loading');

    dismissAllTransientMessages();

    expect(document.getElementById('simple-status').className).toBe('status');
    expect(document.getElementById('simple-progress').classList.contains('show')).toBe(false);
  });

  it('no-ops for missing targets and supports element-driven progress/status resolution', () => {
    expect(() => showStatus('missing-tab', 'No target', 'info')).not.toThrow();
    expect(() => hideStatus('missing-tab')).not.toThrow();
    expect(() => hideStatus(document.createElement('div'))).not.toThrow();

    showStatus('simple', 'Visible', 'info');
    showProgress('simple', 'Working');

    const simpleStatus = document.getElementById('simple-status');
    const simpleProgress = document.getElementById('simple-progress');
    simpleStatus.classList.add('status--visible');

    hideProgress(simpleProgress);
    expect(simpleStatus.classList.contains('status--visible')).toBe(true);
    expect(simpleStatus.style.bottom).toBe('');

    expect(() => hideProgress(123)).not.toThrow();
  });
});
