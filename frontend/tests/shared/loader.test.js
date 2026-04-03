import { beforeEach, describe, expect, it, vi } from 'vitest';

function buildLoaderDom() {
  document.body.innerHTML = `
    <div id="app-loader">
      <div id="app-loader-status"></div>
      <div id="app-loader-progress" aria-valuenow="0">
        <div class="app-loader__progress-fill"></div>
      </div>
      <div id="app-loader-percentage"></div>
    </div>
  `;
}

describe('loader', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    buildLoaderDom();
  });

  async function loadLoaderModule() {
    vi.resetModules();
    return import('../../static/scripts/shared/loader.js');
  }

  it('initializes and updates progress state', async () => {
    const {
      initializeLoader,
      loaderIsActive,
      loaderSetMetadataCount,
      loaderSetPhase,
      loaderSetProgress,
    } = await loadLoaderModule();

    initializeLoader();

    expect(loaderIsActive()).toBe(true);
    expect(document.body.classList.contains('app-loading')).toBe(true);

    loaderSetPhase('Loading metadata', { progress: 25 });
    vi.advanceTimersByTime(50);

    expect(document.getElementById('app-loader-status').textContent).toBe('Loading metadata');
    expect(document.getElementById('app-loader-progress').getAttribute('aria-valuenow')).toBe('3');

    loaderSetProgress(40);
    vi.advanceTimersByTime(1000);
    expect(document.getElementById('app-loader-progress').getAttribute('aria-valuenow')).toBe('40');

    loaderSetMetadataCount();
  });

  it('completes the loader and reveals the application', async () => {
    const {
      initializeLoader,
      loaderComplete,
      loaderIsActive,
    } = await loadLoaderModule();

    initializeLoader();
    loaderComplete({ message: 'Done', delay: 25 });
    vi.advanceTimersByTime(3000);

    expect(loaderIsActive()).toBe(false);
    expect(document.getElementById('app-loader-status').textContent).toBe('Done');
    expect(document.body.classList.contains('app-loaded')).toBe(true);

    vi.advanceTimersByTime(25);
    expect(document.getElementById('app-loader').classList.contains('app-loader--hidden')).toBe(true);
    expect(document.getElementById('app-loader').getAttribute('aria-hidden')).toBe('true');
  });
});
