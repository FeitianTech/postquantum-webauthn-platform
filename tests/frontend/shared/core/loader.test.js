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
    return import('../../../../frontend/static/scripts/shared/loader.js');
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

  it('handles missing loader root and still reveals application on complete', async () => {
    document.body.innerHTML = '<div id="app"></div>';
    const {
      initializeLoader,
      loaderComplete,
      loaderIsActive,
    } = await loadLoaderModule();

    initializeLoader();
    expect(loaderIsActive()).toBe(false);

    loaderComplete();
    expect(document.body.classList.contains('app-loaded')).toBe(true);
  });

  it('ignores invalid phase/progress values and prevents progress from regressing', async () => {
    const {
      initializeLoader,
      loaderSetPhase,
      loaderSetProgress,
      loaderComplete,
    } = await loadLoaderModule();

    initializeLoader();

    loaderSetPhase('', { progress: Number.NaN });
    expect(document.getElementById('app-loader-status').textContent).toBe('');

    loaderSetProgress(30);
    vi.advanceTimersByTime(2000);
    expect(document.getElementById('app-loader-progress').getAttribute('aria-valuenow')).toBe('30');

    // Regression request should keep current rendered value.
    loaderSetProgress(5);
    vi.advanceTimersByTime(200);
    expect(document.getElementById('app-loader-progress').getAttribute('aria-valuenow')).toBe('30');

    loaderComplete('done');
    vi.advanceTimersByTime(1000);
    expect(document.body.classList.contains('app-loaded')).toBe(true);
  });

  it('ignores phase/progress updates after completion and treats repeated completion as a no-op', async () => {
    const {
      initializeLoader,
      loaderComplete,
      loaderIsActive,
      loaderSetPhase,
      loaderSetProgress,
    } = await loadLoaderModule();

    initializeLoader();
    loaderSetProgress(3);
    vi.advanceTimersByTime(400);
    expect(document.getElementById('app-loader-progress').getAttribute('aria-valuenow')).toBe('3');

    loaderComplete({ message: 'Finished', delay: 0 });
    vi.advanceTimersByTime(10);
    expect(loaderIsActive()).toBe(false);

    const statusBefore = document.getElementById('app-loader-status').textContent;
    loaderSetPhase('Ignored phase update', { progress: 55 });
    loaderSetProgress(90);
    loaderComplete({ message: 'Second completion should no-op' });

    expect(document.getElementById('app-loader-status').textContent).toBe(statusBefore);
    expect(document.body.classList.contains('app-loaded')).toBe(true);
  });
});
