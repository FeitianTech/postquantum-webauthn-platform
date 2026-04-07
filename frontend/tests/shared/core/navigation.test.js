import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../../static/scripts/shared/status.js', () => ({
  dismissAllTransientMessages: vi.fn(),
}));

import { updateJsonEditor } from '../../../static/scripts/advanced/json-editor.js';
import { state } from '../../../static/scripts/shared/state.js';
import { dismissAllTransientMessages } from '../../../static/scripts/shared/status.js';

async function loadNavigation() {
  return import('../../../static/scripts/shared/navigation.js');
}

function buildTabDom() {
  document.body.innerHTML = `
    <div class="header">
      <button data-header-menu-toggle aria-expanded="false"></button>
      <div data-header-nav>
        <div class="nav-tabs">
          <button class="nav-tab" data-tab="simple"></button>
          <button class="nav-tab" data-tab="advanced"></button>
        </div>
      </div>
      <div data-header-overlay hidden aria-hidden="true"></div>
    </div>
    <div id="simple-tab" class="tab-content active"></div>
    <div id="advanced-tab" class="tab-content"></div>
    <button class="sub-tab" id="registration-tab-btn"></button>
    <button class="sub-tab" id="authentication-tab-btn"></button>
    <div id="registration-form" class="sub-tab-content"></div>
    <div id="authentication-form" class="sub-tab-content"></div>
    <div class="advanced-header__actions-group" data-subtab="registration"></div>
    <div class="advanced-header__actions-group" data-subtab="authentication"></div>
    <div class="section-header" onclick="toggleSection('details')">
      <span class="expand-icon"></span>
    </div>
    <div id="details"></div>
  `;
}

describe('navigation', () => {
  beforeEach(async () => {
    buildTabDom();
    state.currentSubTab = 'registration';

    const { resetNavigationMenuStateForTests } = await loadNavigation();
    resetNavigationMenuStateForTests();
  });

  it('switches top-level tabs and emits events', async () => {
    const { switchTab } = await loadNavigation();
    const changed = vi.fn();
    document.addEventListener('tab:changed', changed);

    switchTab('advanced');

    expect(dismissAllTransientMessages).toHaveBeenCalled();
    expect(updateJsonEditor).toHaveBeenCalled();
    expect(document.getElementById('advanced-tab').classList.contains('active')).toBe(true);
    expect(document.querySelector('.nav-tab[data-tab="advanced"]').classList.contains('active')).toBe(true);
    expect(window.scrollTo).toHaveBeenCalled();
    expect(changed).toHaveBeenCalled();
  });

  it('initializes the mobile header menu controls', async () => {
    const { initializeNavigationMenu } = await loadNavigation();
    window.innerWidth = 700;

    const controls = initializeNavigationMenu();
    controls.open();
    expect(document.body.classList.contains('header-menu-open')).toBe(true);
    expect(document.querySelector('[data-header-overlay]').hidden).toBe(false);

    controls.close({ focusToggle: true, allowDesktop: true });
    expect(document.body.classList.contains('header-menu-open')).toBe(false);
    expect(document.querySelector('[data-header-overlay]').hidden).toBe(true);
  });

  it('handles toggle/overlay/escape/resize/orientation listeners for header menu', async () => {
    const { initializeNavigationMenu } = await loadNavigation();
    window.innerWidth = 700;

    const controls = initializeNavigationMenu();
    const toggle = document.querySelector('[data-header-menu-toggle]');
    const overlay = document.querySelector('[data-header-overlay]');

    toggle.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    overlay.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(false);

    controls.open();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(false);

    controls.open();
    window.innerWidth = 1200;
    window.dispatchEvent(new Event('resize'));
    expect(document.body.classList.contains('header-menu-open')).toBe(false);

    window.innerWidth = 700;
    controls.open();
    window.dispatchEvent(new Event('orientationchange'));
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    // desktop click should no-op from handler guard
    window.innerWidth = 1200;
    toggle.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    controls.close({ allowDesktop: true });
  });

  it('switches advanced subtabs and toggles collapsible sections', async () => {
    const { switchSubTab, toggleSection } = await loadNavigation();
    const changed = vi.fn();
    document.addEventListener('advanced:subtab-changed', changed);

    switchSubTab('authentication');
    expect(state.currentSubTab).toBe('authentication');
    expect(document.getElementById('authentication-form').classList.contains('active')).toBe(true);
    expect(document.querySelector('[data-subtab="authentication"]').classList.contains('active')).toBe(true);
    expect(changed).toHaveBeenCalled();

    toggleSection('details');
    expect(document.getElementById('details').classList.contains('expanded')).toBe(true);
    toggleSection('details');
    expect(document.getElementById('details').classList.contains('expanded')).toBe(false);
  });

  it('falls back to parent and onclick-header resolution when toggling sections', async () => {
    const { toggleSection } = await loadNavigation();

    document.body.innerHTML = `
      <div id="wrapper-a">
        <div class="section-header"><span class="expand-icon"></span></div>
        <div id="parent-fallback"></div>
      </div>
      <div id="target-container">
        <div id="query-fallback"></div>
      </div>
      <div class="section-header" onclick="toggleSection('query-fallback')"><span class="expand-icon"></span></div>
    `;

    toggleSection('parent-fallback');
    expect(document.getElementById('parent-fallback').classList.contains('expanded')).toBe(true);

    toggleSection('query-fallback');
    expect(document.getElementById('query-fallback').classList.contains('expanded')).toBe(true);
  });

  it('supports explicit event/header inputs when toggling sections', async () => {
    const { toggleSection } = await loadNavigation();

    document.body.innerHTML = `
      <div class="section-header" id="header-a"><span class="expand-icon" id="icon-a"></span></div>
      <div id="explicit-details"></div>
    `;

    const header = document.getElementById('header-a');
    const icon = document.getElementById('icon-a');
    const content = document.getElementById('explicit-details');

    toggleSection('explicit-details', { currentTarget: header });
    expect(content.classList.contains('expanded')).toBe(true);

    toggleSection('explicit-details', { target: icon });
    expect(content.classList.contains('expanded')).toBe(false);

    toggleSection('explicit-details', header);
    expect(content.classList.contains('expanded')).toBe(true);
  });

  it('registers resize/orientation listeners on first init and no-ops for missing sections', async () => {
    vi.resetModules();
    buildTabDom();

    const addSpy = vi.spyOn(window, 'addEventListener');
    const { initializeNavigationMenu, toggleSection } = await import('../../../static/scripts/shared/navigation.js');

    window.innerWidth = 700;
    const controls = initializeNavigationMenu();

    expect(addSpy).toHaveBeenCalledWith('resize', expect.any(Function));
    expect(addSpy).toHaveBeenCalledWith('orientationchange', expect.any(Function));

    expect(() => toggleSection('missing-section')).not.toThrow();

    controls.close({ allowDesktop: true });
    addSpy.mockRestore();
  });

  it('reuses initialized controls and exercises switchTab scroll fallbacks', async () => {
    const { initializeNavigationMenu, switchTab } = await loadNavigation();
    window.innerWidth = 700;

    const controls = initializeNavigationMenu();
    const sameControls = initializeNavigationMenu();
    expect(sameControls).toBe(controls);

    controls.open();
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    const closeSpy = vi.spyOn(controls, 'close');

    const originalScrollTo = window.scrollTo;
    window.scrollTo = vi.fn((...args) => {
      if (typeof args[0] === 'object') {
        throw new Error('object form not supported');
      }
    });

    switchTab('simple', { preserveMessages: true });
    await new Promise(resolve => requestAnimationFrame(resolve));
    expect(closeSpy).toHaveBeenCalledWith({ focusToggle: false, allowDesktop: true });
    expect(window.scrollTo).toHaveBeenCalledWith(0, 0);

    window.scrollTo = undefined;
    document.documentElement.scrollTop = 18;
    document.body.scrollTop = 14;

    switchTab('simple');
    await new Promise(resolve => requestAnimationFrame(resolve));
    expect(document.documentElement.scrollTop).toBe(0);
    expect(document.body.scrollTop).toBe(0);

    window.scrollTo = originalScrollTo;
  });

  it('handles initialization guard paths and desktop open/close menu constraints', async () => {
    let module = await loadNavigation();

    document.body.innerHTML = '<div id="no-header"></div>';
    module.resetNavigationMenuStateForTests();
    expect(module.initializeNavigationMenu()).toBeNull();

    document.body.innerHTML = `
      <div class="header">
        <button data-header-menu-toggle aria-expanded="false"></button>
        <div data-header-nav><div class="nav-tabs"><button class="nav-tab" data-tab="simple"></button></div></div>
      </div>
    `;
    module.resetNavigationMenuStateForTests();
    expect(module.initializeNavigationMenu()).toBeNull();

    buildTabDom();
    module.resetNavigationMenuStateForTests();
    const controls = module.initializeNavigationMenu();

    window.innerWidth = 1200;
    controls.open();
    expect(document.body.classList.contains('header-menu-open')).toBe(false);

    window.innerWidth = 700;
    controls.open();
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    window.innerWidth = 1200;
    controls.close();
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(true);

    document.querySelector('.nav-tab').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(document.body.classList.contains('header-menu-open')).toBe(false);
  });

  it('resolves section headers through parent query fallback when direct siblings are absent', async () => {
    const { toggleSection } = await loadNavigation();

    document.body.innerHTML = `
      <div id="outer">
        <div id="inner">
          <div class="wrapper">
            <div class="section-header" id="nested-header"><span class="expand-icon"></span></div>
          </div>
          <div id="query-target"></div>
        </div>
      </div>
    `;

    toggleSection('query-target');

    expect(document.getElementById('query-target').classList.contains('expanded')).toBe(true);
    expect(document.getElementById('nested-header').classList.contains('expanded')).toBe(true);
  });
});
