import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../static/scripts/shared/status.js', () => ({
  dismissAllTransientMessages: vi.fn(),
}));

import { updateJsonEditor } from '../../static/scripts/advanced/json-editor.js';
import { state } from '../../static/scripts/shared/state.js';
import { dismissAllTransientMessages } from '../../static/scripts/shared/status.js';

async function loadNavigation() {
  return import('../../static/scripts/shared/navigation.js');
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
  beforeEach(() => {
    buildTabDom();
    state.currentSubTab = 'registration';
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
});
