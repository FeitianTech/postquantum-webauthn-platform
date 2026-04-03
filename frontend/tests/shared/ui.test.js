import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  closeModal,
  hideInfoPopup,
  initializeStickyHeader,
  initializeStickyHeaderForElement,
  openModal,
  refreshStickyHeader,
  resetModalScroll,
  resetStickyHeader,
  showInfoPopup,
  toggleJsonEditorExpansion,
  toggleLanguage,
  updateGlobalScrollLock,
} from '../../static/scripts/shared/ui.js';

function buildInfoPopupDom() {
  document.body.innerHTML = `
    <div id="icon">
      <div class="info-popup">
        <button id="lang-toggle">ENG</button>
        <div class="text-en active">English</div>
        <div class="text-zh hidden">中文</div>
      </div>
    </div>
  `;
  return {
    icon: document.getElementById('icon'),
    popup: document.querySelector('.info-popup'),
    toggle: document.getElementById('lang-toggle'),
  };
}

describe('ui shared helpers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('handles info popup show/hide and language toggling', async () => {
    vi.useFakeTimers();
    const { icon, popup, toggle } = buildInfoPopupDom();

    showInfoPopup(icon);
    expect(popup.classList.contains('show')).toBe(true);
    expect(popup.getAttribute('data-listeners-added')).toBe('true');

    // listeners path
    popup.dispatchEvent(new Event('mouseenter'));
    expect(popup.classList.contains('show')).toBe(true);
    popup.dispatchEvent(new Event('mouseleave'));
    await vi.runAllTimersAsync();
    expect(popup.classList.contains('show')).toBe(false);

    showInfoPopup(icon);
    toggleLanguage(toggle);
    expect(toggle.textContent).toBe('中');
    expect(popup.querySelector('.text-zh').classList.contains('active')).toBe(true);

    toggleLanguage(toggle);
    expect(toggle.textContent).toBe('ENG');
    expect(popup.querySelector('.text-en').classList.contains('active')).toBe(true);

    hideInfoPopup(icon);
    await vi.runAllTimersAsync();
    expect(popup.classList.contains('show')).toBe(false);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    toggleLanguage(document.createElement('button'));
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });

  it('updates global scroll lock and modal open/close/reset behavior', async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <div id="json-editor-overlay" class="active"></div>
      <div id="analyze-browser-loader" class="is-open"></div>
      <div class="analyze-browser-panel is-open"></div>
      <div id="modal-a" class="modal detail-screen">
        <div class="modal-content" style="overflow:auto;height:50px">x</div>
        <textarea>y</textarea>
      </div>
      <div id="modal-b" class="modal open" style="z-index: 2000"></div>
    `;

    updateGlobalScrollLock();
    expect(document.body.classList.contains('modal-open')).toBe(true);
    expect(document.documentElement.classList.contains('modal-open')).toBe(true);

    const modalA = document.getElementById('modal-a');
    openModal('modal-a');
    expect(modalA.classList.contains('open')).toBe(true);
    expect(Number(modalA.style.zIndex)).toBeGreaterThanOrEqual(2050);

    // detail-screen close transition path
    closeModal('modal-a');
    expect(modalA.classList.contains('closing')).toBe(true);
    modalA.dispatchEvent(new TransitionEvent('transitionend', { propertyName: 'opacity' }));
    await vi.runAllTimersAsync();
    expect(modalA.classList.contains('closing')).toBe(false);

    // non-detail immediate close path
    modalA.className = 'modal open';
    closeModal('modal-a');
    expect(modalA.classList.contains('open')).toBe(false);

    modalA.querySelector('.modal-content').scrollTop = 10;
    modalA.querySelector('textarea').scrollTop = 10;
    resetModalScroll(modalA);
    expect(modalA.querySelector('.modal-content').scrollTop).toBe(0);
    expect(modalA.querySelector('textarea').scrollTop).toBe(0);

    document.getElementById('json-editor-overlay').classList.remove('active');
    document.getElementById('analyze-browser-loader').classList.remove('is-open');
    document.querySelector('.analyze-browser-panel').classList.remove('is-open');
    document.querySelectorAll('.modal').forEach((m) => m.classList.remove('open'));
    updateGlobalScrollLock();
    expect(document.body.classList.contains('modal-open')).toBe(false);
  });

  it('expands and collapses JSON editor overlay controls', () => {
    document.body.innerHTML = `
      <div id="json-editor-overlay"></div>
      <div id="json-editor-container" aria-expanded="false"></div>
      <button id="json-editor-close" aria-hidden="true" tabindex="-1"></button>
      <textarea id="json-editor"></textarea>
    `;

    toggleJsonEditorExpansion(false);
    const container = document.getElementById('json-editor-container');
    const overlay = document.getElementById('json-editor-overlay');
    const closeButton = document.getElementById('json-editor-close');

    expect(container.classList.contains('expanded')).toBe(true);
    expect(overlay.classList.contains('active')).toBe(true);
    expect(closeButton.getAttribute('aria-hidden')).toBe('false');
    expect(closeButton.tabIndex).toBe(0);

    toggleJsonEditorExpansion(true);
    expect(container.classList.contains('expanded')).toBe(false);
    expect(overlay.classList.contains('active')).toBe(false);
    expect(closeButton.getAttribute('aria-hidden')).toBe('true');
    expect(closeButton.tabIndex).toBe(-1);
  });

  it('initializes sticky headers and supports refresh/reset/destroy lifecycle', async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <header class="header" style="height: 60px;">
        <div class="nav-tabs"><button>One</button></div>
      </header>
    `;

    const header = document.querySelector('.header');
    const controller = initializeStickyHeaderForElement(header, {
      activeClass: 'header-mini--active',
      measuringClass: 'header-mini--measuring',
    });

    expect(controller).toBeTruthy();
    expect(header.dataset.stickyInitialized).toBe('true');

    controller.refreshGeometry();
    controller.evaluate();
    controller.reset();

    refreshStickyHeader(header);
    resetStickyHeader(header);

    // existing controller path
    expect(initializeStickyHeaderForElement(header)).toBe(controller);

    controller.destroy();
    expect(header.dataset.stickyInitialized).toBeUndefined();

    const defaultController = initializeStickyHeader();
    expect(defaultController).toBeTruthy();
    defaultController.destroy();

    await vi.runAllTimersAsync();
  });

  it('gracefully no-ops on missing elements and unknown modal ids', () => {
    document.body.innerHTML = '<div></div>';
    expect(() => openModal('missing')).not.toThrow();
    expect(() => closeModal('missing')).not.toThrow();
    expect(() => resetModalScroll(null)).not.toThrow();
    expect(() => toggleJsonEditorExpansion()).not.toThrow();
    expect(initializeStickyHeaderForElement(null)).toBeNull();
    expect(initializeStickyHeader()).toBeNull();
  });
});
