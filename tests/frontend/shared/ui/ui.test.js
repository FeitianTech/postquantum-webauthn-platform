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
} from '../../../../frontend/static/scripts/shared/ui.js';

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

    document.body.innerHTML += `
      <div id="icon-2">
        <div class="info-popup show"></div>
      </div>
    `;
    showInfoPopup(icon);
    expect(document.querySelector('#icon-2 .info-popup').classList.contains('show')).toBe(false);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    toggleLanguage(document.createElement('button'));
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });

  it('updates global scroll lock and modal open/close/reset behavior', async () => {
    vi.useFakeTimers();
    document.body.innerHTML = `
      <div id="json-editor-overlay" class="active"></div>
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

    // detail-screen fallback timeout path
    openModal('modal-a');
    closeModal('modal-a');
    await vi.advanceTimersByTimeAsync(710);
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
    const resizeObservers = [];
    globalThis.ResizeObserver = class ResizeObserver {
      constructor(callback) {
        this.callback = callback;
        resizeObservers.push(this);
      }

      observe() {}
      disconnect() {}
    };

    document.body.innerHTML = `
      <header class="header" style="height: 60px;">
        <div class="nav-tabs"><button>One</button></div>
      </header>
    `;

    const header = document.querySelector('.header');
    const controller = initializeStickyHeaderForElement(header, {
      activeClass: 'header-mini--active',
      measuringClass: 'header-mini--measuring',
      insert: () => {
        throw new Error('insert failure');
      },
      getScrollPosition: () => {
        throw new Error('scroll accessor failed');
      },
    });

    expect(controller).toBeTruthy();
    expect(header.dataset.stickyInitialized).toBe('true');

    controller.refreshGeometry();
    controller.evaluate();
    controller.reset();

    window.dispatchEvent(new Event('scroll'));
    window.dispatchEvent(new Event('resize'));
    window.dispatchEvent(new Event('pageshow'));
    resizeObservers.forEach((observer) => observer.callback());
    window.dispatchEvent(new Event('beforeunload'));

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

  it('supports sticky header calculations with element scroll targets and unknown refresh/reset headers', () => {
    document.body.innerHTML = `
      <div id="scroll-host" style="height:120px; overflow:auto; position:relative;">
        <header class="header" style="height:40px; position:relative;">
          <div class="nav-tabs"><button>One</button></div>
        </header>
        <div style="height:600px;"></div>
      </div>
    `;

    const header = document.querySelector('.header');
    const host = document.getElementById('scroll-host');

    const controller = initializeStickyHeaderForElement(header, {
      scrollTarget: host,
      root: host,
      cloneSource: header.querySelector('.nav-tabs'),
    });

    expect(controller).toBeTruthy();
    host.scrollTop = 60;
    host.dispatchEvent(new Event('scroll'));
    controller.refreshGeometry();
    controller.evaluate();

    expect(() => refreshStickyHeader(document.createElement('header'))).not.toThrow();
    expect(() => resetStickyHeader(document.createElement('header'))).not.toThrow();

    controller.destroy();
  });

  it('uses custom header-bottom measurement and clamps negative progress values', () => {
    document.body.innerHTML = `
      <div id="scroll-host" style="height:120px; overflow:auto; position:relative;">
        <header class="header" style="height:40px; position:relative;">
          <div class="nav-tabs"><button>One</button></div>
        </header>
        <div style="height:400px;"></div>
      </div>
    `;

    const header = document.querySelector('.header');
    const host = document.getElementById('scroll-host');

    const controller = initializeStickyHeaderForElement(header, {
      scrollTarget: host,
      root: host,
      cloneSource: header.querySelector('.nav-tabs'),
      getScrollPosition: () => -50,
      measureHeaderBottom: () => 10,
    });

    controller.refreshGeometry();
    controller.evaluate();

    const miniHeader = host.querySelector('.header-mini');
    expect(miniHeader).not.toBeNull();
    expect(['', '0']).toContain(miniHeader.style.getPropertyValue('--header-progress'));

    controller.destroy();
  });

  it('falls back to page/document scroll positions and handles non-finite custom scroll values', () => {
    const scrollYDescriptor = Object.getOwnPropertyDescriptor(window, 'scrollY');
    const pageYOffsetDescriptor = Object.getOwnPropertyDescriptor(window, 'pageYOffset');

    document.body.innerHTML = `
      <header class="header" style="height:40px; position:relative;">
        <div class="nav-tabs"><button>One</button></div>
      </header>
    `;

    const header = document.querySelector('.header');

    try {
      Object.defineProperty(window, 'scrollY', { configurable: true, value: undefined });
      Object.defineProperty(window, 'pageYOffset', { configurable: true, value: 24 });

      const controller = initializeStickyHeaderForElement(header, {
        root: document.body,
        cloneSource: header.querySelector('.nav-tabs'),
        measureHeaderBottom: () => 20,
        getScrollPosition: () => Number.NaN,
      });

      controller.refreshGeometry();
      controller.evaluate();
      controller.destroy();
    } finally {
      if (scrollYDescriptor) {
        Object.defineProperty(window, 'scrollY', scrollYDescriptor);
      }
      if (pageYOffsetDescriptor) {
        Object.defineProperty(window, 'pageYOffset', pageYOffsetDescriptor);
      }
    }
  });

  it('covers popup guards, language text fallback errors, and detail modal close reentry edge cases', async () => {
    vi.useFakeTimers();

    document.body.innerHTML = `
      <div id="icon-empty"></div>
      <div id="icon-with-popup">
        <div class="info-popup" data-english-dimensions="true" data-english-text-height="18px">
          <button id="toggle-language">ENG</button>
          <div class="text-en active">English</div>
          <div class="text-zh hidden">中文</div>
        </div>
      </div>
      <div id="modal-no-text" class="info-popup">
        <button id="missing-text-toggle">ENG</button>
      </div>
      <div id="modal-detail" class="modal detail-screen" style="z-index: 1400"></div>
      <div id="modal-other" class="modal open" data-modal-stack-z-index="1600"></div>
    `;

    const iconEmpty = document.getElementById('icon-empty');
    expect(() => showInfoPopup(iconEmpty)).not.toThrow();
    expect(() => hideInfoPopup(iconEmpty)).not.toThrow();

    const iconWithPopup = document.getElementById('icon-with-popup');
    const popup = iconWithPopup.querySelector('.info-popup');
    const languageToggle = document.getElementById('toggle-language');

    hideInfoPopup(iconWithPopup);
    showInfoPopup(iconWithPopup);
    popup.dispatchEvent(new Event('mouseenter'));

    toggleLanguage(languageToggle);
    expect(popup.querySelector('.text-zh').style.height).toBe('18px');

    toggleLanguage(languageToggle);
    expect(popup.querySelector('.text-en').style.height).toBe('18px');

    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    toggleLanguage(document.getElementById('missing-text-toggle'));
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();

    const detailModal = document.getElementById('modal-detail');
    detailModal.dataset.modalStackZIndex = '1700';
    delete detailModal.dataset.modalBaseZIndex;

    closeModal('modal-detail');
    expect(detailModal.classList.contains('closing')).toBe(false);

    detailModal.classList.add('open');
    detailModal.dataset.modalClosing = 'true';
    closeModal('modal-detail');
    expect(detailModal.dataset.modalClosing).toBe('true');
    delete detailModal.dataset.modalClosing;

    closeModal('modal-detail');
    detailModal.dispatchEvent(new TransitionEvent('transitionend', { propertyName: 'transform' }));
    detailModal.dispatchEvent(new TransitionEvent('transitionend', { propertyName: 'opacity' }));
    await vi.advanceTimersByTimeAsync(710);

    expect(detailModal.classList.contains('closing')).toBe(false);
  });

  it('covers sticky header root fallback, clone selector fallback, and requestAnimationFrame fallback timing', async () => {
    vi.useFakeTimers();

    const rafDescriptor = Object.getOwnPropertyDescriptor(window, 'requestAnimationFrame');
    const scrollYDescriptor = Object.getOwnPropertyDescriptor(window, 'scrollY');
    const pageYOffsetDescriptor = Object.getOwnPropertyDescriptor(window, 'pageYOffset');

    document.body.innerHTML = `
      <div id="sticky-root">
        <header class="header" id="sticky-header" style="height: 40px; position: relative;">
          <div class="nav-tabs"><button>Tab</button></div>
        </header>
      </div>
    `;

    const header = document.getElementById('sticky-header');
    document.documentElement.scrollTop = 24;
    document.body.scrollTop = 12;

    try {
      Object.defineProperty(window, 'requestAnimationFrame', { configurable: true, value: undefined });
      Object.defineProperty(window, 'scrollY', { configurable: true, value: undefined });
      Object.defineProperty(window, 'pageYOffset', { configurable: true, value: undefined });

      const controller = initializeStickyHeaderForElement(header, {
        root: {},
        cloneSelector: '.nav-tabs',
        createContent: () => {
          throw new Error('content factory failed');
        },
        getScrollPosition: () => Number.POSITIVE_INFINITY,
      });

      expect(controller).toBeTruthy();
      controller.refreshGeometry();
      controller.evaluate();
      await vi.runAllTimersAsync();
      controller.destroy();
    } finally {
      if (rafDescriptor) {
        Object.defineProperty(window, 'requestAnimationFrame', rafDescriptor);
      }
      if (scrollYDescriptor) {
        Object.defineProperty(window, 'scrollY', scrollYDescriptor);
      }
      if (pageYOffsetDescriptor) {
        Object.defineProperty(window, 'pageYOffset', pageYOffsetDescriptor);
      }
    }
  });

  it('captures baseline popup dimensions on first language toggle and applies them to styles', () => {
    document.body.innerHTML = `
      <div class="info-popup">
        <button id="lang-toggle">ENG</button>
        <div class="text-en active">English</div>
        <div class="text-zh hidden">中文</div>
      </div>
    `;

    const popup = document.querySelector('.info-popup');
    const toggle = document.getElementById('lang-toggle');
    const enText = popup.querySelector('.text-en');

    const styleSpy = vi.spyOn(window, 'getComputedStyle').mockImplementation((element) => {
      if (element === enText) {
        return { width: '88px', height: '16px' };
      }
      return { width: '140px', height: '42px' };
    });

    toggleLanguage(toggle);

    expect(popup.getAttribute('data-english-dimensions')).toBe('true');
    expect(popup.getAttribute('data-english-width')).toBe('140px');
    expect(popup.getAttribute('data-english-height')).toBe('42px');
    expect(popup.getAttribute('data-english-text-height')).toBe('16px');
    expect(popup.style.width).toBe('140px');
    expect(popup.style.height).toBe('42px');
    expect(popup.style.minHeight).toBe('42px');

    styleSpy.mockRestore();
  });

  it('cancels pending popup hide timeout when pointer re-enters popup', async () => {
    vi.useFakeTimers();
    const { icon, popup } = buildInfoPopupDom();

    showInfoPopup(icon);
    popup.dispatchEvent(new Event('mouseleave'));
    popup.dispatchEvent(new Event('mouseenter'));

    await vi.advanceTimersByTimeAsync(250);
    expect(popup.classList.contains('show')).toBe(true);
  });
});
