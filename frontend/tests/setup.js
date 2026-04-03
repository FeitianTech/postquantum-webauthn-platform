import { afterEach, beforeEach, vi } from 'vitest';

class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

class NoopIntersectionObserver {
  constructor(callback) {
    this.callback = callback;
  }

  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}

function createStorage() {
  const store = new Map();
  return {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    key(index) {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key) {
      store.delete(String(key));
    },
    setItem(key, value) {
      store.set(String(key), String(value));
    },
  };
}

beforeEach(() => {
  document.documentElement.innerHTML = '<head></head><body></body>';
  document.documentElement.className = '';
  document.body.className = '';

  const localStorage = createStorage();
  const sessionStorage = createStorage();
  Object.defineProperty(window, 'localStorage', {
    value: localStorage,
    configurable: true,
  });
  Object.defineProperty(window, 'sessionStorage', {
    value: sessionStorage,
    configurable: true,
  });
  Object.defineProperty(globalThis, 'localStorage', {
    value: localStorage,
    configurable: true,
  });
  Object.defineProperty(globalThis, 'sessionStorage', {
    value: sessionStorage,
    configurable: true,
  });

  window.__INITIAL_CREDENTIAL_RECORDS__ = [];
  window.__INITIAL_MDS_INFO__ = {};
  window.__INITIAL_MDS_SNAPSHOT__ = {};
  window.lastFakeCredLength = 0;

  Object.defineProperty(window, 'innerWidth', {
    value: 1280,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(window, 'innerHeight', {
    value: 800,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(window, 'pageYOffset', {
    value: 0,
    writable: true,
    configurable: true,
  });

  window.scrollTo = vi.fn();
  window.open = vi.fn(() => ({
    document: {
      write: vi.fn(),
      close: vi.fn(),
      body: {},
    },
    focus: vi.fn(),
    close: vi.fn(),
    location: { href: '' },
  }));
  window.requestAnimationFrame = (callback) => {
    callback(0);
    return 1;
  };
  window.cancelAnimationFrame = vi.fn();
  window.matchMedia = vi.fn(() => ({
    matches: false,
    media: '',
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));

  globalThis.fetch = vi.fn();
  globalThis.ResizeObserver = NoopResizeObserver;
  globalThis.IntersectionObserver = NoopIntersectionObserver;

  if (!HTMLElement.prototype.scrollIntoView) {
    HTMLElement.prototype.scrollIntoView = vi.fn();
  }
});

afterEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
});
