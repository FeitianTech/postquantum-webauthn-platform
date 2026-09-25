import '@testing-library/jest-dom/vitest';

import { afterEach, vi } from 'vitest';

// jsdom has no layout, no media queries and no observers: give the components
// what they call, and let each test say what it needs.
function matchMedia(query: string): MediaQueryList {
  return {
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  };
}

class NoResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(window, 'matchMedia', { configurable: true, writable: true, value: matchMedia });
Object.defineProperty(window, 'ResizeObserver', { configurable: true, writable: true, value: NoResizeObserver });
Object.defineProperty(window, 'scrollTo', { configurable: true, writable: true, value: () => {} });

afterEach(() => {
  vi.useRealTimers();
});
