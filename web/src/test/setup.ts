import '@testing-library/jest-dom/vitest';

import { configure } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';

import { forgetExplorerList } from '@/logic/mds/explorer/loading.js';
import { StandInPublicKeyCredential } from '@/test/logic/simple/ceremony-answers.js';

// findBy* and waitFor give up after one second by default. The Cloud Build gate
// runs this suite about ten times slower than GitHub's runner (vitest.config.mts).
// There a test that renders the whole app (src/test/app.tsx) waits for the shell, a
// section, its fetch and its render: under that load, reproduced locally on
// 2026-10-03, one such wait took 12 s and a test 26 s. A query still resolves as
// soon as its element appears; one that never does fails after 30 s, inside the
// components project's 60 s a test.
configure({ asyncUtilTimeout: 30_000 });

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

// A test of Node-side code (the Next config) runs without a window.
if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'matchMedia', { configurable: true, writable: true, value: matchMedia });
  Object.defineProperty(window, 'ResizeObserver', { configurable: true, writable: true, value: NoResizeObserver });
  Object.defineProperty(window, 'scrollTo', { configurable: true, writable: true, value: () => {} });
}

// A browser with WebAuthn's JSON methods, as every one the ceremonies run in;
// a test of an older browser takes it away.
beforeEach(() => {
  Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, writable: true, value: StandInPublicKeyCredential });
});

afterEach(() => {
  vi.useRealTimers();
  // The MDS list a page fetched ahead belongs to that page.
  forgetExplorerList();
});
